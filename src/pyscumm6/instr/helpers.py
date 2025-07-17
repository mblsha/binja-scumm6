"""Helper functions for instruction rendering and processing.

This module consolidates common patterns used across instruction classes
to reduce code duplication while maintaining the exact same behavior.
"""

from typing import List, Any, TYPE_CHECKING, Union, Tuple
from binja_helpers.tokens import Token, TInt, TText
from binaryninja.lowlevelil import LowLevelILFunction

if TYPE_CHECKING:
    from .opcodes import Instruction


def is_fusible_push(instr: 'Instruction') -> bool:
    """Return True if *instr* is a push operation that can be fused."""
    class_name = instr.__class__.__name__
    if class_name in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
        return True
    if hasattr(instr, 'produces_result') and instr.produces_result():
        return True
    return False


def render_operand(operand: 'Instruction', use_raw_names: bool = False) -> List[Token]:
    """
    Render a fused operand appropriately.
    
    This function consolidates the common operand rendering logic found
    in multiple base classes (_render_operand methods).
    
    Args:
        operand: The instruction operand to render
        
    Returns:
        List of tokens representing the operand
    """
    from ...scumm6_opcodes import Scumm6Opcodes
    from .smart_bases import get_variable_name
    
    # Variable push operations
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
        # Extract variable data
        if hasattr(operand.op_details.body, 'data'):
            data = operand.op_details.body.data
            
            # Handle signed byte interpretation for PushByteVar
            if operand.__class__.__name__ == 'PushByteVar' and data < 0:
                data = data + 256
            
            # Check if this is a local variable
            if hasattr(operand.op_details.body, 'type'):
                var_type = operand.op_details.body.type
                if var_type == Scumm6Opcodes.VarType.local:
                    return [TInt(f"localvar{data}")]
                elif var_type == Scumm6Opcodes.VarType.bitvar:
                    return [TInt(f"bitvar{data}")]
            
            # System variable - use semantic name mapping
            return [TInt(get_variable_name(data, use_raw_names=use_raw_names))]
    
    # Constant push operations
    elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
        if hasattr(operand.op_details.body, 'data'):
            value = operand.op_details.body.data
            return [TInt(str(value))]
    
    # Result-producing operations (for multi-level fusion)
    elif hasattr(operand, 'produces_result') and operand.produces_result():
        # This is a result-producing instruction (like Add with fused operands)
        # Just render it directly (no extra parentheses here)
        return operand.render()
    
    # Fallback for unknown operand types
    return [TText("?")]


def render_operand_with_parens(operand: 'Instruction', use_raw_names: bool = False) -> List[Token]:
    """
    Render a fused operand with parentheses for nested expressions.
    
    This variant is used by some classes that want to add parentheses
    around nested expressions.
    
    Args:
        operand: The instruction operand to render
        
    Returns:
        List of tokens representing the operand, with parentheses for expressions
    """
    # For result-producing operations, add parentheses
    if hasattr(operand, 'produces_result') and operand.produces_result():
        tokens: List[Token] = []
        tokens.append(TText("("))
        tokens.extend(operand.render())
        tokens.append(TText(")"))
        return tokens
    
    # For all other cases, use standard rendering
    return render_operand(operand, use_raw_names)


def render_operand_smart_binary(operand: 'Instruction', as_operand: bool = False, use_raw_names: bool = False) -> List[Token]:
    """
    Render a fused operand for SmartBinaryOp with special parentheses handling.
    
    This variant adds parentheses selectively based on the operation type
    to match descumm's output style.
    
    Args:
        operand: The instruction operand to render
        as_operand: Whether this is being rendered as an operand of another operation
        
    Returns:
        List of tokens representing the operand
    """
    # Variable and constant handling (no parentheses needed)
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar', 'PushByte', 'PushWord']:
        return render_operand(operand, use_raw_names)
    
    # Result-producing operations
    elif hasattr(operand, 'produces_result') and operand.produces_result():
        # Add parentheses for operations that need grouping when used as operands
        if operand.__class__.__name__ in ['Sub', 'Mul', 'Div']:
            tokens: List[Token] = []
            tokens.append(TText("("))
            # Check if render method supports as_operand parameter
            try:
                tokens.extend(operand.render(as_operand=True))
            except TypeError:
                tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            # Addition doesn't need extra parentheses in most contexts
            try:
                return operand.render(as_operand=True)
            except TypeError:
                return operand.render()
    
    # Fallback
    return render_operand(operand, use_raw_names)


def lift_operand(il: LowLevelILFunction, operand: 'Instruction') -> Any:
    """
    Lift a fused operand to IL expression.
    
    This function consolidates the common operand lifting logic found
    in multiple base classes (_lift_operand methods).
    
    Args:
        il: The LLIL function being built
        operand: The instruction operand to lift
        
    Returns:
        LLIL expression for the operand
    """
    from ... import vars
    
    # Variable push operations
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
        # Use il_get_var for variable access
        return vars.il_get_var(il, operand.op_details.body)
    
    # Constant push operations
    elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
        if hasattr(operand.op_details.body, 'data'):
            value = operand.op_details.body.data
            return il.const(4, value)
    
    # Result-producing operations would need architectural changes
    # to properly lift (would need to execute operand's lift method)
    # For now, return a placeholder
    elif hasattr(operand, 'produces_result') and operand.produces_result():
        # This is a complex case that would require architectural changes
        # to properly implement. For now, use a placeholder.
        return il.const(4, 0)
    
    # Fallback to undefined
    return il.undefined()


def apply_descumm_function_name(name: str) -> str:
    """
    Apply descumm function name mapping.
    
    This helper centralizes the function name mapping logic used
    across multiple render methods.
    
    Args:
        name: The internal function name
        
    Returns:
        The descumm-compatible display name
    """
    from .smart_bases import DESCUMM_FUNCTION_NAMES
    return DESCUMM_FUNCTION_NAMES.get(name, name)


def get_subop_name(subop: Union[int, Any]) -> str:
    """
    Get the name of a subop, handling both enum objects and raw integers.
    
    Kaitai sometimes returns subop as an integer instead of an enum object,
    especially for unknown or edge case values. This function handles both cases.
    
    Args:
        subop: Either an enum object with a 'name' attribute or an integer
        
    Returns:
        The subop name string (e.g., "room_screen" or "subop_123" for unknowns)
    """
    if isinstance(subop, int):
        return f"subop_{subop}"
    else:
        # Assume it's an enum object with a name attribute
        return str(subop.name)


def extract_primary_text_for_llil(message: Any) -> str:
    """Extract the printable text from a Message for LLIL lookup."""
    text_chars: List[str] = []

    for part in getattr(message, "parts", []):
        if hasattr(part, "data"):
            if part.data == 0xFF or part.data == 0:
                # Stop at control codes or terminator
                break
            elif 32 <= part.data <= 126:
                # Direct printable character
                text_chars.append(chr(part.data))
            elif hasattr(part, "content") and hasattr(part.content, "value"):
                # Character wrapped in content
                char_value = part.content.value
                if isinstance(char_value, int) and 32 <= char_value <= 126:
                    text_chars.append(chr(char_value))

    return "".join(text_chars)


def extract_message_text(message: Any) -> str:
    """Extract plain ASCII text from a Message object."""
    text_chars: List[str] = []

    for part in getattr(message, "parts", []):
        if not hasattr(part, "data"):
            continue

        data = part.data

        if isinstance(data, bytes):
            try:
                text_chars.append(data.decode("iso-8859-1").rstrip("\x00"))
            except Exception:
                pass
        elif isinstance(data, str):
            text_chars.append(data)
        elif data not in (0, 0xFF):
            if 32 <= data <= 126:
                text_chars.append(chr(data))
            elif hasattr(part, "content") and hasattr(part.content, "value"):
                char_value = part.content.value
                if isinstance(char_value, int) and 32 <= char_value <= 126:
                    text_chars.append(chr(char_value))

    return "".join(text_chars)


def extract_message_text_with_sound(message: Any) -> Tuple[List[str], str]:
    """Extract sound commands and text from a Message object."""
    sound_cmds: List[str] = []
    text_chars: List[str] = []

    for part in getattr(message, "parts", []):
        if not hasattr(part, "data"):
            continue

        if part.data == 0xFF and hasattr(part, "content") and hasattr(part.content, "payload"):
            payload = part.content.payload
            if payload.__class__.__name__ == "Sound" and hasattr(payload, "v1") and hasattr(payload, "v3"):
                sound_cmds.append(
                    f"sound({hex(payload.v1).upper().replace('X', 'x')}, {hex(payload.v3).upper().replace('X', 'x')})"
                )
        elif part.data != 0:
            if hasattr(part, "content") and hasattr(part.content, "value"):
                char_value = part.content.value
                if isinstance(char_value, int) and 32 <= char_value <= 126:
                    text_chars.append(chr(char_value))
            elif 32 <= part.data <= 126:
                text_chars.append(chr(part.data))

    return sound_cmds, "".join(text_chars)
