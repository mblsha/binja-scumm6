"""Concrete SCUMM6 instruction implementations."""

from typing import List, Any, Optional, Tuple, cast
import copy
from binja_helpers.tokens import Token, TInstr, TSep, TInt, TText
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP, LowLevelILLabel
from binaryninja import IntrinsicName, InstructionInfo
from ...scumm6_opcodes import Scumm6Opcodes

from .opcodes import Instruction
from .generic import VariableWriteOp, ControlFlowOp, IntrinsicOp
from .smart_bases import SmartConditionalJump, FusibleMultiOperandMixin, get_variable_name
from .helpers import (
    get_subop_name,
    render_operand,
    lift_operand,
    extract_message_text,
    extract_message_text_with_sound,
)

# Import the vars module to use the same LLIL generation logic
from ... import vars

# Array ID to name mapping based on descumm
SCUMM_ARRAY_NAMES = {
    110: "VAR_GUI_COLORS",  # 0x6E
    230: "array230",  # 0xE6
    236: "array236",  # 0xEC - no descumm name known yet
    24013: "VAR_PAUSE_MSG",  # 0x5DCD (CD5D in little-endian)
    23245: "VAR_GAME_DISK_MSG",  # 0x5ACD (CD5A in little-endian)
    23501: "VAR_OPEN_FAILED_MSG",  # 0x5BCD (CD5B in little-endian)
    23757: "VAR_READ_ERROR_MSG",  # 0x5CCD (CD5C in little-endian)
    24269: "VAR_SAVE_ERROR_MSG",  # 0x5ECD (CD5E in little-endian)
    24525: "VAR_RESTART_MSG",  # 0x5FCD (CD5F in little-endian)
    24781: "VAR_QUIT_MSG",  # 0x60CD (CD60 in little-endian)
    # Add more mappings as discovered
}


def handle_unknown_subop_lift(il: LowLevelILFunction, subop: Any, base_name: str) -> Tuple[str, bool]:
    """
    Handle subop conversion for lift methods. Returns (intrinsic_name, is_unknown).
    
    Args:
        il: The IL function (not used but kept for consistency)
        subop: The subop value (may be int or enum)
        base_name: Base name for the intrinsic (e.g., "actor_ops", "verb_ops")
        
    Returns:
        Tuple of (intrinsic_name, is_unknown_subop)
    """
    from ...scumm6_opcodes import Scumm6Opcodes
    
    if isinstance(subop, int):
        try:
            subop = Scumm6Opcodes.SubopType(subop)
        except ValueError:
            # If the int value is not a valid enum member, mark as unknown
            return f"{base_name}.unknown_{subop}", True
        else:
            return f"{base_name}.{subop.name}", False
    else:
        # Already an enum
        return f"{base_name}.{subop.name}", False


def parse_message_with_control_codes(message: Any) -> List[Token]:
    """
    Generic function to parse SCUMM6 Message objects with full control code support.
    
    This function handles all control codes including:
    - 0x01: newline()
    - 0x02: keepText()
    - 0x03: wait()
    - 0x0a: sound(id, volume)
    
    Returns a list of tokens representing the parsed message with descumm-style formatting.
    """
    msg_tokens: List[Token] = []
    
    if not hasattr(message, 'parts') or not message.parts:
        return [TText('""')]
    
    i = 0
    parts = message.parts
    
    while i < len(parts) and parts[i].data != 0:
        part = parts[i]
        
        if part.data == 0xff and hasattr(part, 'content'):
            # Special sequence with proper SpecialSequence content
            special = part.content
            if special.code == 0x0a:  # Sound command
                # Sound command with inline values
                if hasattr(special, 'payload'):
                    sound = special.payload
                    if hasattr(sound, 'value1') and hasattr(sound, 'v3'):
                        sound_id = sound.value1
                        volume = sound.v3
                        if msg_tokens:
                            msg_tokens.append(TText(" + "))
                        msg_tokens.append(TText(f"sound({hex(sound_id).upper().replace('X', 'x')}, {hex(volume).upper().replace('X', 'x')})"))
            elif special.code == 0x03:  # Wait command
                if msg_tokens:
                    msg_tokens.append(TText(" + "))
                msg_tokens.append(TText("wait()"))
            elif special.code == 0x02:  # KeepText command
                if msg_tokens:
                    msg_tokens.append(TText(" + "))
                msg_tokens.append(TText("keepText()"))
            elif special.code == 0x01:  # Newline command
                if msg_tokens:
                    msg_tokens.append(TText(" + "))
                msg_tokens.append(TText("newline()"))
            # Other special codes can be added here
        elif part.data == 0xfe and i + 1 < len(parts) and parts[i + 1].data == 0x01:
            # Handle FE01 sequence as newline (printCursor format)
            if msg_tokens:
                msg_tokens.append(TText(" + "))
            msg_tokens.append(TText("newline()"))
            i += 1  # Skip the next part (0x01) since we handled it
        elif 32 <= part.data <= 126:
            # Text run - collect consecutive printable characters
            text = ""
            while i < len(parts) and 32 <= parts[i].data <= 126:
                text += chr(parts[i].data)
                i += 1
            if msg_tokens:
                msg_tokens.append(TText(" + "))
            msg_tokens.append(TText(f'"{text}"'))
            i -= 1  # Back up since we'll increment at loop end
        i += 1
    
    if not msg_tokens:
        return [TText('""')]
    
    return msg_tokens


# PushByte and PushWord are now generated by factories in opcode_table.py


class PushByteVar(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        var_id = self.op_details.body.data
        # Handle signed byte interpretation
        if var_id < 0:
            var_id = var_id + 256
        return [
            TInstr("push_byte_var"),
            TSep("("),
            TInt(get_variable_name(var_id)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.ByteData), \
            f"Expected ByteData body, got {type(self.op_details.body)}"

        # Create a wrapper that adds the missing type attribute for compatibility
        # with the existing vars.il_get_var function
        class VarBlock:
            def __init__(self, data: int, var_type: Scumm6Opcodes.VarType):
                self.data = data
                self.type = var_type

        var_block = VarBlock(self.op_details.body.data, Scumm6Opcodes.VarType.scumm_var)
        il.append(il.push(4, vars.il_get_var(il, var_block)))


class PushWordVar(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr("push_word_var"),
            TSep("("),
            TInt(get_variable_name(var_id)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.WordVarData), \
            f"Expected WordVarData body, got {type(self.op_details.body)}"

        il.append(il.push(4, vars.il_get_var(il, self.op_details.body)))


class Dup(Instruction):

    @property
    def stack_pop_count(self) -> int:
        return 1

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("dup")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop value into temp register, then push it twice
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))


# Pop1 and Pop2 are now generated by factories in opcode_table.py
# Add, Sub, Mul, Div, Land, Lor, Nott, Eq, Neq, Gt, Lt, Le, Ge are now generated by factories in opcode_table.py


# Abs is now generated by factory in opcode_table.py


class Band(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("band")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # The original implementation generates two unimplemented() calls for UnknownOp:
        # 1. One from the else clause (fallthrough)
        # 2. One from the UnknownOp check
        il.append(il.unimplemented())
        il.append(il.unimplemented())


class Bor(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("bor")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # The original implementation generates two unimplemented() calls for UnknownOp:
        # 1. One from the else clause (fallthrough)
        # 2. One from the UnknownOp check
        il.append(il.unimplemented())
        il.append(il.unimplemented())


class _VarIncDecInstruction(Instruction):
    """Shared logic for incrementing/decrementing variable values."""

    instr_name: str
    body_type: type
    delta: int  # +1 for increment, -1 for decrement

    def render(self, as_operand: bool = False) -> List[Token]:
        var_id = self.op_details.body.data
        if self.body_type is Scumm6Opcodes.ByteVarData and var_id < 0:
            var_id += 256
        return [
            TInstr(self.instr_name),
            TSep("("),
            TInt(get_variable_name(var_id)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, self.body_type), (
            f"Expected {self.body_type.__name__} body, "
            f"got {type(self.op_details.body)}"
        )
        current_value = vars.il_get_var(il, self.op_details.body)
        op = il.add if self.delta > 0 else il.sub
        new_value = op(4, current_value, il.const(4, 1))
        il.append(vars.il_set_var(il, self.op_details.body, new_value))


class ByteVarInc(_VarIncDecInstruction):
    instr_name = "byte_var_inc"
    body_type = Scumm6Opcodes.ByteVarData
    delta = 1


class WordVarInc(_VarIncDecInstruction):
    instr_name = "word_var_inc"
    body_type = Scumm6Opcodes.WordVarData
    delta = 1


class ByteVarDec(_VarIncDecInstruction):
    instr_name = "byte_var_dec"
    body_type = Scumm6Opcodes.ByteVarData
    delta = -1


class WordVarDec(_VarIncDecInstruction):
    instr_name = "word_var_dec"
    body_type = Scumm6Opcodes.WordVarData
    delta = -1


# BreakHere is now generated by factory in opcode_table.py


class Dummy(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("dummy")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # Original implementation: falls through to else case then gets caught by UnknownOp check
        # This generates two unimplemented() calls like other UnknownOp instructions
        il.append(il.unimplemented())
        il.append(il.unimplemented())


# GetRandomNumber and GetRandomNumberRange are now generated by factories in opcode_table.py


class PickOneOf(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("pick_one_of")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # Original implementation: falls through to else case then gets caught by UnknownOp check
        # This generates two unimplemented() calls like other UnknownOp instructions
        il.append(il.unimplemented())
        il.append(il.unimplemented())


class PickOneOfDefault(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("pick_one_of_default")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # Original implementation: falls through to else case then gets caught by UnknownOp check
        # This generates two unimplemented() calls like other UnknownOp instructions
        il.append(il.unimplemented())
        il.append(il.unimplemented())


class Shuffle(Instruction):

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr("shuffle")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp), \
            f"Expected UnknownOp body, got {type(self.op_details.body)}"

        # Original implementation: falls through to else case then gets caught by UnknownOp check
        # This generates two unimplemented() calls like other UnknownOp instructions
        il.append(il.unimplemented())
        il.append(il.unimplemented())


class _BaseArrayReadCommon(Instruction):
    """Common implementation for array read operations."""

    instr_name: str
    intrinsic_name: str
    expected_body_type: Any
    pop_count: int = 1

    def render(self, as_operand: bool = False) -> List[Token]:
        array_id = self.op_details.body.array
        array_name = SCUMM_ARRAY_NAMES.get(array_id, f"array_{array_id}")
        return [TInstr(self.instr_name), TSep("("), TInt(array_name), TSep(")")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, self.expected_body_type), \
            f"Expected {self.expected_body_type.__name__} body, got {type(self.op_details.body)}"

        params = [il.pop(4) for _ in range(self.pop_count)]
        il.append(il.intrinsic(
            [il.reg(4, LLIL_TEMP(0))],
            IntrinsicName(self.intrinsic_name),
            params,
        ))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))


class _BaseArrayRead(_BaseArrayReadCommon):
    """Single index array read."""
    pop_count = 1


class ByteArrayRead(_BaseArrayRead):
    instr_name = "byte_array_read"
    intrinsic_name = "byte_array_read"
    expected_body_type = Scumm6Opcodes.ByteArrayRead


class WriteByteVar(VariableWriteOp):
    instruction_name = "write_byte_var"
    expected_body_type = Scumm6Opcodes.ByteVarData


class WriteWordVar(VariableWriteOp):
    instruction_name = "write_word_var" 
    expected_body_type = Scumm6Opcodes.WordVarData


class WordArrayRead(_BaseArrayRead):
    instr_name = "word_array_read"
    intrinsic_name = "word_array_read"
    expected_body_type = Scumm6Opcodes.WordArrayRead


class _BaseArrayIndexedRead(_BaseArrayReadCommon):
    """Indexed array read with two parameters."""

    pop_count = 2


class ByteArrayIndexedRead(_BaseArrayIndexedRead):
    instr_name = "byte_array_indexed_read"
    intrinsic_name = "byte_array_indexed_read"
    expected_body_type = Scumm6Opcodes.ByteArrayIndexedRead


class WordArrayIndexedRead(_BaseArrayIndexedRead):
    instr_name = "word_array_indexed_read"
    intrinsic_name = "word_array_indexed_read"
    expected_body_type = Scumm6Opcodes.WordArrayIndexedRead


class _BaseArrayWrite(FusibleMultiOperandMixin, Instruction):
    """Shared implementation for byte/word array writes."""

    instr_name: str
    intrinsic_name: str
    expected_body_type: Any

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []

    @property
    def stack_pop_count(self) -> int:
        if self.fused_operands:
            return 0
        return 2

    def _get_max_operands(self) -> int:
        return 2

    def fuse(self, previous: Instruction) -> Optional['Instruction']:
        return self._standard_fuse(previous)

    def _render_operand(self, operand: Instruction) -> List[Token]:
        return render_operand(operand, use_raw_names=True)

    def render(self, as_operand: bool = False) -> List[Token]:
        array_id = self.op_details.body.array
        array_name = SCUMM_ARRAY_NAMES.get(array_id, f"array_{array_id}")

        if self.fused_operands:
            if len(self.fused_operands) == 2:
                index_operand = self.fused_operands[0]
                value_operand = self.fused_operands[1]

                tokens: List[Token] = []
                tokens.append(TText(array_name))
                tokens.append(TSep("["))
                tokens.extend(self._render_operand(index_operand))
                tokens.append(TSep("] = "))
                tokens.extend(self._render_operand(value_operand))
                return tokens

        return [TInstr(self.instr_name), TSep("("), TInt(array_name), TSep(")")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, self.expected_body_type), \
            f"Expected {self.expected_body_type.__name__} body, got {type(self.op_details.body)}"

        if self.fused_operands:
            params = [self._lift_operand(il, op) for op in self.fused_operands]
            il.append(il.intrinsic([
                il.reg(4, LLIL_TEMP(0))], IntrinsicName(self.intrinsic_name), params))
        else:
            il.append(il.intrinsic([
                il.reg(4, LLIL_TEMP(0))], IntrinsicName(self.intrinsic_name), [il.pop(4), il.pop(4)]))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))

    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        return lift_operand(il, operand)


class ByteArrayWrite(_BaseArrayWrite):
    instr_name = "byte_array_write"
    intrinsic_name = "byte_array_write"
    expected_body_type = Scumm6Opcodes.ByteArrayWrite


class WordArrayWrite(_BaseArrayWrite):
    instr_name = "word_array_write"
    intrinsic_name = "word_array_write"
    expected_body_type = Scumm6Opcodes.WordArrayWrite


class _BaseArrayIndexedWrite(Instruction):
    """Shared implementation for byte/word indexed array writes."""

    instr_name: str
    intrinsic_name: str
    expected_body_type: Any

    def render(self, as_operand: bool = False) -> List[Token]:
        array_id = self.op_details.body.array
        array_name = SCUMM_ARRAY_NAMES.get(array_id, f"array_{array_id}")
        return [TInstr(self.instr_name), TSep("("), TInt(array_name), TSep(")")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, self.expected_body_type), \
            f"Expected {self.expected_body_type.__name__} body, got {type(self.op_details.body)}"

        il.append(il.intrinsic(
            [il.reg(4, LLIL_TEMP(0))],
            IntrinsicName(self.intrinsic_name),
            [il.pop(4), il.pop(4), il.pop(4)],
        ))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))


class ByteArrayIndexedWrite(_BaseArrayIndexedWrite):
    instr_name = "byte_array_indexed_write"
    intrinsic_name = "byte_array_indexed_write"
    expected_body_type = Scumm6Opcodes.ByteArrayIndexedWrite


class WordArrayIndexedWrite(_BaseArrayIndexedWrite):
    instr_name = "word_array_indexed_write"
    intrinsic_name = "word_array_indexed_write"
    expected_body_type = Scumm6Opcodes.WordArrayIndexedWrite


class _BaseArrayMutate(Instruction):
    """Shared implementation for inc/dec array operations."""

    instr_name: str
    expected_body_type: Any = Scumm6Opcodes.UnknownOp

    def render(self, as_operand: bool = False) -> List[Token]:
        return [TInstr(self.instr_name)]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, self.expected_body_type), \
            f"Expected {self.expected_body_type.__name__} body, got {type(self.op_details.body)}"

        il.append(il.unimplemented())
        il.append(il.unimplemented())


class ByteArrayInc(_BaseArrayMutate):
    instr_name = "byte_array_inc"


class WordArrayInc(_BaseArrayMutate):
    instr_name = "word_array_inc"


class ByteArrayDec(_BaseArrayMutate):
    instr_name = "byte_array_dec"


class WordArrayDec(_BaseArrayMutate):
    instr_name = "word_array_dec"


class DimArray(FusibleMultiOperandMixin, Instruction):
    """Dimension array operations with fusion support."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        # DimArray operations take 1 parameter (the size)
        return 1
    
    @property
    def stack_pop_count(self) -> int:
        """Return 0 when fully fused, otherwise 1."""
        return max(0, 1 - len(self.fused_operands))
    
    def fuse(self, previous: Instruction) -> Optional['DimArray']:
        """Use standard fusion logic from mixin."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(str(operand.op_details.body.data))]
            else:
                return [TInt("?")]
        else:
            return operand.render()
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Get subop type
        subop = self.op_details.body.subop
        if isinstance(subop, int):
            # Map int to enum
            try:
                subop = Scumm6Opcodes.SubopType(subop)
            except ValueError:
                pass
        
        # Map subop to descumm-style names
        subop_map = {
            "int_array": "int",
            "bit_array": "bit",
            "nibble_array": "nibble",
            "byte_array": "byte",
            "string_array": "string",
            "undim_array": "undim",
        }
        
        subop_name = subop.name if hasattr(subop, 'name') else f"subop_{subop}"
        display_subop = subop_map.get(subop_name, subop_name)
        
        # Get array variable
        array_var = self.op_details.body.array
        
        tokens = [TInstr("dimArray"), TText(f".{display_subop}(")]
        tokens.append(TText(get_variable_name(array_var)))
        
        if self.fused_operands:
            tokens.append(TText(", "))
            tokens.extend(self._render_operand(self.fused_operands[0]))
        else:
            tokens.append(TText(", ..."))
        
        tokens.append(TText(")"))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for dimArray operations."""
        if self.fused_operands:
            # Use fused operand
            size_expr = self._lift_operand(il, self.fused_operands[0])
        else:
            # Pop from stack
            size_expr = il.pop(4)
        
        # Get array variable and subop
        array_var = self.op_details.body.array
        subop = self.op_details.body.subop
        if hasattr(subop, 'name'):
            subop_name = subop.name
        else:
            subop_name = f"subop_{subop}"
        
        # Generate intrinsic call
        il.append(il.intrinsic([], f"dim_array.{subop_name}", [il.const(4, array_var), size_expr]))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                return il.const(4, operand.op_details.body.data)
            else:
                return il.const(4, 0)
        else:
            # For complex operands, use placeholder
            return il.const(4, 0)


class Iff(ControlFlowOp):

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)

    @property
    def stack_pop_count(self) -> int:
        return 1

    def render(self, as_operand: bool = False) -> List[Token]:
        jump_offset = self.op_details.body.jump_offset
        
        # Display absolute address like descumm if we have the current address
        if self.addr is not None:
            target_addr = self.addr + self.length() + jump_offset
            # Format as hex with leading zeros if negative (like descumm)
            if target_addr < 0:
                formatted_addr = f"{target_addr & 0xFFFFFFFF:x}"
            else:
                formatted_addr = f"{target_addr:x}"
            return [
                TInstr("if"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr(formatted_addr),
            ]
        
        # Fallback to relative addressing if no address available
        if jump_offset > 0:
            return [
                TInstr("if"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr(f"+{jump_offset}"),
            ]
        else:
            return [
                TInstr("if"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr(f"{jump_offset}"),
            ]

    def is_conditional(self) -> bool:
        return True

    def analyze(self, info: InstructionInfo, addr: int) -> None:
        super().analyze(info, addr)

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.JumpData), \
            f"Expected JumpData body, got {type(self.op_details.body)}"

        # Create labels for true and false branches
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        
        # Pop condition value from stack
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        
        # If condition != 0, jump to target (iff = "if true")
        il.append(
            il.if_expr(
                il.compare_not_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0)), t, f
            )
        )
        
        # True branch - jump to target
        il.mark_label(t)
        target_addr = addr + 3 + self.op_details.body.jump_offset  # 3 = instruction length
        il.append(il.jump(il.const(4, target_addr)))
        
        # False branch - continue to next instruction
        il.mark_label(f)


class IfNot(ControlFlowOp):

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)

    @property
    def stack_pop_count(self) -> int:
        return 1

    def render(self, as_operand: bool = False) -> List[Token]:
        jump_offset = self.op_details.body.jump_offset
        
        # Display absolute address like descumm if we have the current address
        if self.addr is not None:
            target_addr = self.addr + self.length() + jump_offset
            if jump_offset == 0:
                # Special case for zero offset (infinite loop)
                return [
                    TInstr("unless"),
                    TSep(" "),
                    TInstr("goto"),
                    TSep(" "),
                    TInstr("self"),
                ]
            else:
                # Format as hex with leading zeros if negative (like descumm)
                if target_addr < 0:
                    formatted_addr = f"{target_addr & 0xFFFFFFFF:x}"
                else:
                    formatted_addr = f"{target_addr:x}"
                return [
                    TInstr("unless"),
                    TSep(" "),
                    TInstr("goto"),
                    TSep(" "),
                    TInstr(formatted_addr),
                ]
        
        # Fallback to relative addressing if no address available
        if jump_offset > 0:
            return [
                TInstr("unless"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr(f"+{jump_offset}"),
            ]
        elif jump_offset < 0:
            return [
                TInstr("unless"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr(f"{jump_offset}"),
            ]
        else:
            # Zero offset = skip next instruction if true
            return [
                TInstr("unless"),
                TSep(" "),
                TInstr("goto"),
                TSep(" "),
                TInstr("self"),
            ]

    def is_conditional(self) -> bool:
        return True

    def analyze(self, info: InstructionInfo, addr: int) -> None:
        super().analyze(info, addr)

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.JumpData), \
            f"Expected JumpData body, got {type(self.op_details.body)}"

        # Create labels for true and false branches
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        
        # Pop condition value from stack
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        
        # If condition == 0, jump to target (if_not = "if false")
        il.append(
            il.if_expr(
                il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0)), t, f
            )
        )
        
        # True branch - jump to target
        il.mark_label(t)
        target_addr = addr + 3 + self.op_details.body.jump_offset  # 3 = instruction length
        il.append(il.jump(il.const(4, target_addr)))
        
        # False branch - continue to next instruction
        il.mark_label(f)


class Jump(ControlFlowOp):

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)

    def render(self, as_operand: bool = False) -> List[Token]:
        jump_offset = self.op_details.body.jump_offset
        
        # Display absolute address like descumm if we have the current address
        if self.addr is not None:
            target_addr = self.addr + self.length() + jump_offset
            if jump_offset == 0:
                # Special case for zero offset (infinite loop)
                return [
                    TInstr("jump"),
                    TSep(" "),
                    TInstr("self"),
                ]
            else:
                # Format as hex with leading zeros if negative (like descumm)
                if target_addr < 0:
                    formatted_addr = f"{target_addr & 0xFFFFFFFF:x}"
                else:
                    formatted_addr = f"{target_addr:x}"
                return [
                    TInstr("jump"),
                    TSep(" "),
                    TInstr(formatted_addr),
                ]
        
        # Fallback to relative addressing if no address available
        if jump_offset > 0:
            return [
                TInstr("goto"),
                TSep(" "),
                TInstr(f"+{jump_offset}"),
            ]
        elif jump_offset < 0:
            return [
                TInstr("goto"),
                TSep(" "),
                TInstr(f"{jump_offset}"),
            ]
        else:
            # Zero offset = infinite loop
            return [
                TInstr("goto"),
                TSep(" "),
                TInstr("self"),
            ]

    def is_conditional(self) -> bool:
        return False

    def analyze(self, info: InstructionInfo, addr: int) -> None:
        super().analyze(info, addr)

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.JumpData), \
            f"Expected JumpData body, got {type(self.op_details.body)}"

        # Unconditional jump to target
        target_addr = addr + 3 + self.op_details.body.jump_offset  # 3 = instruction length
        # Use const_pointer to ensure proper cross-references for inter-procedural jumps
        il.append(il.jump(il.const_pointer(il.arch.address_size, target_addr)))


class SmartIff(SmartConditionalJump):
    """Fusible 'if true' conditional jump instruction."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self._name = "iff"
        self._is_if_not = False  # This is 'if', not 'if_not'


class SmartIfNot(SmartConditionalJump):
    """Fusible 'if false/unless' conditional jump instruction."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self._name = "if_not"
        self._is_if_not = True  # This is 'if_not'


# =============================================================================
# Group 3: Complex Engine Intrinsics
# =============================================================================

# DrawObject, DrawObjectAt, DrawBlastObject are now generated by factories in opcode_table.py


class Cutscene(IntrinsicOp):
    """Start cutscene with variable number of parameters."""
    
    @property
    def intrinsic_name(self) -> str:
        return "cutscene"
    
    @property
    def pop_count(self) -> int:
        """Cutscene uses call_func_list which requires complex argument parsing."""
        # For call_func_list, we need to look at the actual body to determine argument count
        if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
            return len(self.op_details.body.args)
        else:
            # Default to 0 if we can't determine the argument count
            return 0


# EndCutscene, StopMusic, FreezeUnfreeze are now generated by factories in opcode_table.py


class StopObjectCode1(IntrinsicOp):
    """Stop object code (variant 1) with no parameters."""
    
    @property
    def intrinsic_name(self) -> str:
        return "stop_object_code1"
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Override to add no_ret() call as in original implementation."""
        super().lift(il, addr)
        il.append(il.no_ret())


class StopObjectCode2(IntrinsicOp):
    """Stop object code (variant 2) with no parameters."""
    
    @property
    def intrinsic_name(self) -> str:
        return "stop_object_code2"
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Override to add no_ret() call as in original implementation."""
        super().lift(il, addr)
        il.append(il.no_ret())


# StopObjectScript, StartSound, StopSound, PanCameraTo, ActorFollowCamera, SetCameraAt, LoadRoom, GetState, SetState, SetOwner are now generated by factories


# Simple Actor Query Operations - now generated by factories
# GetOwner, IsScriptRunning, IsSoundRunning, GetActorMoving, GetActorRoom, GetActorCostume, GetActorWalkBox, GetInventoryCount, FindInventory, GetObjectX, GetObjectY, GetObjectOldDir are now generated by factories


# AnimateActor, FaceActor, PickupObject, SetBoxFlags, DoSentence, GetActorElevation, GetActorWidth, GetActorScaleX, GetActorAnimCounter, GetVerbFromXy, GetActorFromXy are now generated by factories


class SetObjectName(FusibleMultiOperandMixin, Instruction):
    """Set object name operation with string message."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
        self._stack_pop_count = 2  # Pops object ID and room ID
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        return max(0, self._stack_pop_count - len(self.fused_operands))
    
    def _extract_message_text(self, message: Any) -> str:
        """Extract text from a SCUMM6 Message object."""
        return extract_message_text(message)
    
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        else:
            return il.const(4, operand.op_details.body.data)
    
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        tokens: List[Token] = [TInstr("setObjectName")]
        tokens.append(TText("("))
        
        # Add object ID and room ID parameters if fused
        if self.fused_operands:
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            
            # Add the string after parameters
            if len(self.fused_operands) >= 2 and isinstance(self.op_details.body, Scumm6Opcodes.Message):
                tokens.append(TSep(", "))
                string_text = self._extract_message_text(self.op_details.body)
                tokens.append(TText(f'"{string_text}"'))
        else:
            # No fusion - show placeholders and string
            tokens.append(TText("..."))
            if isinstance(self.op_details.body, Scumm6Opcodes.Message):
                tokens.append(TSep(", "))
                string_text = self._extract_message_text(self.op_details.body)
                tokens.append(TText(f'"{string_text}"'))
        
        tokens.append(TText(")"))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Extract the message text
        if isinstance(self.op_details.body, Scumm6Opcodes.Message):
            from .helpers import extract_primary_text_for_llil
            message_text = extract_primary_text_for_llil(self.op_details.body)
            
            if message_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                if string_ptr:
                    # Build parameters: object_id, room_id, string_ptr
                    params = []
                    
                    # Add fused operands
                    for operand in self.fused_operands:
                        params.append(self._lift_operand(il, operand))
                    
                    # Add remaining stack pops
                    for _ in range(self.stack_pop_count):
                        params.append(il.pop(4))
                    
                    # Add string pointer
                    params.append(string_ptr)
                    
                    # Generate intrinsic
                    il.append(il.intrinsic([], "set_object_name", params))
                    return
        
        # Fallback without valid string
        params = []
        
        # Add fused operands
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add remaining stack pops
        for _ in range(self.stack_pop_count):
            params.append(il.pop(4))
        
        il.append(il.intrinsic([], "set_object_name", params))
    
    def fuse(self, previous: Instruction) -> Optional['SetObjectName']:
        """Fuse with push instruction for parameters."""
        # Only fuse if we need more operands (max 2: object_id and room_id)
        if len(self.fused_operands) >= 2:
            return None
            
        # Check if previous is a fusible push
        if not self._is_fusible_push(previous):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused


# Zero-Parameter Intrinsics and Timing Operations - now generated by factories
# BeginOverride, EndOverride, CreateBoxMatrix, StopTalking, StopSentence, Wait, Delay, DelaySeconds, DelayMinutes, DelayFrames, StartMusic, StopScript are now generated by factories


# Distance/Geometry/Query/Movement Operations - now generated by factories  
# IsRoomScriptRunning, GetObjectNewDir, DistObjectObject, DistObjectPt, DistPtPt, GetPixel, FindObject, GetVerbEntrypoint, IsActorInBox, WalkActorToObj, WalkActorTo, PutActorAtXy are now generated by factories


# PutActorAtObject - now generated by factories from configs.py


# Additional Simple Operations (now generated by factories from configs.py)
# GetDatetime - now generated by factories from configs.py


# GetAnimateVariable - now generated by factories from configs.py


# PickVarRandom - now generated by factories from configs.py


# GetActorLayer - now generated by factories from configs.py


# Final Simple Utility Operations (now generated by factories from configs.py)
# CursorCommand - now generated by factories from configs.py


# SoundKludge - now generated by factories from configs.py


class IfClassOfIs(FusibleMultiOperandMixin, Instruction):
    """Check if object belongs to a specific class - pushes boolean result to stack."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _get_max_operands(self) -> int:
        """if_class_of_is takes 3 parameters: object, class_id, and count."""
        return 3
    
    def fuse(self, previous: Instruction) -> Optional['IfClassOfIs']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        # Normally pops 2 values (plus the count which is already on stack)
        # With full fusion, pops nothing
        return max(0, 3 - len(self.fused_operands))

    def render(self, as_operand: bool = False) -> List[Token]:
        if self.fused_operands and len(self.fused_operands) >= 2:
            # We have at least object and class fused
            tokens: List[Token] = []
            tokens.append(TInstr("ifClassOfIs"))
            tokens.append(TSep("("))
            
            # The stack order is: object, class, count
            # With LIFO fusion: fused_operands[0] is object (last fused), [1] is class, [2] is count (first fused)
            if len(self.fused_operands) >= 3:
                # Full fusion - show object
                tokens.extend(self._render_operand(self.fused_operands[0]))
                tokens.append(TSep(", "))
                tokens.append(TSep("["))
                # Show class ID
                tokens.extend(self._render_operand(self.fused_operands[1]))
                tokens.append(TSep("]"))
            else:
                # Partial fusion
                tokens.append(TText("..."))
            
            tokens.append(TSep(")"))
            return tokens
        else:
            return [TInstr("if_class_of_is")]
    
    def produces_result(self) -> bool:
        """This instruction produces a boolean result that can be consumed."""
        return True
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            var_num = operand.op_details.body.data if hasattr(operand.op_details.body, 'data') else 0
            # Check if it's explicitly marked as a local variable type
            if hasattr(operand.op_details.body, 'type'):
                from ...scumm6_opcodes import Scumm6Opcodes
                if operand.op_details.body.type == Scumm6Opcodes.VarType.local:
                    return [TText(f"localvar{var_num}")]
                else:
                    return [TText(get_variable_name(var_num))]
            # Otherwise check if it's in the local variable range (0-15)
            elif 0 <= var_num < 16:  # First 16 are local variables
                return [TText(f"localvar{var_num}")]
            else:
                return [TText(get_variable_name(var_num))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            value = operand.op_details.body.data if hasattr(operand.op_details.body, 'data') else 0
            return [TInt(str(value))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.IfClassOfIs), \
            f"Expected IfClassOfIs body, got {type(self.op_details.body)}"
        
        if self.fused_operands and len(self.fused_operands) >= 2:
            # Use fused operands
            if len(self.fused_operands) >= 3:
                # Full fusion: object, class, count
                # With LIFO: fused_operands[0] is object, [1] is class, [2] is count
                object_val = self._lift_operand(il, self.fused_operands[0])
                class_val = self._lift_operand(il, self.fused_operands[1])
            else:
                # Partial fusion - pop remaining from stack
                if len(self.fused_operands) == 2:
                    # We have class and count (object still on stack)
                    class_val = self._lift_operand(il, self.fused_operands[0])
                    object_val = il.pop(4)
                else:
                    # We have only count
                    class_val = il.pop(4)
                    object_val = il.pop(4)
        else:
            # No fusion - pop from stack
            class_val = il.pop(4)    # Pop class ID
            object_val = il.pop(4)   # Pop object ID
        
        # Call intrinsic to check if object is of specified class
        # This returns a boolean result (0 or 1)
        result = il.intrinsic([il.reg(4, LLIL_TEMP(0))], "if_class_of_is", [object_val, class_val])
        il.append(result)
        
        # Push the result to stack
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            var_num = operand.op_details.body.data if hasattr(operand.op_details.body, 'data') else 0
            return il.reg(4, f"var_{var_num}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            value = operand.op_details.body.data if hasattr(operand.op_details.body, 'data') else 0
            return il.const(4, value)
        else:
            return il.const(4, 0)  # Placeholder


# SetClass - now generated by factories from configs.py


# DrawBox - now generated by factories from configs.py


# IsAnyOf - now generated by factories from configs.py


# Additional Simple Script Operations (now generated by factories from configs.py)
# LoadRoomWithEgo - now generated by factories from configs.py


# SetBoxSet - now generated by factories from configs.py


# StampObject - now generated by factories from configs.py


# SetBlastObjectWindow - now generated by factories from configs.py


# PseudoRoom - now generated by factories from configs.py


# FindAllObjects - now generated by factories from configs.py


# Simple Script and Object Operations (now generated by factories from configs.py)
# JumpToScript - now generated by factories from configs.py


# StartObject - now generated by factories from configs.py


# StartObjectQuick - now generated by factories from configs.py


# Array Management Operations (now generated by factories from configs.py)
# DimArray - now generated by factories from configs.py


# Dim2dimArray - now generated by factories from configs.py


# Kernel Operations (now generated by factories from configs.py)
# KernelGetFunctions - now generated by factories from configs.py


# KernelSetFunctions - now generated by factories from configs.py


# Additional Utility Operations (now generated by factories from configs.py)
# SaveRestoreVerbs - custom implementation for sub-operation support

class SaveRestoreVerbs(FusibleMultiOperandMixin, Instruction):
    """Save/restore verbs operation with custom fusion support."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        return 3  # save_restore_verbs pops 3 values
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        return 3  # saveRestoreVerbs takes 3 parameters
    
    def fuse(self, previous: Instruction) -> Optional['SaveRestoreVerbs']:
        """Attempt to fuse with previous instruction."""
        return cast(Optional['SaveRestoreVerbs'], self._standard_fuse(previous))
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif operand.produces_result():
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Placeholder
    
    def render(self, as_operand: bool = False) -> List[Token]:
        # Get sub-operation byte
        
        # The body should be CallFuncPop3Byte which has a param field
        subop_byte = self.op_details.body.param if hasattr(self.op_details.body, 'param') else 0
        
        # Map sub-operation byte to descumm-style names
        subop_names = {
            1: "saveVerbs",
            141: "saveVerbs",    # 0x8D
            142: "restoreVerbs", # 0x8E
            # Add more mappings as we discover them
        }
        
        subop_name = subop_names.get(subop_byte, f"subop_{subop_byte}")
        display_name = f"saveRestoreVerbs.{subop_name}"
        
        # Handle fused operands
        if self.fused_operands:
            tokens = [TInstr(display_name), TSep("(")]
            # Render operands in push order (not reversed)
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TSep(")"))
            return tokens
        else:
            # No fusion - show with ellipsis
            return [TInstr(f"{display_name}(...)")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        
        # Get sub-operation byte (now unsigned)
        subop_byte = self.op_details.body.param if hasattr(self.op_details.body, 'param') else 0
        
        # Map sub-operation byte to descumm-style intrinsic names
        subop_intrinsics = {
            1: "save_restore_verbs.saveVerbs",
            141: "save_restore_verbs.saveVerbs",    # 0x8D
            142: "save_restore_verbs.restoreVerbs", # 0x8E
        }
        
        intrinsic_name = subop_intrinsics.get(subop_byte, f"save_restore_verbs.subop_{subop_byte}")
        
        if self.fused_operands:
            # Use fused operands directly
            params = [self._lift_operand(il, op) for op in self.fused_operands]
            il.append(il.intrinsic([], IntrinsicName(intrinsic_name), params))
        else:
            # Pop 3 arguments from stack
            params = [il.pop(4) for _ in range(3)]
            il.append(il.intrinsic([], IntrinsicName(intrinsic_name), params))


# Dialog and Text Operations (now generated by factories from configs.py)

class PrintLine(FusibleMultiOperandMixin, Instruction):
    """Print line operations with various formatting options."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression with parentheses
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # Complex case: would need to execute operand's lift method
            # For now, use placeholder - future enhancement needed
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Placeholder
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop's pop_count."""
        subop_body = self.op_details.body.body
        return getattr(subop_body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['PrintLine']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Handle both enum and int subop types
        if hasattr(self.op_details.body.subop, 'name'):
            subop_name = get_subop_name(self.op_details.body.subop)
        else:
            # Map integer subop values to names
            subop_int_map = {
                0x01: "overhead",
                0x02: "mumble",
                0x03: "textstring",
                0x04: "baseop",  # begin
                0x05: "endd",
                0x06: "color",
                0x07: "left",
                0x08: "at",  # XY
                0x09: "right",
                0x0A: "center",
                0x0B: "clipped",
            }
            subop_name = subop_int_map.get(self.op_details.body.subop, f"subop_{self.op_details.body.subop}")
        
        # Map subop names to descumm-style names
        subop_map = {
            "begin": "begin",
            "baseop": "begin",  # Alternative name for begin
            "color": "color",
            "center": "center",
            "charset": "charset",
            "left": "left",
            "overhead": "overhead",
            "mumble": "mumble",
            "msg": "msg",
            "textstring": "msg",  # Alternative name for msg
            "width": "width",
            "transparency": "transparency",
            "xy": "XY",  # Map xy to XY for descumm compatibility
            "at": "XY",  # Alternative name for XY
            "endd": "end",  # Map endd to end
            "right": "right",
            "clipped": "right",  # descumm uses "right" for clipped
        }
        
        # Use the mapped name or fall back to original
        display_subop = subop_map.get(subop_name, subop_name)
        display_name = f"printLine.{display_subop}"
        
        tokens: List[Token] = [TInstr(display_name)]
        
        # Check for specific body types
        subop_body = self.op_details.body.body
        
        if isinstance(subop_body, Scumm6Opcodes.CallFuncString):
            # String parameter (like msg)
            tokens.append(TText("("))
            # Handle complex string formatting
            string_data = subop_body.data
            # Basic handling of special sequences
            # TODO: Full descumm-style formatting with sound() and wait()
            if string_data:
                # For now, show raw string with escape sequences
                tokens.append(TText(f'"{string_data}"'))
            else:
                tokens.append(TText('""'))
            tokens.append(TText(")"))
        elif hasattr(subop_body, '__class__') and subop_body.__class__.__name__ == 'Message':
            # Complex message with parts (sound, text, wait, etc.)
            tokens.append(TText("("))
            # Parse the message parts to reconstruct descumm-style output
            if hasattr(subop_body, 'parts') and subop_body.parts:
                msg_tokens: List[Token] = []
                i = 0
                parts = subop_body.parts
                
                while i < len(parts) and parts[i].data != 0:
                    part = parts[i]
                    
                    if part.data == 0xff and hasattr(part, 'content'):
                        # Special sequence
                        special = part.content
                        if special.code == 0x0a:  # Sound command
                            # Sound command with inline values
                            if hasattr(special, 'payload'):
                                sound = special.payload
                                if hasattr(sound, 'value1') and hasattr(sound, 'v3'):
                                    sound_id = sound.value1
                                    volume = sound.v3
                                    if msg_tokens:
                                        msg_tokens.append(TText(" + "))
                                    msg_tokens.append(TText(f"sound(0x{sound_id:x}, 0x{volume:x})"))
                        elif special.code == 0x03:  # Wait command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("wait()"))
                        elif special.code == 0x02:  # KeepText command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("keepText()"))
                        elif special.code == 0x01:  # Newline command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("newline()"))
                        # Other special codes can be added here
                    elif 32 <= part.data <= 126:
                        # Text run - collect consecutive printable characters
                        text = ""
                        while i < len(parts) and 32 <= parts[i].data <= 126:
                            text += chr(parts[i].data)
                            i += 1
                        if msg_tokens:
                            msg_tokens.append(TText(" + "))
                        msg_tokens.append(TText(f'"{text}"'))
                        i -= 1  # Back up since we'll increment at loop end
                    i += 1
                
                if msg_tokens:
                    tokens.extend(msg_tokens)
                else:
                    tokens.append(TText('""'))
            else:
                tokens.append(TText("..."))
            tokens.append(TText(")"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop0):
            # No parameters - just show empty parens
            tokens.append(TText("()"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop1):
            # Single parameter
            if self.fused_operands:
                tokens.append(TText("("))
                tokens.extend(self._render_operand(self.fused_operands[0]))
                tokens.append(TText(")"))
            else:
                tokens.append(TText("(...)"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop2):
            # Two parameters (like XY)
            if self.fused_operands and len(self.fused_operands) >= 2:
                tokens.append(TText("("))
                tokens.extend(self._render_operand(self.fused_operands[0]))
                tokens.append(TSep(", "))
                tokens.extend(self._render_operand(self.fused_operands[1]))
                tokens.append(TText(")"))
            else:
                tokens.append(TText("(...)"))
        elif self.fused_operands:
            # Regular parameters
            tokens.append(TText("("))
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TText(")"))
        else:
            # No fused operands - check if this operation expects parameters
            max_operands = self._get_max_operands()
            if max_operands > 0:
                # Operation expects parameters but none are fused
                tokens.append(TText("(...)"))
            else:
                # Operation takes no parameters
                tokens.append(TText("()"))
        
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for print line."""
        # For now, use intrinsic
        params = []
        
        # Add fused operands as direct parameters
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add remaining stack pops
        for _ in range(self.stack_pop_count):
            params.append(il.pop(4))
        
        il.append(il.intrinsic(
            [],  # no output
            IntrinsicName("print_line"),
            params
        ))


# PrintText - now generated by factories from configs.py


class PrintDebug(Instruction):
    """Print debug with text parameter."""

    def _extract_message_text(self, message: Any) -> Tuple[List[str], str]:
        """Extract text from a SCUMM6 Message object, including sound commands."""
        return extract_message_text_with_sound(message)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        # Check if this instruction contains a message
        from ...scumm6_opcodes import Scumm6Opcodes
        
        if hasattr(self.op_details.body, 'subop') and hasattr(self.op_details.body, 'body'):
            # This is a Print structure with a subop
            if (self.op_details.body.subop == Scumm6Opcodes.SubopType.textstring and 
                isinstance(self.op_details.body.body, Scumm6Opcodes.Message)):
                # Use generic message parsing with full control code support
                msg_tokens = parse_message_with_control_codes(self.op_details.body.body)
                tokens = [
                    TInstr("printDebug"),
                    TText(".msg(")
                ]
                tokens.extend(msg_tokens)
                tokens.append(TText(")"))
                return tokens
            else:
                # Handle other subops like begin(), end(), etc.
                subop_name = get_subop_name(self.op_details.body.subop)
                # Map baseop to begin to match descumm format
                if subop_name == "baseop":
                    subop_name = "begin"
                return [TInstr("printDebug"), TText(f".{subop_name}()")]
        
        # Fallback for simple print_debug without subop
        return [TInstr("printDebug")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Check if this instruction contains a message
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        if (hasattr(self.op_details.body, 'subop') and 
            hasattr(self.op_details.body, 'body') and
            self.op_details.body.subop == Scumm6Opcodes.SubopType.textstring and 
            isinstance(self.op_details.body.body, Scumm6Opcodes.Message)):
            
            # Extract the primary text from the message (ignoring control codes for now)
            from .helpers import extract_primary_text_for_llil
            message_text = extract_primary_text_for_llil(self.op_details.body.body)
            
            if message_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                if string_ptr:
                    # Generate intrinsic with string pointer
                    il.append(il.intrinsic([], "print_debug", [string_ptr]))
                    return
        
        # Default: simple intrinsic without parameters
        il.append(il.intrinsic([], "print_debug", []))
    


class PrintSystem(FusibleMultiOperandMixin, Instruction):
    """Print system message with msg subop support."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            elif hasattr(subop_value, 'name'):
                # Handle enum - check if it's the color subop
                if subop_value.name == 'color':
                    return 1
            
            # Check numeric value for color subop (0x42 = 66)
            if subop_value == 0x42:
                return 1  # Color value
        
        return 0  # Default: no fusion for other subops
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def fuse(self, previous: Instruction) -> Optional['PrintSystem']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        else:
            return [TText("operand")]
    
    def _extract_message_text(self, message: Any) -> str:
        """Extract text from a SCUMM6 Message object."""
        return extract_message_text(message)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        if hasattr(self.op_details.body, 'subop') and hasattr(self.op_details.body, 'body'):
            # This is a Print structure with a subop
            subop_value = self.op_details.body.subop
            
            # Convert enum to int if needed
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            # Check if subop is 0x4B (75) which is textstring/msg
            if subop_value == 0x4B:
                if isinstance(self.op_details.body.body, Scumm6Opcodes.Message):
                    # Use generic message parsing with full control code support
                    msg_tokens = parse_message_with_control_codes(self.op_details.body.body)
                    tokens = [
                        TInstr("printSystem"),
                        TText(".msg(")
                    ]
                    tokens.extend(msg_tokens)
                    tokens.append(TText(")"))
                    return tokens
                else:
                    # No message body
                    return [TInstr("printSystem"), TText(".msg()")]
            else:
                # Other subops - use generic rendering
                if hasattr(self.op_details.body.subop, 'name'):
                    subop_name = get_subop_name(self.op_details.body.subop)
                    
                    # Handle color subop with fusion
                    if subop_name == 'color' and self.fused_operands:
                        tokens = [TInstr("printSystem"), TText(".color(")]
                        for i, operand in enumerate(self.fused_operands):
                            if i > 0:
                                tokens.append(TSep(", "))
                            tokens.extend(self._render_operand(operand))
                        tokens.append(TText(")"))
                        return tokens
                    
                    # Apply descumm function name mapping
                    from .helpers import apply_descumm_function_name
                    display_name = f"print_system.{subop_name}"
                    display_name = apply_descumm_function_name(display_name)
                    
                    # Extract just the subop part if it was mapped
                    if "." in display_name:
                        subop_display = display_name.split(".", 1)[1]
                    else:
                        subop_display = subop_name
                    
                    return [TInstr("printSystem"), TText(f".{subop_display}()")]
        
        # Fallback for simple print_system without subop
        return [TInstr("printSystem")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Handle different subops
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            
            # Handle message subop
            if (hasattr(self.op_details.body, 'body') and
                subop_value == Scumm6Opcodes.SubopType.textstring and 
                isinstance(self.op_details.body.body, Scumm6Opcodes.Message)):
                
                # Extract the primary text from the message
                from .helpers import extract_primary_text_for_llil
                message_text = extract_primary_text_for_llil(self.op_details.body.body)
                
                if message_text:
                    # Try to get a string pointer
                    string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                    if string_ptr:
                        # Generate intrinsic with string pointer
                        il.append(il.intrinsic([], "print_system", [string_ptr]))
                        return
                
                # Fallback for message without valid string
                il.append(il.intrinsic([], "print_system", []))
                return
            
            # Handle color subop with fusion
            elif hasattr(subop_value, 'name') and subop_value.name == 'color' and self.fused_operands:
                # Use fused operands for color subop
                params = []
                for operand in self.fused_operands:
                    if operand.__class__.__name__ in ['PushByte', 'PushWord']:
                        params.append(il.const(4, operand.op_details.body.data))
                    elif operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
                        params.append(il.reg(4, f"var_{operand.op_details.body.data}"))
                    else:
                        params.append(il.const(4, 0))  # Fallback
                il.append(il.intrinsic([], "print_system.color", params))
                return
        
        # Default: simple intrinsic
        il.append(il.intrinsic([], "print_system", []))
    


class PrintText(FusibleMultiOperandMixin, Instruction):
    """Print text with various formatting options including printCursor."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
        self._stack_pop_count = 0  # Default, will be set based on subop
        
        # Determine stack pop count based on subop
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            # Set pop count based on subop type
            if subop_value == 0x41:  # at (XY)
                self._stack_pop_count = 2  # Pops x and y coordinates
            elif subop_value == 0x42:  # color
                self._stack_pop_count = 1  # Pops color value
            # Add other subops as needed
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            if subop_value == 0x41:  # at (XY)
                return 2  # X and Y coordinates
            elif subop_value == 0x42:  # color
                return 1  # Color value
        
        return 0  # Default: no fusion for other subops
    
    @property
    def stack_pop_count(self) -> int:
        """Return 0 when fully fused, otherwise the normal count."""
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            if subop_value == 0x41:  # at (XY)
                # For XY, we need 2 operands
                return max(0, 2 - len(self.fused_operands))
            elif subop_value == 0x42:  # color
                # For color, we need 1 operand
                return max(0, 1 - len(self.fused_operands))
        
        return self._stack_pop_count
    
    def fuse(self, previous: Instruction) -> Optional['PrintText']:
        """Use standard fusion logic from mixin."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    def _extract_message_text(self, message: Any) -> str:
        """Extract text from a SCUMM6 Message object."""
        return extract_message_text(message)
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(str(operand.op_details.body.data))]
            else:
                return [TInt("?")]
        elif operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Handle variable pushes
            if hasattr(operand.op_details.body, 'data'):
                from .smart_bases import get_variable_name
                var_id = operand.op_details.body.data
                # Handle signed byte interpretation for PushByteVar
                if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                    var_id = var_id + 256
                return [TInt(get_variable_name(var_id))]
            else:
                return [TInt("var_?")]
        else:
            return operand.render()
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        if hasattr(self.op_details.body, 'subop') and hasattr(self.op_details.body, 'body'):
            # This is a Print structure with a subop
            subop_value = self.op_details.body.subop
            
            # Convert enum to int if needed
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            # Check if subop is 0x4B (75) which is printCursor.msg
            if subop_value == 0x4B:
                if isinstance(self.op_details.body.body, Scumm6Opcodes.Message):
                    # Use generic message parsing with full control code support
                    msg_tokens = parse_message_with_control_codes(self.op_details.body.body)
                    tokens = [
                        TInstr("printCursor"),
                        TText(".msg(")
                    ]
                    tokens.extend(msg_tokens)
                    tokens.append(TText(")"))
                    return tokens
                else:
                    # No message body
                    return [TInstr("printCursor"), TText(".msg()")]
            elif subop_value == 0x41:  # at (XY)
                tokens = [TInstr("printCursor"), TText(".XY")]
                if self.fused_operands and len(self.fused_operands) >= 2:
                    # Fused XY coordinates
                    # Due to how fusion works iteratively from the end of the sequence,
                    # fused_operands[0] = first pushed, fused_operands[1] = second pushed
                    tokens.append(TText("("))
                    tokens.extend(self._render_operand(self.fused_operands[0]))  # first param (x)
                    tokens.append(TText(", "))
                    tokens.extend(self._render_operand(self.fused_operands[1]))  # second param (y)
                    tokens.append(TText(")"))
                else:
                    # Not fused, show with placeholders
                    tokens.append(TText("(...)"))
                return tokens
            elif subop_value == 0x42:  # color
                tokens = [TInstr("printCursor"), TText(".color")]
                if self.fused_operands and len(self.fused_operands) >= 1:
                    # Fused color value
                    tokens.append(TText("("))
                    tokens.extend(self._render_operand(self.fused_operands[0]))
                    tokens.append(TText(")"))
                else:
                    # Not fused, show with placeholder
                    tokens.append(TText("(...)"))
                return tokens
            else:
                # Other subops - use generic rendering with descumm mapping
                if hasattr(self.op_details.body.subop, 'name'):
                    subop_name = get_subop_name(self.op_details.body.subop)
                    # Apply descumm function name mapping
                    from .helpers import apply_descumm_function_name
                    full_name = f"print_text.{subop_name}"
                    mapped_name = apply_descumm_function_name(full_name)
                    
                    # If mapped, return the mapped name
                    if mapped_name != full_name:
                        return [TInstr(mapped_name), TText("()")]
                    else:
                        return [TInstr("printText"), TText(f".{subop_name}()")]
        
        # Fallback for simple print_text without subop
        return [TInstr("printText")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for print operations."""
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        if hasattr(self.op_details.body, 'subop'):
            subop_value = self.op_details.body.subop
            if hasattr(subop_value, 'value'):
                subop_value = subop_value.value
            
            # Handle message subop (textstring = 0xF9)
            if (subop_value == 0xF9 and 
                hasattr(self.op_details.body, 'body') and 
                isinstance(self.op_details.body.body, Scumm6Opcodes.Message)):
                
                # Extract the primary text from the message
                from .helpers import extract_primary_text_for_llil
                message_text = extract_primary_text_for_llil(self.op_details.body.body)
                
                if message_text:
                    # Try to get a string pointer
                    string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                    if string_ptr:
                        # Generate intrinsic with string pointer
                        il.append(il.intrinsic([], "print_text", [string_ptr]))
                        return
                
                # Fallback for message without valid string
                il.append(il.intrinsic([], "print_text", []))
                return
            
            elif subop_value == 0x41 and self.fused_operands and len(self.fused_operands) >= 2:
                # Fused XY coordinates
                # Due to how fusion works iteratively from the end,
                # fused_operands[0] = first pushed, fused_operands[1] = second pushed
                # Match the render order
                x_expr = self._lift_operand(il, self.fused_operands[0])  # first param
                y_expr = self._lift_operand(il, self.fused_operands[1])  # second param
                il.append(il.intrinsic([], "print_text", [x_expr, y_expr]))
            else:
                # Not fused or other subops - use stack pops
                params = []
                for _ in range(self.stack_pop_count):
                    params.append(il.pop(4))
                il.append(il.intrinsic([], "print_text", params))
        else:
            # No subop
            il.append(il.intrinsic([], "print_text", []))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                return il.const(4, operand.op_details.body.data)
            else:
                return il.const(4, 0)
        else:
            # For complex operands, we'd need to handle them specially
            return il.const(4, 0)
    


# PrintActor - now generated by factories from configs.py


# PrintEgo - now generated by factories from configs.py


class TalkActor(FusibleMultiOperandMixin, Instruction):
    """Talk actor with string message and actor parameter."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
        self._stack_pop_count = 1  # Pops actor ID from stack by default
    
    @property
    def stack_pop_count(self) -> int:
        """Return 0 when fused, 1 when not fused."""
        return 0 if self.fused_operands else self._stack_pop_count
    
    def _extract_message_text(self, message: Any) -> Tuple[List[str], str]:
        """Extract text and sound commands from a SCUMM6 Message object."""
        return extract_message_text_with_sound(message)
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        else:
            return il.const(4, operand.op_details.body.data)
    
    
    def render(self, as_operand: bool = False) -> List[Token]:
        # Extract the message text from the bytecode
        from ...scumm6_opcodes import Scumm6Opcodes
        
        if self.fused_operands and len(self.fused_operands) >= 1:
            # We have the actor parameter fused
            tokens = [TInstr("talkActor"), TText("(")]
            
            # Use generic message parsing with full control code support
            if isinstance(self.op_details.body, Scumm6Opcodes.Message):
                msg_tokens = parse_message_with_control_codes(self.op_details.body)
                tokens.extend(msg_tokens)
            else:
                tokens.append(TText("..."))
            
            # Add the actor parameter
            tokens.extend([TSep(", ")])
            tokens.extend(self._render_operand(self.fused_operands[0]))
            tokens.append(TText(")"))
            return tokens
        else:
            # No fusion - don't show the message content
            return [TInstr("talkActor"), TText("()")]
    
    def _extract_all_strings_for_llil(self, message: Any) -> List[str]:
        """Extract all string segments from a message for LLIL string lookup.
        
        This extracts strings separated by control codes like wait(), sound(), etc.
        For example: "Hello" + wait() + "World" returns ["Hello", "World"]
        """
        strings: List[str] = []
        current_chars: List[str] = []
        
        for part in message.parts:
            if hasattr(part, 'data'):
                if part.data == 0xFF or part.data == 0:
                    # Control code or terminator - finish current string if any
                    if current_chars:
                        strings.append(''.join(current_chars))
                        current_chars = []
                    # Skip the control code itself
                elif 32 <= part.data <= 126:
                    # Direct printable character
                    current_chars.append(chr(part.data))
                elif hasattr(part, 'content') and hasattr(part.content, 'value'):
                    # Character wrapped in content
                    char_value = part.content.value
                    if isinstance(char_value, int) and 32 <= char_value <= 126:
                        current_chars.append(chr(char_value))
        
        # Add any remaining string
        if current_chars:
            strings.append(''.join(current_chars))
        
        return strings
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        params = []
        
        # First parameter is always the actor ID
        if self.fused_operands and len(self.fused_operands) >= 1:
            # Use fused actor parameter
            params.append(self._lift_operand(il, self.fused_operands[0]))
            
            # For fused case, extract all strings from the message and add them as string pointers
            if isinstance(self.op_details.body, Scumm6Opcodes.Message):
                strings = self._extract_all_strings_for_llil(self.op_details.body)
                
                for i, string_text in enumerate(strings):
                    if string_text:  # Skip empty strings
                        # Use sequential temp register indices starting from 0
                        string_ptr = get_string_pointer_for_llil(il, string_text, i)
                        if string_ptr:
                            params.append(string_ptr)
        else:
            # Pop actor from stack
            params.append(il.pop(4))
            # For non-fused case, the message is embedded in the instruction and not looked up
            # from BSTR, so we don't add string pointers
        
        # Generate intrinsic with actor ID and possibly string pointers
        il.append(il.intrinsic([], "talk_actor", params))
    
    def fuse(self, previous: Instruction) -> Optional['TalkActor']:
        """Fuse with push instruction for actor parameter."""
        # Only fuse if we need an operand
        if len(self.fused_operands) >= 1:
            return None
            
        # Check if previous is a fusible push
        if not self._is_fusible_push(previous):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused


# TalkEgo - now generated by factories from configs.py


# Complex Operations with Sub-commands
class CursorCommand(FusibleMultiOperandMixin, Instruction):
    """Cursor command operations with various sub-commands."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression with parentheses
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # Complex case: would need to execute operand's lift method
            # For now, use placeholder - future enhancement needed
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Placeholder
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop's pop_count."""
        subop_body = self.op_details.body.body
        
        # Special handling for CallFuncList which uses pop_list instead of pop_count
        if hasattr(subop_body, "pop_list") and subop_body.pop_list:
            # For list operations, we need to get the count from the stack
            # This is a special case where we need to look at previous instructions
            if self.op_details.body.subop.name == "charset_color":
                # The last fused operand should be the count
                if self.fused_operands and len(self.fused_operands) > 0:
                    last_operand = self.fused_operands[-1]
                    if hasattr(last_operand.op_details.body, 'data'):
                        # Return count + 1 to include the count parameter itself
                        return int(last_operand.op_details.body.data) + 1
                # If no fused operands, we need to allow fusion to start
                # Return a reasonable maximum to allow initial fusion
                return 10  # Allow up to 10 operands until we know the actual count
            return 0
        
        return getattr(subop_body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['CursorCommand']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        subop_name = get_subop_name(self.op_details.body.subop)
        
        # Map subop names to descumm-style names
        subop_map = {
            "charset_set": "initCharset",
            "charset_color": "charsetColors",
            "cursor_on": "on",
            "cursor_off": "off",
            "cursor_soft_on": "softOn",
            "cursor_soft_off": "softOff",
            "userput_on": "userputOn",
            "userput_off": "userputOff",
            "userput_soft_on": "userputSoftOn",
            "userput_soft_off": "userputSoftOff",
            "cursor_image": "image",
            "cursor_hotspot": "hotspot",
            "cursor_transparent": "transparent",
        }
        
        # Use the mapped name or fall back to original
        display_subop = subop_map.get(subop_name, subop_name)
        display_name = f"cursorCommand.{display_subop}"
        
        # Apply descumm function name mapping if available
        from .helpers import apply_descumm_function_name
        display_name = apply_descumm_function_name(display_name)
        
        tokens: List[Token] = [TInstr(display_name)]
        
        # Check for specific body types
        subop_body = self.op_details.body.body
        
        if isinstance(subop_body, Scumm6Opcodes.CallFuncPop0):
            # No parameters - just show empty parens
            if not self.fused_operands:
                tokens.append(TText("()"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncList):
            # List parameter (for charset_color)
            tokens.append(TText("("))
            if self.fused_operands:
                # The last operand is the count, the rest are the values
                if len(self.fused_operands) > 0:
                    # Extract count from last operand
                    count_operand = self.fused_operands[-1]
                    if hasattr(count_operand.op_details.body, 'data'):
                        count = count_operand.op_details.body.data
                        # Show as array, excluding the count
                        tokens.append(TText("["))
                        # Show the actual values (all operands except the last one)
                        value_operands = self.fused_operands[:-1]
                        # Use min to handle cases where we have fewer operands than expected
                        actual_count = min(count, len(value_operands))
                        for i, operand in enumerate(value_operands[:actual_count]):
                            if i > 0:
                                tokens.append(TSep(", "))
                            tokens.extend(self._render_operand(operand))
                        # Add ellipsis if we expect more parameters than we have
                        if count > len(value_operands):
                            if len(value_operands) > 0:
                                tokens.append(TSep(", "))
                            tokens.append(TText("..."))
                        tokens.append(TText("]"))
                    else:
                        # Fallback if we can't extract count
                        tokens.append(TText("["))
                        # Show all values except the last (count) operand
                        value_operands = self.fused_operands[:-1]
                        for i, operand in enumerate(value_operands):
                            if i > 0:
                                tokens.append(TSep(", "))
                            tokens.extend(self._render_operand(operand))
                        tokens.append(TText("]"))
                else:
                    tokens.append(TText("[]"))
            else:
                tokens.append(TText("..."))
            tokens.append(TText(")"))
        elif self.fused_operands:
            # Regular parameters
            tokens.append(TText("("))
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TText(")"))
        else:
            # No fused operands, show (...)
            tokens.append(TText("(...)"))
        
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for cursor command."""
        # For now, use intrinsic
        params = []
        
        # Add fused operands as direct parameters
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add remaining stack pops
        for _ in range(self.stack_pop_count):
            params.append(il.pop(4))
        
        il.append(il.intrinsic(
            [],  # no output
            IntrinsicName("cursor_command"),
            params
        ))


class PrintActor(FusibleMultiOperandMixin, Instruction):
    """Print actor dialog operations with various formatting options."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression with parentheses
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # Complex case: would need to execute operand's lift method
            # For now, use placeholder - future enhancement needed
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Placeholder
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop's pop_count."""
        subop_body = self.op_details.body.body
        
        # Special handling for begin/baseop subop which takes actor ID
        if self.op_details.body.subop.name in ["begin", "baseop"]:
            return 1  # Actor ID
        
        return getattr(subop_body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['PrintActor']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        subop_name = get_subop_name(self.op_details.body.subop)
        
        # Map subop names to descumm-style names
        subop_map = {
            "begin": "begin",
            "baseop": "begin",  # Alternative name for begin
            "color": "color",
            "center": "center",
            "charset": "charset",
            "left": "left",
            "overhead": "overhead",
            "mumble": "mumble",
            "msg": "msg",
            "textstring": "msg",  # Alternative name for msg
            "width": "width",
            "transparency": "transparency",
        }
        
        # Use the mapped name or fall back to original
        display_subop = subop_map.get(subop_name, subop_name)
        display_name = f"printActor.{display_subop}"
        
        tokens: List[Token] = [TInstr(display_name)]
        
        # Check for specific body types
        subop_body = self.op_details.body.body
        
        if isinstance(subop_body, Scumm6Opcodes.CallFuncString):
            # String parameter (like msg)
            tokens.append(TText("("))
            # Handle complex string formatting
            string_data = subop_body.data
            # Basic handling of special sequences
            # TODO: Full descumm-style formatting with sound() and wait()
            if string_data:
                # For now, show raw string with escape sequences
                tokens.append(TText(f'"{string_data}"'))
            else:
                tokens.append(TText('""'))
            tokens.append(TText(")"))
        elif hasattr(subop_body, '__class__') and subop_body.__class__.__name__ == 'Message':
            # Complex message with parts (sound, text, wait, etc.)
            tokens.append(TText("("))
            # Parse the message parts to reconstruct descumm-style output
            if hasattr(subop_body, 'parts') and subop_body.parts:
                msg_tokens: List[Token] = []
                i = 0
                parts = subop_body.parts
                
                while i < len(parts) and parts[i].data != 0:
                    part = parts[i]
                    
                    if part.data == 0xff and hasattr(part, 'content'):
                        # Special sequence
                        special = part.content
                        if special.code == 0x0a:  # Sound command
                            # Sound command with inline values
                            if hasattr(special, 'payload'):
                                sound = special.payload
                                if hasattr(sound, 'value1') and hasattr(sound, 'v3'):
                                    sound_id = sound.value1
                                    volume = sound.v3
                                    if msg_tokens:
                                        msg_tokens.append(TText(" + "))
                                    msg_tokens.append(TText(f"sound(0x{sound_id:x}, 0x{volume:x})"))
                        elif special.code == 0x03:  # Wait command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("wait()"))
                        elif special.code == 0x02:  # KeepText command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("keepText()"))
                        elif special.code == 0x01:  # Newline command
                            if msg_tokens:
                                msg_tokens.append(TText(" + "))
                            msg_tokens.append(TText("newline()"))
                        # Other special codes can be added here
                    elif 32 <= part.data <= 126:
                        # Text run - collect consecutive printable characters
                        text = ""
                        while i < len(parts) and 32 <= parts[i].data <= 126:
                            text += chr(parts[i].data)
                            i += 1
                        if msg_tokens:
                            msg_tokens.append(TText(" + "))
                        msg_tokens.append(TText(f'"{text}"'))
                        i -= 1  # Back up since we'll increment at loop end
                    i += 1
                
                if msg_tokens:
                    tokens.extend(msg_tokens)
                else:
                    tokens.append(TText('""'))
            else:
                tokens.append(TText("..."))
            tokens.append(TText(")"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop0):
            # No parameters - just show empty parens
            if not self.fused_operands:
                tokens.append(TText("()"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop1):
            # Single parameter
            if self.fused_operands:
                tokens.append(TText("("))
                tokens.extend(self._render_operand(self.fused_operands[0]))
                tokens.append(TText(")"))
            else:
                tokens.append(TText("(...)"))
        elif self.fused_operands:
            # Regular parameters
            tokens.append(TText("("))
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TText(")"))
        else:
            # No fused operands, show (...)
            tokens.append(TText("(...)"))
        
        return tokens
    
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for print actor."""
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Check if we have a Message subop
        subop_body = self.op_details.body.body
        subop_name = get_subop_name(self.op_details.body.subop)
        
        # Handle message subops (msg/textstring)
        if (subop_name in ["msg", "textstring"] and 
            hasattr(subop_body, '__class__') and 
            subop_body.__class__.__name__ == 'Message'):
            
            # Extract the primary text from the message
            from .helpers import extract_primary_text_for_llil
            message_text = extract_primary_text_for_llil(subop_body)
            
            if message_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                if string_ptr:
                    # Generate intrinsic with string pointer
                    params = [string_ptr]
                    
                    # Add any fused operands (like actor ID for begin subop)
                    for operand in self.fused_operands:
                        params.append(self._lift_operand(il, operand))
                    
                    # Add remaining stack pops
                    for _ in range(self.stack_pop_count):
                        params.append(il.pop(4))
                    
                    il.append(il.intrinsic([], "print_actor", params))
                    return
            
            # Fallback for message without valid string
            il.append(il.intrinsic([], "print_actor", []))
            return
        
        # Handle string subops (CallFuncString)
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncString) and subop_body.data:
            # String parameter - create a string pointer
            string_ptr = get_string_pointer_for_llil(il, subop_body.data, 0)
            if string_ptr:
                params = [string_ptr]
                
                # Add any fused operands
                for operand in self.fused_operands:
                    params.append(self._lift_operand(il, operand))
                
                # Add remaining stack pops
                for _ in range(self.stack_pop_count):
                    params.append(il.pop(4))
                
                il.append(il.intrinsic([], f"print_actor.{subop_name}", params))
                return
            
            # String not found - fallback
            il.append(il.intrinsic([], "print_actor", []))
            return
        
        # Default handling for non-string subops
        params = []
        
        # Add fused operands as direct parameters
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add remaining stack pops
        for _ in range(self.stack_pop_count):
            params.append(il.pop(4))
        
        il.append(il.intrinsic(
            [],  # no output
            IntrinsicName("print_actor"),
            params
        ))


class PrintEgo(PrintActor):
    """Print ego dialog operations - same as PrintActor but for ego."""
    
    def render(self, as_operand: bool = False) -> List[Token]:
        # Get tokens from parent class
        tokens = super().render()
        # Replace printActor with printEgo
        if tokens and hasattr(tokens[0], 'text'):
            tokens[0] = TInstr(tokens[0].text.replace('printActor', 'printEgo'))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for print ego."""
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Check if we have a Message subop
        subop_body = self.op_details.body.body
        subop_name = get_subop_name(self.op_details.body.subop)
        
        # Handle message subops (msg/textstring)
        if (subop_name in ["msg", "textstring"] and 
            hasattr(subop_body, '__class__') and 
            subop_body.__class__.__name__ == 'Message'):
            
            # Extract the primary text from the message
            from .helpers import extract_primary_text_for_llil
            message_text = extract_primary_text_for_llil(subop_body)
            
            if message_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                if string_ptr:
                    # Generate intrinsic with string pointer
                    params = [string_ptr]
                    
                    # Add any fused operands 
                    for operand in self.fused_operands:
                        params.append(self._lift_operand(il, operand))
                    
                    # Add remaining stack pops
                    for _ in range(self.stack_pop_count):
                        params.append(il.pop(4))
                    
                    il.append(il.intrinsic([], "print_ego", params))
                    return
            
            # Fallback for message without valid string
            il.append(il.intrinsic([], "print_ego", []))
            return
        
        # Handle string subops (CallFuncString)
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncString) and subop_body.data:
            # String parameter - create a string pointer
            string_ptr = get_string_pointer_for_llil(il, subop_body.data, 0)
            if string_ptr:
                params = [string_ptr]
                
                # Add any fused operands
                for operand in self.fused_operands:
                    params.append(self._lift_operand(il, operand))
                
                # Add remaining stack pops
                for _ in range(self.stack_pop_count):
                    params.append(il.pop(4))
                
                il.append(il.intrinsic([], f"print_ego.{subop_name}", params))
                return
            
            # String not found - fallback
            il.append(il.intrinsic([], "print_ego", []))
            return
        
        # Default handling for non-string subops
        params = []
        
        # Add fused operands as direct parameters
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add remaining stack pops
        for _ in range(self.stack_pop_count):
            params.append(il.pop(4))
        
        il.append(il.intrinsic(
            [],  # no output
            IntrinsicName("print_ego"),
            params
        ))


class ActorOps(FusibleMultiOperandMixin, Instruction):
    """Actor operations with various sub-commands."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop's pop_count."""
        subop_body = self.op_details.body.body
        return getattr(subop_body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['ActorOps']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Handle cases where subop is an int instead of enum
        subop_name = get_subop_name(self.op_details.body.subop)
        full_name = f"actor_ops.{subop_name}"
        from .helpers import apply_descumm_function_name
        display_name = apply_descumm_function_name(full_name)
        
        tokens: List[Token] = [TInstr(display_name)]
        
        # Check if this subop has string data (like actor_name)
        subop_body = self.op_details.body.body
        if isinstance(subop_body, Scumm6Opcodes.CallFuncString):
            # String parameter
            tokens.append(TText("("))
            tokens.append(TText(f'"{subop_body.data}"'))
            tokens.append(TText(")"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop0):
            # No parameters - just show empty parens if there's nothing fused
            if not self.fused_operands:
                tokens.append(TText("()"))
        elif self.fused_operands:
            # Add fused operand parameters
            tokens.append(TText("("))
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TText(")"))
        else:
            # No fusion and not handled above - show empty parens
            tokens.append(TText("()"))
        
        return tokens
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(get_variable_name(operand.op_details.body.data))]
            else:
                return [TInt("var_?")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
            else:
                return [TInt("?")]
        else:
            return [TText("operand")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        from ...actor_state import ActorProperty, get_current_actor_property_address, CURRENT_ACTOR_ADDRESS
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.ActorOps), \
            f"Expected ActorOps body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        subop_name = get_subop_name(subop)
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Build parameters
        params = []
        
        # Check if this subop has string data (like actor_name/setName)
        if isinstance(subop_body, Scumm6Opcodes.CallFuncString):
            # String parameter - create a string pointer
            string_ptr = get_string_pointer_for_llil(il, subop_body.data, 0)
            if string_ptr:
                params.append(string_ptr)
            else:
                # String not found in BSTR - return unimplemented
                il.append(il.unimplemented())
                return
        elif self.fused_operands:
            # Use fused operands directly
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
            # Pop any remaining arguments
            remaining_pops = pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
        else:
            # Pop all arguments from stack
            params = [il.pop(4) for _ in range(pop_count)]
        
        # Handle specific actor operations by writing to memory
        if subop_name == "set_current_actor":
            # setCurActor(actor_id) - write actor_id to CURRENT_ACTOR_ADDRESS
            if params:
                actor_id = params[0]
                il.append(il.store(4, il.const_pointer(4, CURRENT_ACTOR_ADDRESS), actor_id))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "set_costume":
            # setCostume(costume_id) - write to current actor's COSTUME property
            if params:
                costume_id = params[0]
                current_actor_addr, costume_offset = get_current_actor_property_address(ActorProperty.COSTUME)
                
                # Calculate: actor_base = *(CURRENT_ACTOR_ADDRESS) * ACTOR_STRUCT_SIZE + ACTORS_START
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                costume_addr = il.add(4, actor_base, il.const(4, costume_offset))
                il.append(il.store(2, costume_addr, costume_id))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "talk_color":
            # setTalkColor(color) - write to current actor's TALK_COLOR property
            if params:
                talk_color = params[0]
                current_actor_addr, talk_color_offset = get_current_actor_property_address(ActorProperty.TALK_COLOR)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                talk_color_addr = il.add(4, actor_base, il.const(4, talk_color_offset))
                il.append(il.store(1, talk_color_addr, talk_color))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "actor_name":
            # setName(string_ptr) - write string pointer to current actor's NAME_PTR property
            if params:
                name_ptr = params[0]
                current_actor_addr, name_ptr_offset = get_current_actor_property_address(ActorProperty.NAME_PTR)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                name_ptr_addr = il.add(4, actor_base, il.const(4, name_ptr_offset))
                il.append(il.store(4, name_ptr_addr, name_ptr))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "step_dist":
            # setWalkSpeed(x_speed, y_speed) - write to WALK_SPEED_X and WALK_SPEED_Y
            if len(params) >= 2:
                x_speed, y_speed = params[0], params[1]
                current_actor_addr, _ = get_current_actor_property_address(ActorProperty.WALK_SPEED_X)
                
                # Calculate actor base address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                
                # Write X speed
                x_speed_offset = ActorProperty.WALK_SPEED_X.value.offset
                x_speed_addr = il.add(4, actor_base, il.const(4, x_speed_offset))
                il.append(il.store(2, x_speed_addr, x_speed))
                
                # Write Y speed
                y_speed_offset = ActorProperty.WALK_SPEED_Y.value.offset
                y_speed_addr = il.add(4, actor_base, il.const(4, y_speed_offset))
                il.append(il.store(2, y_speed_addr, y_speed))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "init":
            # init() - no parameters, could initialize actor properties to defaults
            # For now, just generate a comment operation
            il.append(il.nop())
            
        elif subop_name == "ignore_boxes":
            # setIgnoreBoxes() - write 1 to current actor's IGNORE_BOXES property
            current_actor_addr, ignore_boxes_offset = get_current_actor_property_address(ActorProperty.IGNORE_BOXES)
            
            # Calculate actor property address
            current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
            from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
            actor_base = il.add(4, 
                il.const_pointer(4, ACTORS_START),
                il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
            )
            ignore_boxes_addr = il.add(4, actor_base, il.const(4, ignore_boxes_offset))
            il.append(il.store(1, ignore_boxes_addr, il.const(1, 1)))  # Set to 1 (true)
            
        elif subop_name == "never_zclip":
            # setNeverZClip() - write 1 to current actor's NEVER_ZCLIP property
            current_actor_addr, never_zclip_offset = get_current_actor_property_address(ActorProperty.NEVER_ZCLIP)
            
            # Calculate actor property address
            current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
            from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
            actor_base = il.add(4, 
                il.const_pointer(4, ACTORS_START),
                il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
            )
            never_zclip_addr = il.add(4, actor_base, il.const(4, never_zclip_offset))
            il.append(il.store(1, never_zclip_addr, il.const(1, 1)))  # Set to 1 (true)
            
        elif subop_name == "elevation":
            # setElevation(elevation) - write to current actor's ELEVATION property
            if params:
                elevation = params[0]
                current_actor_addr, elevation_offset = get_current_actor_property_address(ActorProperty.ELEVATION)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                elevation_addr = il.add(4, actor_base, il.const(4, elevation_offset))
                il.append(il.store(2, elevation_addr, elevation))  # 2 bytes, signed
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "scale":
            # setScale(scale) - write to both SCALE_X and SCALE_Y properties
            if params:
                scale = params[0]
                current_actor_addr, _ = get_current_actor_property_address(ActorProperty.SCALE_X)
                
                # Calculate actor base address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                
                # Write scale to both X and Y
                scale_x_offset = ActorProperty.SCALE_X.value.offset
                scale_x_addr = il.add(4, actor_base, il.const(4, scale_x_offset))
                il.append(il.store(1, scale_x_addr, scale))
                
                scale_y_offset = ActorProperty.SCALE_Y.value.offset
                scale_y_addr = il.add(4, actor_base, il.const(4, scale_y_offset))
                il.append(il.store(1, scale_y_addr, scale))
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "text_offset":
            # setTalkPos(x, y) - write to TALK_POS_X and TALK_POS_Y
            if len(params) >= 2:
                x_pos, y_pos = params[0], params[1]
                current_actor_addr, _ = get_current_actor_property_address(ActorProperty.TALK_POS_X)
                
                # Calculate actor base address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                
                # Write X position
                talk_pos_x_offset = ActorProperty.TALK_POS_X.value.offset
                talk_pos_x_addr = il.add(4, actor_base, il.const(4, talk_pos_x_offset))
                il.append(il.store(2, talk_pos_x_addr, x_pos))  # 2 bytes, signed
                
                # Write Y position
                talk_pos_y_offset = ActorProperty.TALK_POS_Y.value.offset
                talk_pos_y_addr = il.add(4, actor_base, il.const(4, talk_pos_y_offset))
                il.append(il.store(2, talk_pos_y_addr, y_pos))  # 2 bytes, signed
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "actor_width":
            # setWidth(width) - write to current actor's WIDTH property
            if params:
                width = params[0]
                current_actor_addr, width_offset = get_current_actor_property_address(ActorProperty.WIDTH)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                width_addr = il.add(4, actor_base, il.const(4, width_offset))
                il.append(il.store(1, width_addr, width))  # 1 byte
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "walk_animation":
            # setWalkFrame(frame) - write to current actor's WALK_FRAME property
            if params:
                frame = params[0]
                current_actor_addr, walk_frame_offset = get_current_actor_property_address(ActorProperty.WALK_FRAME)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                walk_frame_addr = il.add(4, actor_base, il.const(4, walk_frame_offset))
                il.append(il.store(1, walk_frame_addr, frame))  # 1 byte
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "stand_animation":
            # setStandFrame(frame) - write to current actor's STAND_FRAME property
            if params:
                frame = params[0]
                current_actor_addr, stand_frame_offset = get_current_actor_property_address(ActorProperty.STAND_FRAME)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                stand_frame_addr = il.add(4, actor_base, il.const(4, stand_frame_offset))
                il.append(il.store(1, stand_frame_addr, frame))  # 1 byte
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "talk_animation":
            # setTalkFrame(frame1, frame2) - write to current actor's TALK_FRAME property
            # Note: The second parameter might be for a different property or ignored
            if params:
                frame = params[0]  # Use first parameter for TALK_FRAME
                current_actor_addr, talk_frame_offset = get_current_actor_property_address(ActorProperty.TALK_FRAME)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                talk_frame_addr = il.add(4, actor_base, il.const(4, talk_frame_offset))
                il.append(il.store(1, talk_frame_addr, frame))  # 1 byte
                
                # If there's a second parameter, we might need to store it somewhere else
                # For now, we'll ignore it as we don't have a second talk frame field
            else:
                il.append(il.unimplemented())
                
        elif subop_name == "palette":
            # setPalette(palette) - write to current actor's PALETTE property
            if params:
                palette = params[0]
                current_actor_addr, palette_offset = get_current_actor_property_address(ActorProperty.PALETTE)
                
                # Calculate actor property address
                current_actor_id = il.load(4, il.const_pointer(4, current_actor_addr))
                from ...actor_state import ACTOR_STRUCT_SIZE, ACTORS_START
                actor_base = il.add(4, 
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, current_actor_id, il.const(4, ACTOR_STRUCT_SIZE))
                )
                palette_addr = il.add(4, actor_base, il.const(4, palette_offset))
                il.append(il.store(1, palette_addr, palette))  # 1 byte
            else:
                il.append(il.unimplemented())
            
        else:
            # Unknown or unimplemented subop - fallback to unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        from ... import vars
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - use il_get_var
            return vars.il_get_var(il, operand.op_details.body)
        else:
            # Constant push - use const
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return il.const(4, value)
        
        # Fallback to undefined
        return il.undefined()


class VerbOps(FusibleMultiOperandMixin, Instruction):
    """Verb operations with various sub-commands."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop's pop_count."""
        subop_body = self.op_details.body.body
        return getattr(subop_body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['VerbOps']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def _extract_message_text(self, message: Any) -> str:
        """Extract string from a Message object."""
        return extract_message_text(message)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        subop_name = get_subop_name(self.op_details.body.subop)
        full_name = f"verb_ops.{subop_name}"
        from .helpers import apply_descumm_function_name
        display_name = apply_descumm_function_name(full_name)
        
        tokens: List[Token] = [TInstr(display_name)]
        
        # Check if this subop has message data (like verb_name)
        subop_body = self.op_details.body.body
        if isinstance(subop_body, Scumm6Opcodes.Message):
            # Message parameter - extract the text
            tokens.append(TText("("))
            text = self._extract_message_text(subop_body)
            tokens.append(TText(f'"{text}"'))
            tokens.append(TText(")"))
        elif isinstance(subop_body, Scumm6Opcodes.CallFuncPop0):
            # No parameters - just show empty parens
            tokens.append(TText("()"))
        elif self.fused_operands:
            # Add fused operand parameters
            tokens.append(TText("("))
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            tokens.append(TText(")"))
        elif getattr(subop_body, "pop_count", 0) > 0:
            # Has parameters but not fused
            tokens.append(TText("(...)"))
        else:
            # No parameters
            tokens.append(TText("()"))
        
        return tokens
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(get_variable_name(operand.op_details.body.data))]
            else:
                return [TInt("var_?")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
            else:
                return [TInt("?")]
        else:
            return [TText("operand")]
    
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.VerbOps), \
            f"Expected VerbOps body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        intrinsic_name, unknown_subop = handle_unknown_subop_lift(il, subop, "verb_ops")
        
        # Check if this subop has message data (like verb_name)
        if isinstance(subop_body, Scumm6Opcodes.Message):
            # Message parameter - extract the text and create string pointer
            from .helpers import extract_primary_text_for_llil
            message_text = extract_primary_text_for_llil(subop_body)
            
            if message_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, message_text, 0)
                if string_ptr:
                    # Generate intrinsic with string pointer
                    params = [string_ptr]
                    
                    # Add any fused operands
                    for operand in self.fused_operands:
                        params.append(self._lift_operand(il, operand))
                    
                    # Add remaining stack pops
                    pop_count = getattr(subop_body, "pop_count", 0)
                    remaining_pops = pop_count - len(self.fused_operands)
                    for _ in range(remaining_pops):
                        params.append(il.pop(4))
                    
                    il.append(il.intrinsic([], intrinsic_name, params))
                    return
            
            # Fallback for message without valid string
            il.append(il.intrinsic([], intrinsic_name, []))
            return
        
        # Default handling for non-message subops
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Build parameters
        if self.fused_operands:
            # Use fused operands directly
            params = []
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
            # Pop any remaining arguments
            remaining_pops = pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
        else:
            # Pop arguments normally
            params = [il.pop(4) for _ in range(pop_count)]
        
        # If unknown subop, generate unimplemented instead of intrinsic
        if unknown_subop:
            # Generate unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
        else:
            # Normal intrinsic handling
            if push_count > 0:
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], intrinsic_name, params))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        else:
            return il.const(4, 0)  # Placeholder


class ArrayOps(FusibleMultiOperandMixin, Instruction):
    """Array operations with various sub-commands."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        # Check if we need to fix the length for assign_string with UnknownOp
        actual_length = length
        if hasattr(kaitai_op, 'body') and hasattr(kaitai_op.body, 'subop'):
            subop_value = kaitai_op.body.subop if isinstance(kaitai_op.body.subop, int) else kaitai_op.body.subop.value
            if subop_value == 0:  # assign_string
                # Check if it parsed as UnknownOp (which reads too much)
                if hasattr(kaitai_op.body, 'body') and hasattr(kaitai_op.body.body, 'data'):
                    # Manually calculate the correct length
                    # Format: opcode(1) + array(2) + subop(1) + message(variable)
                    data = kaitai_op.body.body.data
                    if isinstance(data, (bytes, bytearray)):
                        # Find null terminator
                        null_pos = data.find(0)
                        if null_pos >= 0:
                            # Correct length = 4 (opcode + array + subop) + message length + 1 (null)
                            actual_length = 4 + null_pos + 1
        
        super().__init__(kaitai_op, actual_length, addr)
        self.fused_operands: List[Instruction] = []
    
    def _extract_message_text(self, message: Any) -> str:
        """Extract text from a SCUMM6 Message object."""
        return extract_message_text(message)
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands based on subop."""
        # Handle both enum and integer subop types
        if hasattr(self.op_details.body.subop, 'name'):
            subop_name = get_subop_name(self.op_details.body.subop)
        else:
            # Map integer subop values to names
            subop_int_map = {
                0x00: "assign_string",
                # Add more mappings as needed
            }
            subop_value = self.op_details.body.subop
            subop_name = subop_int_map.get(subop_value, f"unknown_{subop_value}")
        
        # assign_string takes one parameter (the index)
        if subop_name == "assign_string":
            return 1
        # Other subops may have different requirements
        return 0
    
    def fuse(self, previous: Instruction) -> Optional['ArrayOps']:
        """Fuse with previous push instructions."""
        return self._standard_fuse(previous)  # type: ignore[return-value]
    
    @property
    def stack_pop_count(self) -> int:
        """Return remaining pops needed after fusion."""
        max_operands = self._get_max_operands()
        fused_count = len(self.fused_operands)
        return max(0, max_operands - fused_count)
    
    def render(self, as_operand: bool = False) -> List[Token]:
        
        # Handle both enum and integer subop types
        if hasattr(self.op_details.body.subop, 'name'):
            subop_name = get_subop_name(self.op_details.body.subop)
        else:
            # Map integer subop values to names
            subop_int_map = {
                0x00: "assign_string",
                # Add more mappings as needed
            }
            subop_value = self.op_details.body.subop
            subop_name = subop_int_map.get(subop_value, f"unknown_{subop_value}")
        
        # Special handling for assign_string
        if subop_name == "assign_string" and hasattr(self.op_details.body, 'array'):
            # Get array number and convert to name
            array_num = self.op_details.body.array
            array_name = SCUMM_ARRAY_NAMES.get(array_num, f"array_{array_num}")
            
            tokens: List[Token] = []
            
            # Show as array[index] = "string"
            tokens.append(TInt(array_name))
            tokens.append(TSep("["))
            
            # Add the index
            if self.fused_operands and len(self.fused_operands) >= 1:
                # Use fused operand for index
                tokens.extend(self._render_operand(self.fused_operands[0]))
            else:
                # Show as needing index from stack
                tokens.append(TText("..."))
            
            tokens.append(TSep("] = "))
            
            # Add the string value
            # The body might be UnknownOp if Kaitai didn't parse it correctly
            # In that case, try to extract the message manually
            if hasattr(self.op_details.body, 'body'):
                body = self.op_details.body.body
                if hasattr(body, 'parts'):
                    # Properly parsed Message object
                    string_text = self._extract_message_text(body)
                    tokens.append(TText(f'"{string_text}"'))
                else:
                    # UnknownOp - extract message manually from raw data
                    # The message starts right after the subop byte
                    if hasattr(body, 'data') and body.data:
                        # Extract text from raw bytes
                        text_chars = []
                        for byte in body.data:
                            if byte == 0:  # Null terminator
                                break
                            if 32 <= byte <= 126:  # Printable ASCII
                                text_chars.append(chr(byte))
                        string_text = ''.join(text_chars)
                        tokens.append(TText(f'"{string_text}"'))
                    else:
                        tokens.append(TText('"..."'))
            else:
                tokens.append(TText('"..."'))
            
            return tokens
        
        # Default rendering for other subops
        return [TInstr(f"array_ops.{subop_name}")]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # Complex case - placeholder
            return il.const(4, 0)
        else:
            return il.const(4, 0)
    
    def _extract_primary_text_for_llil(self, body: Any) -> str:
        """Extract the primary text content from array ops body for LLIL string lookup."""
        text_chars = []
        
        # Handle Message objects
        if hasattr(body, 'parts'):
            for part in body.parts:
                if hasattr(part, 'data'):
                    if part.data == 0xFF or part.data == 0:
                        # Stop at control codes or terminator
                        break
                    elif 32 <= part.data <= 126:
                        # Direct printable character
                        text_chars.append(chr(part.data))
                    elif hasattr(part, 'content') and hasattr(part.content, 'value'):
                        # Character wrapped in content
                        char_value = part.content.value
                        if isinstance(char_value, int) and 32 <= char_value <= 126:
                            text_chars.append(chr(char_value))
        # Handle UnknownOp with raw data
        elif hasattr(body, 'data') and body.data:
            # Extract text from raw bytes
            for byte in body.data:
                if byte == 0:  # Null terminator
                    break
                if 32 <= byte <= 126:  # Printable ASCII
                    text_chars.append(chr(byte))
        
        return ''.join(text_chars)
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        from ..instr.smart_bases import get_string_pointer_for_llil
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.ArrayOps), \
            f"Expected ArrayOps body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        intrinsic_name, unknown_subop = handle_unknown_subop_lift(il, subop, "array_ops")
        
        # Check for assign_string subop
        subop_value = subop if isinstance(subop, int) else (subop.value if hasattr(subop, 'value') else None)
        if subop_value == 0x00:  # assign_string
            # Get array number
            array_num = self.op_details.body.array
            
            # Extract the string text
            from .helpers import extract_primary_text_for_llil
            string_text = extract_primary_text_for_llil(subop_body)
            
            if string_text:
                # Try to get a string pointer
                string_ptr = get_string_pointer_for_llil(il, string_text, 0)
                if string_ptr:
                    # Build parameters: array_id, index, string_ptr
                    params = [il.const(4, array_num)]  # Array ID
                    
                    # Add index (from fused operand or stack)
                    if self.fused_operands and len(self.fused_operands) >= 1:
                        params.append(self._lift_operand(il, self.fused_operands[0]))
                    else:
                        params.append(il.pop(4))  # Pop index from stack
                    
                    params.append(string_ptr)  # String pointer
                    
                    # Generate intrinsic
                    il.append(il.intrinsic([], "array_ops.assign_string", params))
                    return
            
            # Fallback without valid string
            il.append(il.intrinsic([], "array_ops.assign_string", []))
            return
        
        # Default handling for other subops
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Build parameters
        if self.fused_operands:
            # Use fused operands directly
            params = []
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
            # Pop any remaining arguments
            remaining_pops = pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
        else:
            # Pop arguments normally
            params = [il.pop(4) for _ in range(pop_count)]
        
        # If unknown subop, generate unimplemented instead of intrinsic
        if unknown_subop:
            # Generate unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
        else:
            # Normal intrinsic handling
            if push_count > 0:
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], intrinsic_name, params))


class RoomOps(Instruction):
    """Room operations with various sub-commands."""
    
    def render(self, as_operand: bool = False) -> List[Token]:
        subop_name = get_subop_name(self.op_details.body.subop)
        return [TInstr(f"room_ops.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.RoomOps), \
            f"Expected RoomOps body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        intrinsic_name, unknown_subop = handle_unknown_subop_lift(il, subop, "room_ops")
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        # If unknown subop, generate unimplemented instead of intrinsic
        if unknown_subop:
            # Generate unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
        else:
            # Normal intrinsic handling
            if push_count > 0:
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], intrinsic_name, params))


class SystemOps(Instruction):
    """System operations with various sub-commands."""
    
    def render(self, as_operand: bool = False) -> List[Token]:
        subop_name = get_subop_name(self.op_details.body.subop)
        return [TInstr(f"system_ops.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.SystemOps), \
            f"Expected SystemOps body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        intrinsic_name, unknown_subop = handle_unknown_subop_lift(il, subop, "system_ops")
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        # If unknown subop, generate unimplemented instead of intrinsic
        if unknown_subop:
            # Generate unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
        else:
            # Normal intrinsic handling
            if push_count > 0:
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], intrinsic_name, params))


class ResourceRoutines(Instruction):
    """Resource management operations with various sub-commands."""
    
    def render(self, as_operand: bool = False) -> List[Token]:
        subop_name = get_subop_name(self.op_details.body.subop)
        return [TInstr(f"resource_routines.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Verify we have the expected body type
        assert isinstance(self.op_details.body, Scumm6Opcodes.ResourceRoutines), \
            f"Expected ResourceRoutines body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Handle case where subop is an int instead of enum
        intrinsic_name, unknown_subop = handle_unknown_subop_lift(il, subop, "resource_routines")
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        # If unknown subop, generate unimplemented instead of intrinsic
        if unknown_subop:
            # Generate unimplemented
            il.append(il.unimplemented())
            # Push dummy value if needed
            if push_count > 0:
                il.append(il.push(4, il.const(4, 0)))
        else:
            # Normal intrinsic handling
            if push_count > 0:
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], intrinsic_name, params))
