"""Special handling for script operations with variable arguments."""

from typing import List, Optional, Any
import copy
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction

from .opcodes import Instruction
from .smart_bases import SmartSemanticIntrinsicOp, SmartIntrinsicOp
from .configs import SemanticIntrinsicConfig, IntrinsicConfig


class StartScriptQuick(SmartSemanticIntrinsicOp):
    """StartScriptQuick with proper variable argument handling."""
    
    # Set class attributes that parent expects
    _name = "start_script_quick"
    _config: SemanticIntrinsicConfig  # Will be set by factory
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self._script_id: Optional[int] = None
        self._arg_count: Optional[int] = None
        
    def fuse(self, previous: Instruction) -> Optional['StartScriptQuick']:
        """
        Custom fusion for startScriptQuick that handles:
        1. Script ID
        2. Arg count 
        3. Variable number of arguments based on arg count
        
        Stack order (LIFO): script_id, arg1, arg2, ..., argN, arg_count
        Expected output: startScriptQuick(script_id, [arg1, arg2, ..., argN])
        """
        # If we don't have fused operands yet, we're looking for arg_count
        if not self.fused_operands:
            # First fusion should be arg_count
            if not self._is_fusible_push(previous):
                return None
                
            # Create initial fusion with arg_count
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous]
            fused._length = self._length + previous.length()
            
            # Extract arg_count
            if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                fused._arg_count = previous.op_details.body.data
            
            return fused
            
        # If we have the arg_count, collect arguments
        if self._arg_count is not None:
            # Calculate how many arguments we've collected so far
            # fused_operands[0] is arg_count, rest are arguments
            current_arg_count = len(self.fused_operands) - 1
            
            if current_arg_count < self._arg_count:
                # Still need more arguments
                if not self._is_fusible_push(previous):
                    return None
                    
                fused = copy.deepcopy(self)
                fused.fused_operands = [previous] + self.fused_operands
                fused._length = self._length + previous.length()
                fused._arg_count = self._arg_count  # Preserve arg count
                fused._script_id = self._script_id  # Preserve script id if set
                return fused
                
            elif current_arg_count == self._arg_count:
                # We have all arguments, now need script_id
                if not self._is_fusible_push(previous):
                    return None
                    
                fused = copy.deepcopy(self)
                fused.fused_operands = [previous] + self.fused_operands
                fused._length = self._length + previous.length()
                fused._arg_count = self._arg_count  # Preserve arg count
                
                # Extract script_id value
                if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                    fused._script_id = previous.op_details.body.data
                    
                return fused
        
        # No more fusion possible
        return None
        
    def render(self) -> List[Token]:
        """Render in descumm style: startScriptQuick(script_id, [args])"""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) >= self._arg_count + 2:
            # We have script_id, arg_count, and arguments
            # Order in fused_operands: script_id, arg1, arg2, ..., argN, arg_count
            tokens = [TInstr("startScriptQuick"), TSep("(")]
            
            # Script ID (first in fused_operands due to LIFO)
            script_id_op = self.fused_operands[0]
            tokens.extend(self._render_operand(script_id_op))
            tokens.append(TSep(", "))
            
            # Arguments as array
            tokens.append(TSep("["))
            # Arguments are from index 1 to self._arg_count (inclusive)
            # The last element is arg_count which we skip
            for i in range(1, self._arg_count + 1):
                if i > 1:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(self.fused_operands[i]))
            tokens.append(TSep("]"))
            
            tokens.append(TSep(")"))
            return tokens
        else:
            # Fallback to default rendering
            return super().render()
            
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for startScriptQuick with proper parameter handling."""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) >= self._arg_count + 2:
            # We have all parameters fused
            # Order in fused_operands: script_id, arg1, arg2, ..., argN, arg_count
            params = []
            
            # Script ID
            params.append(self._lift_operand(il, self.fused_operands[0]))
            
            # Variable arguments (from index 1 to self._arg_count)
            # Skip the arg_count - it's implicit in the number of arguments
            for i in range(1, self._arg_count + 1):
                params.append(self._lift_operand(il, self.fused_operands[i]))
                
            # Generate intrinsic call
            il.append(il.intrinsic([], "start_script_quick", params))
        else:
            # Fallback to default lifting
            super().lift(il, addr)


class StartScript(SmartSemanticIntrinsicOp):
    """StartScript with variable argument handling: startScript(script_id, flags, [args])"""
    
    # Set class attributes that parent expects
    _name = "start_script"
    _config: SemanticIntrinsicConfig  # Will be set by factory
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self._arg_count: Optional[int] = None
        
    def fuse(self, previous: Instruction) -> Optional['StartScript']:
        """
        Fusion pattern: script_id, flags, arg_count (then args...)
        Stack order (LIFO): script_id, flags, arg_count
        Output: startScript(script_id, flags, [])
        """
        # First fusion: arg_count
        if not self.fused_operands:
            if not self._is_fusible_push(previous):
                return None
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous]
            fused._length = self._length + previous.length()
            if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                fused._arg_count = previous.op_details.body.data
            return fused
            
        # Second fusion: flags
        elif len(self.fused_operands) == 1:
            if not self._is_fusible_push(previous):
                return None
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous] + self.fused_operands
            fused._length = self._length + previous.length()
            fused._arg_count = self._arg_count
            return fused
            
        # Third fusion: script_id
        elif len(self.fused_operands) == 2:
            if not self._is_fusible_push(previous):
                return None
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous] + self.fused_operands
            fused._length = self._length + previous.length()
            fused._arg_count = self._arg_count
            return fused
        
        return None
        
    def render(self) -> List[Token]:
        """Render as: startScript(script_id, flags, [])"""
        if self.fused_operands and len(self.fused_operands) >= 3:
            tokens = [TInstr("startScript"), TSep("(")]
            
            # script_id (first due to LIFO)
            tokens.extend(self._render_operand(self.fused_operands[0]))
            tokens.append(TSep(", "))
            
            # flags (second)
            tokens.extend(self._render_operand(self.fused_operands[1]))
            tokens.append(TSep(", "))
            
            # Empty array for now (no variable args implemented yet)
            tokens.append(TSep("[]"))
            
            tokens.append(TSep(")"))
            return tokens
        else:
            return super().render()
            
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL with script_id and flags."""
        if self.fused_operands and len(self.fused_operands) >= 3:
            params = [
                self._lift_operand(il, self.fused_operands[0]),  # script_id
                self._lift_operand(il, self.fused_operands[1]),  # flags
            ]
            il.append(il.intrinsic([], "start_script", params))
        else:
            super().lift(il, addr)


class SoundKludge(SmartIntrinsicOp):
    """SoundKludge with variable argument handling."""
    
    # Set class attributes that parent expects
    _name = "sound_kludge"
    _config: IntrinsicConfig  # Will be set by factory
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self._arg_count: Optional[int] = None
        
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused."""
        return instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(f"var_{operand.op_details.body.data}")]
            else:
                return [TInt("var_?")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
            else:
                return [TInt("?")]
        else:
            return [TInt("operand")]
    
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
        
    def fuse(self, previous: Instruction) -> Optional['SoundKludge']:
        """
        Custom fusion for soundKludge that handles variable arguments.
        
        Stack order (LIFO): arg1, arg2, ..., argN, arg_count
        Expected output: soundKludge([arg1, arg2, ..., argN])
        """
        # If we don't have fused operands yet, we're looking for arg_count
        if not self.fused_operands:
            # First fusion should be arg_count
            if not self._is_fusible_push(previous):
                return None
                
            # Create initial fusion with arg_count
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous]
            fused._length = self._length + previous.length()
            
            # Extract arg_count
            if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                fused._arg_count = previous.op_details.body.data
            
            return fused
            
        # We have arg_count, now collect the arguments
        if self._arg_count is not None and len(self.fused_operands) <= self._arg_count:
            if not self._is_fusible_push(previous):
                return None
                
            fused = copy.deepcopy(self)
            fused.fused_operands.append(previous)
            fused._length = self._length + previous.length()
            fused._arg_count = self._arg_count
            return fused
            
        # All fusions complete
        return None
        
    def render(self) -> List[Token]:
        """Render as: soundKludge([arg1, arg2, ...])"""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) > self._arg_count:
            tokens = [TInstr("soundKludge"), TSep("("), TSep("[")]
            
            # Arguments are in reverse order (stack is LIFO), skip the first one (arg_count)
            args = self.fused_operands[1:]
            for i, arg in enumerate(reversed(args)):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(arg))
            
            tokens.append(TSep("]"))
            tokens.append(TSep(")"))
            return tokens
        else:
            return super().render()
    
    @property 
    def stack_pop_count(self) -> int:
        """Calculate stack pops based on fusion state."""
        if self.fused_operands and self._arg_count is not None:
            # We've fused everything
            return 0
        return self._config.pop_count if self._config else 1
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for soundKludge."""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) > self._arg_count:
            # Create array of arguments (skip arg_count, reverse order)
            args = self.fused_operands[1:]
            params = [self._lift_operand(il, arg) for arg in reversed(args)]
            
            il.append(il.intrinsic([], "sound_kludge", params))
        else:
            super().lift(il, addr)
