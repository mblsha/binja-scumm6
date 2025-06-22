"""Special handling for script operations with variable arguments."""

from typing import List, Optional, Any
import copy
from binja_helpers.tokens import Token, TInstr, TSep
from binaryninja.lowlevelil import LowLevelILFunction

from .opcodes import Instruction
from .smart_bases import SmartSemanticIntrinsicOp
from .configs import SemanticIntrinsicConfig


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
