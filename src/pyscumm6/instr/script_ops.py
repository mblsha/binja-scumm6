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
        """
        # If we don't have fused operands yet, we're looking for arg_count and args
        if not self.fused_operands:
            # We need at least 2 operands (arg_count + at least one arg)
            if not self._is_fusible_push(previous):
                return None
                
            # Create initial fusion with first operand
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous]
            fused._length = self._length + previous.length()
            return fused
            
        # If we have some operands, check if we need more
        if len(self.fused_operands) == 1:
            # We have one operand, need the arg_count
            if not self._is_fusible_push(previous):
                return None
                
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous] + self.fused_operands
            fused._length = self._length + previous.length()
            
            # Extract arg_count value if it's a constant
            if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                fused._arg_count = previous.op_details.body.data
            
            return fused
            
        # Check if we need the script ID
        if len(self.fused_operands) == 2 and self._arg_count == 1:
            # We have arg_count and one arg, now need script_id
            if not self._is_fusible_push(previous):
                return None
                
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous] + self.fused_operands
            fused._length = self._length + previous.length()
            
            # Extract script_id value
            if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                fused._script_id = previous.op_details.body.data
                
            return fused
            
        # For now, don't handle more complex cases
        return None
        
    def render(self) -> List[Token]:
        """Render in descumm style: startScriptQuick(script_id, [args])"""
        if self.fused_operands and len(self.fused_operands) >= 3:
            # We have script_id, arg_count, and at least one arg
            tokens = [TInstr("startScriptQuick"), TSep("(")]
            
            # Script ID (first in fused_operands due to LIFO)
            script_id_op = self.fused_operands[0]
            tokens.extend(self._render_operand(script_id_op))
            tokens.append(TSep(", "))
            
            # Arguments as array
            tokens.append(TSep("["))
            # Skip arg_count (index 1), show actual args
            for i in range(2, len(self.fused_operands)):
                if i > 2:
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
        if self.fused_operands and len(self.fused_operands) >= 3:
            # We have all parameters fused
            # Parameters: script_id, arg_count, args...
            params = []
            
            # Script ID
            params.append(self._lift_operand(il, self.fused_operands[0]))
            
            # Arg count
            params.append(self._lift_operand(il, self.fused_operands[1]))
            
            # Variable arguments
            for i in range(2, len(self.fused_operands)):
                params.append(self._lift_operand(il, self.fused_operands[i]))
                
            # Generate intrinsic call
            il.append(il.intrinsic([], "start_script_quick", params))
        else:
            # Fallback to default lifting
            super().lift(il, addr)