"""Special handling for script operations with variable arguments."""

from typing import List, Optional, Any
from binja_test_mocks.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction

from .opcodes import Instruction
from .smart_bases import SmartVariableArgumentIntrinsic, get_variable_name
from .configs import SemanticIntrinsicConfig, IntrinsicConfig


class StartScriptQuick(SmartVariableArgumentIntrinsic):
    """startScriptQuick(script_id, [args...])"""

    _name = "start_script_quick"
    _config: SemanticIntrinsicConfig  # Will be set by factory

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self._script_id: Optional[int] = None

    def get_fixed_param_count(self) -> int:
        return 1

    @property
    def stack_pop_count(self) -> int:  # pragma: no cover - simple property
        if (
            self.fused_operands
            and self._arg_count is not None
            and len(self.fused_operands) >= self._arg_count + 2
        ):
            return 0
        return -1

    def render_instruction(self) -> List[Token]:
        if not (self.fused_operands and self._arg_count is not None):
            return [TInstr(f"{self.get_instruction_name()}()")]

        total_needed = self._arg_count + self.get_fixed_param_count() + 1
        if len(self.fused_operands) < total_needed:
            return [TInstr(f"{self.get_instruction_name()}()")]

        tokens = [TInstr("startScriptQuick"), TSep("(")]
        tokens.extend(self._render_operand(self.fused_operands[0]))
        tokens.append(TSep(", "))
        tokens.append(TSep("["))
        for i in range(1, self._arg_count + 1):
            if i > 1:
                tokens.append(TSep(", "))
            tokens.extend(self._render_operand(self.fused_operands[i]))
        tokens.append(TSep("]"))
        tokens.append(TSep(")"))
        return tokens

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for startScriptQuick with proper parameter handling."""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) >= self._arg_count + 2:
            # We have all parameters fused
            # Order in fused_operands: script_id, arg1, arg2, ..., argN, arg_count
            params = []
            
            # Script ID
            params.append(self._lift_operand(il, self.fused_operands[0]))
            
            # Extract script_id value for resolution
            if self.fused_operands[0].__class__.__name__ in ['PushByte', 'PushWord']:
                self._script_id = self.fused_operands[0].op_details.body.data
            
            # Add script address as second parameter
            script_address = self._resolve_script_address(il, addr)
            params.append(il.const(4, script_address))
            
            # Variable arguments (from index 1 to self._arg_count)
            # Skip the arg_count - it's implicit in the number of arguments
            for i in range(1, self._arg_count + 1):
                params.append(self._lift_operand(il, self.fused_operands[i]))
                
            # Generate intrinsic call
            il.append(il.intrinsic([], "start_script_quick", params))
        else:
            # Fallback to default lifting
            super().lift(il, addr)
            
    def _resolve_script_address(self, il: LowLevelILFunction, call_addr: int) -> int:
        """Resolve script ID to script address using container state."""
        if self._script_id is None:
            return 0  # Unknown script ID
            
        try:
            from ...scumm6 import LastBV
            from ...container import ContainerParser
            
            bv = LastBV.get()
            if bv and hasattr(bv, 'state'):
                script_addr = ContainerParser.get_script_ptr(bv.state, self._script_id, call_addr)
                if script_addr:
                    return script_addr
        except Exception:
            pass
            
        return 0  # Failed to resolve


class StartScript(SmartVariableArgumentIntrinsic):
    """startScript(script_id, flags, [args...])"""

    _name = "start_script"
    _config: SemanticIntrinsicConfig  # Will be set by factory

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self._script_id: Optional[int] = None

    def get_fixed_param_count(self) -> int:
        return 2

    @property
    def stack_pop_count(self) -> int:  # pragma: no cover - simple property
        if (
            self.fused_operands
            and self._arg_count is not None
            and len(self.fused_operands) >= self._arg_count + 3
        ):
            return 0
        return -1

    def render_instruction(self) -> List[Token]:
        if not (self.fused_operands and self._arg_count is not None):
            return [TInstr(f"{self.get_instruction_name()}()")]

        total_needed = self._arg_count + self.get_fixed_param_count() + 1
        if len(self.fused_operands) < total_needed:
            return [TInstr(f"{self.get_instruction_name()}()")]

        tokens = [TInstr("startScript"), TSep("(")]
        tokens.extend(self._render_operand(self.fused_operands[0]))
        tokens.append(TSep(", "))
        tokens.extend(self._render_operand(self.fused_operands[1]))
        tokens.append(TSep(", "))
        tokens.append(TSep("["))
        for i in range(2, 2 + self._arg_count):
            if i > 2:
                tokens.append(TSep(", "))
            tokens.extend(self._render_operand(self.fused_operands[i]))
        tokens.append(TSep("]"))
        tokens.append(TSep(")"))
        return tokens

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL with script_id, flags, and arguments."""
        if self.fused_operands and self._arg_count is not None and len(self.fused_operands) >= self._arg_count + 3:
            params = [
                self._lift_operand(il, self.fused_operands[0]),  # script_id
            ]
            
            # Extract script_id value for resolution
            if self.fused_operands[0].__class__.__name__ in ['PushByte', 'PushWord']:
                self._script_id = self.fused_operands[0].op_details.body.data
            
            # Add script address as second parameter
            script_address = self._resolve_script_address(il, addr)
            params.append(il.const(4, script_address))
            
            # Then flags
            params.append(self._lift_operand(il, self.fused_operands[1]))  # flags
            
            # Add variable arguments
            for i in range(2, 2 + self._arg_count):
                params.append(self._lift_operand(il, self.fused_operands[i]))
            
            il.append(il.intrinsic([], "start_script", params))
        else:
            super().lift(il, addr)
            
    def _resolve_script_address(self, il: LowLevelILFunction, call_addr: int) -> int:
        """Resolve script ID to script address using container state."""
        if self._script_id is None:
            return 0  # Unknown script ID
            
        try:
            from ...scumm6 import LastBV
            from ...container import ContainerParser
            
            bv = LastBV.get()
            if bv and hasattr(bv, 'state'):
                script_addr = ContainerParser.get_script_ptr(bv.state, self._script_id, call_addr)
                if script_addr:
                    return script_addr
        except Exception:
            pass
            
        return 0  # Failed to resolve


class StartObject(SmartVariableArgumentIntrinsic):
    """startObject(object_id, script, entrypoint, [args...])"""

    _name = "start_object"
    _config: SemanticIntrinsicConfig  # Will be set by factory

    def get_fixed_param_count(self) -> int:
        return 3

    def render_instruction(self) -> List[Token]:
        if not (self.fused_operands and self._arg_count is not None):
            return [TInstr(f"{self.get_instruction_name()}()")]

        total_needed = self._arg_count + self.get_fixed_param_count() + 1
        if len(self.fused_operands) < total_needed:
            return [TInstr(f"{self.get_instruction_name()}()")]

        tokens = [TInstr("startObject"), TSep("(")]

        # object_id
        tokens.extend(self._render_operand(self.fused_operands[0]))
        tokens.append(TSep(", "))

        # script parameter: render as localvar if variable push
        script_op = self.fused_operands[1]
        if script_op.__class__.__name__ in ["PushByteVar", "PushWordVar"] and hasattr(script_op.op_details.body, "data"):
            tokens.append(TInt(f"localvar{script_op.op_details.body.data}"))
        else:
            tokens.extend(self._render_operand(script_op))
        tokens.append(TSep(", "))

        # entrypoint
        tokens.extend(self._render_operand(self.fused_operands[2]))
        tokens.append(TSep(", "))

        tokens.append(TSep("["))
        for i in range(3, 3 + self._arg_count):
            if i > 3:
                tokens.append(TSep(", "))
            tokens.extend(self._render_operand(self.fused_operands[i]))
        tokens.append(TSep("]"))

        tokens.append(TSep(")"))
        return tokens


class SoundKludge(SmartVariableArgumentIntrinsic):
    """SoundKludge with variable argument handling."""
    
    # Set class attributes that parent expects
    _name = "sound_kludge"
    _config: IntrinsicConfig  # Will be set by factory
    
    def get_fixed_param_count(self) -> int:
        """SoundKludge has 0 fixed parameters: soundKludge([args...])."""
        return 0
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(operand.op_details.body, 'data'):
                var_id = operand.op_details.body.data
                # Handle signed byte interpretation for PushByteVar
                if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                    var_id = var_id + 256
                return [TInt(get_variable_name(var_id))]
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


class Cutscene(SmartVariableArgumentIntrinsic):
    """Cutscene with dynamic argument handling."""
    
    # Set class attributes that parent expects
    _name = "cutscene"
    _config: IntrinsicConfig  # Will be set by factory
    
    def get_fixed_param_count(self) -> int:
        """Cutscene has 0 fixed parameters: beginCutscene([args...])."""
        return 0


class IsAnyOf(SmartVariableArgumentIntrinsic):
    """IsAnyOf with variable argument handling for array parameters."""
    
    # Set class attributes that parent expects
    _name = "is_any_of"
    _config: IntrinsicConfig  # Will be set by factory
    
    def get_fixed_param_count(self) -> int:
        """IsAnyOf has 1 fixed parameter: test_value."""
        return 1
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately - use VAR_ format for isAnyOf."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # For isAnyOf, use VAR_ format to match descumm output
            from ... import vars
            var_num = operand.op_details.body.data
            var_mapping = vars.scumm_vars_inverse()
            if var_num in var_mapping:
                # Use full VAR_ name for descumm compatibility
                return [TInt(var_mapping[var_num])]
            else:
                # Fallback to var_N format for unknown variables
                return [TInt(f"var_{var_num}")]
        else:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(str(operand.op_details.body.data))]
            else:
                return [TInt("?")]
    
    def render_instruction(self) -> List[Token]:
        """Custom rendering for isAnyOf to remove spaces in array."""
        if not (self.fused_operands and self._arg_count is not None):
            return [TInstr(f"{self.get_instruction_name()}()")]
        
        total_needed = self._arg_count + self.get_fixed_param_count() + 1
        if len(self.fused_operands) < total_needed:
            return [TInstr(f"{self.get_instruction_name()}()")]
        
        tokens = [TInstr(self.get_instruction_name()), TSep("(")]
        
        # Test value (first parameter)
        tokens.extend(self._render_operand(self.fused_operands[0]))
        tokens.append(TSep(","))  # No space after comma for descumm compatibility
        
        # Comparison values as array
        tokens.append(TSep("["))
        for i in range(1, self._arg_count + 1):
            if i > 1:
                tokens.append(TSep(", "))  # No space after comma
            tokens.extend(self._render_operand(self.fused_operands[i]))
        tokens.append(TSep("]"))
        
        tokens.append(TSep(")"))
        return tokens
