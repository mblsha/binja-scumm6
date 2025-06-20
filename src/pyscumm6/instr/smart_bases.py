"""Smart base classes for generated instruction types."""

from typing import List
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP

from .opcodes import Instruction
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig)
from ...scumm6_opcodes import Scumm6Opcodes

class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation base class."""
    
    _name: str
    _config: IntrinsicConfig
    
    def render(self) -> List[Token]:
        return [TInstr(self._name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Handle special lift cases
        if self._config.special_lift:
            special_method = getattr(self, self._config.special_lift)
            special_method(il, addr)
            return
            
        # Handle UnknownOp case - generate double unimplemented
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            il.append(il.unimplemented())
            il.append(il.unimplemented())
            return
        
        # Standard intrinsic lift
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._name, params))
    
    def no_ret_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for instructions that don't return."""
        # Do standard lift first
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        il.append(il.intrinsic([], self._name, params))
        il.append(il.no_ret())
    
    def cutscene_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for cutscene with dynamic argument count."""
        # Custom logic for cutscene argument parsing
        if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
            pop_count = len(self.op_details.body.args)
        else:
            pop_count = 0
            
        params = [il.pop(4) for _ in range(pop_count)]
        il.append(il.intrinsic([], self._name, params))

class SmartVariableOp(Instruction):
    """Self-configuring variable operation base class."""
    
    _name: str
    _config: VariableConfig
    
    def render(self) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr(self._name),
            TSep("("),
            TInt(f"var_{var_id}"),
            TSep(")"),
        ]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ... import vars
        
        expected_type = (Scumm6Opcodes.ByteVarData if self._config.var_type == "byte" 
                        else Scumm6Opcodes.WordVarData)
        
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        if self._config.operation == "inc":
            current_value = vars.il_get_var(il, self.op_details.body)
            incremented_value = il.add(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, incremented_value))
        elif self._config.operation == "dec":
            current_value = vars.il_get_var(il, self.op_details.body)
            decremented_value = il.sub(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, decremented_value))

class SmartComplexOp(Instruction):
    """Unified complex operation handler."""
    
    _name: str
    _config: ComplexConfig
    
    def render(self) -> List[Token]:
        subop_name = self.op_details.body.subop.name
        return [TInstr(f"{self._name}.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Get the expected body type dynamically
        expected_type = getattr(Scumm6Opcodes, self._config.body_type_name)
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Construct intrinsic name
        intrinsic_name = f"{self._name}.{subop.name}"
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        if push_count > 0:
            il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        else:
            il.append(il.intrinsic([], intrinsic_name, params))

# Smart stack operation base classes
class SmartBinaryOp(Instruction):
    """Self-configuring binary stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b op a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))

class SmartUnaryOp(Instruction):
    """Self-configuring unary stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop one value
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))

        if self._name == "nott":
            # Special case for logical NOT - compare with zero
            comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
            il.append(il.push(4, comp_res))
        else:
            # Get the operation from the il object
            il_func = getattr(il, self._config.il_op_name)
            result = il_func(4, il.reg(4, LLIL_TEMP(0)))
            il.append(il.push(4, result))

class SmartComparisonOp(Instruction):
    """Self-configuring comparison stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the comparison operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b compare a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        comp_res = il_func(4, op1, op2)
        il.append(il.push(4, comp_res))

class SmartArrayOp(Instruction):
    """Self-configuring array operation."""
    
    _name: str
    _config: ArrayConfig
    
    def render(self) -> List[Token]:
        if hasattr(self.op_details.body, 'array'):
            array_id = self.op_details.body.array
            return [
                TInstr(self._name),
                TSep("("),
                TInt(f"array_{array_id}"),
                TSep(")"),
            ]
        else:
            return [TInstr(self._name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from binaryninja import IntrinsicName
        
        # Handle UnknownOp case for array inc/dec operations
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            # For inc/dec operations, use intrinsic calls like other array operations
            if self._config.operation in ["inc", "dec"]:
                from binaryninja import IntrinsicName
                
                # Array inc/dec operations pop array index and array ID from stack
                # Stack layout: [array_id, index] (index on top)
                # Generate intrinsic call similar to other array operations
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4), il.pop(4)]  # pop index, then array_id
                ))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
                return
            else:
                # For other UnknownOp cases, keep the original behavior
                il.append(il.unimplemented())
                il.append(il.unimplemented())
                return
        
        # Generate intrinsic call
        if self._config.operation == "read":
            if self._config.indexed:
                # Indexed read: pop index and base
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4), il.pop(4)]
                ))
            else:
                # Simple read: pop base only
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4)]
                ))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        elif self._config.operation == "write":
            if self._config.indexed:
                # Indexed write: pop value, index, base
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4), il.pop(4), il.pop(4)]
                ))
            else:
                # Simple write: pop value and base
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4), il.pop(4)]
                ))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))

class SmartSemanticIntrinsicOp(Instruction):
    """Self-configuring semantic intrinsic following descumm philosophy."""
    
    _name: str
    _config: SemanticIntrinsicConfig
    
    def render(self) -> List[Token]:
        """Render in descumm-style function call format."""
        return self._render_semantic_call()
    
    def _render_semantic_call(self) -> List[Token]:
        """Render as: semantic_name(param1, param2, ...)"""
        tokens = [TInstr(self._config.semantic_name), TSep("(")]
        
        # For variable args operations, show dynamic parameter count
        if self._config.variable_args:
            # Show script_id as first param, then variable args indicator
            if self._config.parameter_names:
                first_param = self._config.parameter_names[0]
                tokens.extend([TInstr(first_param)])
                if len(self._config.parameter_names) > 1:
                    tokens.extend([TSep(","), TSep(" "), TInstr("...")])
            else:
                tokens.append(TInstr("..."))
        else:
            # Show fixed parameters
            for i, param_name in enumerate(self._config.parameter_names):
                if i > 0:
                    tokens.extend([TSep(","), TSep(" ")])
                tokens.append(TInstr(param_name))
        
        tokens.append(TSep(")"))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL following descumm semantic approach."""
        # Handle variable arguments for script operations
        if self._config.variable_args:
            self._lift_variable_args_operation(il, addr)
        else:
            self._lift_fixed_args_operation(il, addr)
    
    def _lift_variable_args_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle operations with variable arguments (like start_script)."""
        # Extract variable arguments first (following original scumm6.py pattern)
        args = self._extract_variable_arguments(il)
        
        # Get the main parameters (script_id for script operations)
        script_id = il.pop(4)
        params = [script_id] + args
        
        # For start_script, also handle flags
        if self._name == "start_script":
            flags = il.pop(4)
            params = [script_id, flags] + args
        
        # Generate semantic intrinsic call
        il.append(il.intrinsic([], self._config.semantic_name, params))
        
        # Handle control flow implications if needed
        if self._config.control_flow_impact:
            self._handle_script_call_flow(il, script_id)
    
    def _lift_fixed_args_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle operations with fixed arguments."""
        # Standard intrinsic lift with semantic name
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._config.semantic_name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._config.semantic_name, params))
    
    def _extract_variable_arguments(self, il: LowLevelILFunction) -> List[int]:
        """Extract variable arguments from stack (following original implementation)."""
        # This is simplified - in real implementation, this would follow
        # the pattern from scumm6.py for extracting variable argument lists
        # For now, return empty list as placeholder
        return []
    
    def _handle_script_call_flow(self, il: LowLevelILFunction, script_id: int) -> None:
        """Handle control flow implications for script calls."""
        # In a full implementation, this would:
        # 1. Try to resolve script_id to actual address
        # 2. Generate appropriate call or jump instruction for CFG
        # 3. Handle the script context passing
        # For now, this is a placeholder
        pass
