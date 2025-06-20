"""Smart base classes for generated instruction types."""

from typing import List, Optional
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
import copy

from .opcodes import Instruction
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig)
from ...scumm6_opcodes import Scumm6Opcodes

class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation base class."""
    
    _name: str
    _config: IntrinsicConfig

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self._config.special_lift == "cutscene_lift":
            if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
                return len(self.op_details.body.args)
            return 0
        return self._config.pop_count
    
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


class SmartFusibleIntrinsic(SmartIntrinsicOp):
    """Intrinsic operation that supports instruction fusion for function-call style rendering."""
    
    def fuse(self, previous: Instruction) -> Optional['SmartFusibleIntrinsic']:
        """Attempt to fuse with the previous instruction."""
        # Only fuse if we need more operands
        if len(self.fused_operands) >= self._config.pop_count:
            return None
        
        # Check if previous is a fusible push instruction
        if not self._is_fusible_push(previous):
            return None
        
        # Create a new fused instruction
        fused = copy.deepcopy(self)
        
        # Add the previous instruction to the front (stack is LIFO)
        fused.fused_operands.insert(0, previous)
        
        # Update length to include the fused instruction
        fused._length = self._length + previous.length()
        
        return fused
    
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused."""
        return instr.__class__.__name__ in [
            'PushByte', 'PushWord', 'PushByteVar', 'PushWordVar'
        ]
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        # If we have fused operands, we pop fewer from the stack
        if hasattr(self, 'fused_operands'):
            return max(0, self._config.pop_count - len(self.fused_operands))
        return super().stack_pop_count
    
    def render(self) -> List[Token]:
        """Render the instruction, showing fused operands if available."""
        if self.fused_operands:
            # Function-call style: draw_object(100, 200)
            tokens = [TInstr(self._name), TSep("(")]
            
            # Add operands in correct order (reverse of fusion order)
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            
            tokens.append(TSep(")"))
            return tokens
        else:
            # Normal rendering
            return super().render()
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        from binja_helpers.tokens import TInt, TText
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - extract var number
            if hasattr(operand.op_details.body, 'data'):
                var_num = operand.op_details.body.data
                return [TInt(f"var_{var_num}")]
        else:
            # Constant push - extract value
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
        
        # Fallback
        return [TText("?")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Lift the instruction, using fused operands if available."""
        if self.fused_operands:
            # Build parameters from fused operands
            params = []
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
            
            # Add any remaining stack pops if we don't have all operands fused
            remaining_pops = self._config.pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
            
            # Generate the intrinsic call
            if self._config.push_count > 0:
                outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
                il.append(il.intrinsic(outputs, IntrinsicName(self._name), params))
                for out_reg in outputs:
                    il.append(il.push(4, out_reg))
            else:
                il.append(il.intrinsic([], IntrinsicName(self._name), params))
        else:
            # Use parent implementation
            super().lift(il, addr)
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> any:
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


class SmartVariableOp(Instruction):
    """Self-configuring variable operation base class."""
    
    _name: str
    _config: VariableConfig

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return 0

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

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return getattr(self.op_details.body.body, "pop_count", 0)

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

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        # If we have fused operands, we need fewer stack pops
        return max(0, 2 - len(self.fused_operands))

    def fuse(self, previous: Instruction) -> Optional['SmartBinaryOp']:
        """
        Attempt to fuse with a previous push instruction.
        
        Args:
            previous: The previous instruction to potentially fuse with
            
        Returns:
            A new fused instruction if fusion is possible, None otherwise
        """
        # Only fuse if we need more operands
        if len(self.fused_operands) >= 2:
            return None
            
        # Check if previous is a fusible push instruction
        if not self._is_fusible_push(previous):
            return None
            
        # Create a new fused instruction by copying ourselves
        fused = copy.deepcopy(self)
        
        # Add the previous instruction to the front of fused operands
        # (since stack is LIFO, the most recent push becomes the first operand)
        fused.fused_operands.insert(0, previous)
        
        # Update length to include the fused instruction
        fused._length = self._length + previous.length()
        
        return fused
    
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if an instruction is a fusible push operation."""
        # Check for factory-generated push constants (they have specific class names)
        class_name = instr.__class__.__name__
        if class_name in ('PushByte', 'PushWord'):
            return True
            
        # Check for manual push variable instructions
        if class_name in ('PushByteVar', 'PushWordVar'):
            return True
            
        return False

    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        
        # If we have fused operands, render in function call style
        if self.fused_operands:
            tokens = [TInstr(display_name), TSep("(")]
            
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.extend([TSep(","), TSep(" ")])
                
                # Extract the value/name from the operand
                if hasattr(operand, 'op_details') and hasattr(operand.op_details, 'body'):
                    if operand.__class__.__name__ in ('PushByteVar', 'PushWordVar'):
                        # Variable (push_byte_var, push_word_var) 
                        var_id = operand.op_details.body.data
                        tokens.append(TInstr(f"var_{var_id}"))
                    elif hasattr(operand.op_details.body, 'data'):
                        # Constant value (push_byte, push_word)
                        tokens.append(TInt(str(operand.op_details.body.data)))
                    else:
                        # Fallback
                        tokens.append(TInstr("?"))
                else:
                    tokens.append(TInstr("?"))
            
            # If we still need stack operands, indicate with ellipsis
            remaining_ops = 2 - len(self.fused_operands)
            if remaining_ops > 0:
                if self.fused_operands:
                    tokens.extend([TSep(","), TSep(" ")])
                tokens.append(TInstr("..."))
                    
            tokens.append(TSep(")"))
            return tokens
        else:
            # Standard rendering
            return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Collect operands: use fused operands first, then pop from stack
        operands = []
        
        # Add fused operands (in order - first fused operand is first operand)
        for operand in self.fused_operands:
            if hasattr(operand, 'op_details') and hasattr(operand.op_details, 'body'):
                if hasattr(operand.op_details.body, 'data'):
                    # Constant value
                    operands.append(il.const(4, operand.op_details.body.data))
                elif operand.__class__.__name__ in ('PushByteVar', 'PushWordVar'):
                    # Variable - use the vars module
                    from ... import vars
                    operands.append(vars.il_get_var(il, operand.op_details.body))
                else:
                    # Fallback - treat as constant 0
                    operands.append(il.const(4, 0))
        
        # Pop remaining operands from stack
        remaining_pops = 2 - len(self.fused_operands)
        for i in range(remaining_pops):
            operands.append(il.pop(4))
        
        # Ensure we have exactly 2 operands
        if len(operands) != 2:
            # Fallback - use standard stack operations
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
            op1 = il.reg(4, LLIL_TEMP(1))
            op2 = il.reg(4, LLIL_TEMP(0))
        else:
            # Use our collected operands: operand[1] op operand[0] (reverse order for stack semantics)
            op1 = operands[1] if len(operands) > 1 else operands[0]
            op2 = operands[0]

        # Get the operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b op a
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))

class SmartUnaryOp(Instruction):
    """Self-configuring unary stack operation."""
    
    _name: str
    _config: StackConfig

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return 1

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

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return 2

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

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self._config.operation == "read":
            return 2 if self._config.indexed else 1
        elif self._config.operation == "write":
            return 3 if self._config.indexed else 2
        return 0

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

    @property
    def stack_pop_count(self) -> int:
        """
        The number of values this instruction expects to pop from the stack.
        For functions with variable arguments, this returns -1 to indicate
        the pop count is dynamic and depends on a value on the stack.
        """
        if self._config.variable_args:
            return -1
        return self._config.pop_count
    
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