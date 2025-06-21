"""Smart base classes for generated instruction types."""

from typing import List, Optional, Any, NamedTuple, cast
from binja_helpers.tokens import Token, TInstr, TSep, TInt, TText
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP, LowLevelILLabel
from binaryninja import IntrinsicName
import copy

from .opcodes import Instruction
from .generic import ControlFlowOp
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
            tokens: List[Token] = [TInstr(self._name), TSep("(")]
            
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
                data = operand.op_details.body.data
                return [TInt(f"var_{data}")]
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
        subop = self.op_details.body.subop
        
        # Ensure subop is an enum member, not an int
        if isinstance(subop, int):
            from ...scumm6_opcodes import Scumm6Opcodes
            try:
                subop = Scumm6Opcodes.SubopType(subop)
            except ValueError:
                # Handle cases where the int value is not a valid enum member
                return [TInstr(f"{self._name}.unknown_{subop}")]
        
        subop_name = subop.name
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
        
        # Ensure subop is an enum member, not an int
        if isinstance(subop, int):
            try:
                subop = Scumm6Opcodes.SubopType(subop)
            except ValueError:
                # Handle cases where the int value is not a valid enum member
                il.append(il.unimplemented())
                return
        
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
    
    def produces_result(self) -> bool:
        """Binary operations produce results that can be consumed by other instructions."""
        return True

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
        """Check if an instruction is a fusible push operation or produces a consumable result."""
        # Check for factory-generated push constants (they have specific class names)
        class_name = instr.__class__.__name__
        if class_name in ('PushByte', 'PushWord'):
            return True
            
        # Check for manual push variable instructions
        if class_name in ('PushByteVar', 'PushWordVar'):
            return True
        
        # Check if instruction produces a result that can be consumed
        # This enables multi-level expression building
        if instr.produces_result():
            return True
            
        return False
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(f"var_{operand.op_details.body.data}")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression
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
            # This is a result-producing instruction - we need to generate its IL
            # For now, use a placeholder. In a real implementation, we would
            # need to execute the instruction's lift method and capture its result
            # This is complex and might require significant architectural changes
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Fallback

    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        
        # If we have fused operands, render in function call style
        if self.fused_operands:
            tokens: List[Token] = [TInstr(display_name), TSep("(")]
            
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.extend([TSep(","), TSep(" ")])
                
                # Use the helper method to render the operand
                tokens.extend(self._render_operand(operand))
            
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

class SmartConditionalJump(ControlFlowOp):
    """Smart conditional jump that supports fusion with comparison operations."""
    
    _name: str
    _is_if_not: bool  # True for if_not, False for iff
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self.fused_operands: List['Instruction'] = []
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        else:
            return 1  # Normal conditional jump pops condition from stack
    
    def is_conditional(self) -> bool:
        return True
    
    def fuse(self, previous: Instruction) -> Optional['SmartConditionalJump']:
        """Attempt to fuse with a comparison operation or simple push."""
        # Only fuse if we don't already have operands
        if self.fused_operands:
            return None
            
        # Check if previous is a comparison operation or simple push
        if not (self._is_comparison_op(previous) or self._is_simple_push(previous)):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused
    
    def _is_comparison_op(self, instr: Instruction) -> bool:
        """Check if instruction is a comparison operation that can be fused."""
        comparison_ops = ['Eq', 'Neq', 'Gt', 'Lt', 'Le', 'Ge']
        return instr.__class__.__name__ in comparison_ops
    
    def _is_simple_push(self, instr: Instruction) -> bool:
        """Check if instruction is a simple push that can be fused for loop conditions."""
        simple_push_ops = ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']
        return instr.__class__.__name__ in simple_push_ops
    
    def _render_condition(self, condition_instr: Instruction) -> List[Token]:
        """Render a fused condition (comparison or simple push) as readable condition."""
        # Check if this is a comparison with fused operands
        if hasattr(condition_instr, 'fused_operands') and len(condition_instr.fused_operands) >= 2:
            # Get operands (in reverse order due to stack semantics)
            left_operand = condition_instr.fused_operands[1]
            right_operand = condition_instr.fused_operands[0]
            
            tokens: List[Token] = []
            tokens.extend(self._render_operand(left_operand))
            
            # Get comparison operator and potentially invert it
            op_name = condition_instr.__class__.__name__.lower()
            if self._is_if_not:
                # Invert the comparison for readability
                inverted_ops = {'eq': '!=', 'neq': '==', 'gt': '<=', 'lt': '>=', 'le': '>', 'ge': '<'}
                op_symbol = inverted_ops.get(op_name, f"!{op_name}")
            else:
                # Use normal comparison
                normal_ops = {'eq': '==', 'neq': '!=', 'gt': '>', 'lt': '<', 'le': '<=', 'ge': '>='}
                op_symbol = normal_ops.get(op_name, op_name)
            
            tokens.append(TText(f" {op_symbol} "))
            tokens.extend(self._render_operand(right_operand))
            
            return tokens
        
        # Check if this is a simple push (for simple truthiness test)
        elif condition_instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            tokens = []
            if self._is_if_not:
                tokens.append(TText("!"))
            tokens.extend(self._render_operand(condition_instr))
            return tokens
        
        # Fallback for unknown condition types
        else:
            return [TText("condition")]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(f"var_{operand.op_details.body.data}")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        else:
            return [TText("operand")]
    
    def render(self) -> List[Token]:
        if self.fused_operands:
            # Render as readable conditional
            tokens: List[Token] = []
            if self._is_if_not:
                tokens.append(TInstr("if "))
            else:
                tokens.append(TInstr("if "))
            
            tokens.extend(self._render_condition(self.fused_operands[0]))
            
            # Add jump target
            jump_offset = self.op_details.body.jump_offset
            if jump_offset >= 0:
                tokens.append(TText(f" goto +{jump_offset}"))
            else:
                tokens.append(TText(f" goto {jump_offset}"))
            
            return tokens
        else:
            # Normal rendering
            jump_offset = self.op_details.body.jump_offset
            if self._is_if_not:
                instr_name = "unless"
            else:
                instr_name = "if"
            
            if jump_offset == 0:
                # Handle zero offset as 'self'
                return [TInstr(instr_name), TText(" "), TInstr("goto"), TText(" "), TInstr("self")]
            elif jump_offset > 0:
                return [TInstr(f"{instr_name} goto +{jump_offset}")]
            else:
                return [TInstr(f"{instr_name} goto {jump_offset}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        jump_offset = self.op_details.body.jump_offset
        target_addr = addr + self.length() + jump_offset
        
        if self.fused_operands:
            # Generate IL for fused comparison
            comparison = self.fused_operands[0]
            if hasattr(comparison, 'fused_operands') and len(comparison.fused_operands) >= 2:
                # Get operands (reverse order for stack semantics)
                left_operand = comparison.fused_operands[1]
                right_operand = comparison.fused_operands[0]
                
                left_expr = self._lift_operand(il, left_operand)
                right_expr = self._lift_operand(il, right_operand)
                
                # Get comparison operation
                op_name = comparison.__class__.__name__.lower()
                comparison_ops = {
                    'eq': 'compare_equal',
                    'neq': 'compare_not_equal', 
                    'gt': 'compare_signed_greater_than',
                    'lt': 'compare_signed_less_than',
                    'le': 'compare_signed_less_equal',
                    'ge': 'compare_signed_greater_equal'
                }
                
                il_op_name = comparison_ops.get(op_name, 'compare_equal')
                il_func = getattr(il, il_op_name)
                condition = il_func(4, left_expr, right_expr)
                
                # Apply if_not logic if needed
                if self._is_if_not:
                    condition = il.compare_equal(4, condition, il.const(4, 0))
                else:
                    condition = il.compare_not_equal(4, condition, il.const(4, 0))
                
                # Generate conditional jump
                true_label = il.get_label_for_address(il.arch, target_addr)
                false_label = LowLevelILLabel()
                
                # Generate conditional jump with the obtained label
                il.append(il.if_expr(condition, true_label, false_label))
                il.mark_label(false_label) 
            else:
                # Fallback to normal stack-based lifting
                self._lift_normal(il, addr)
        else:
            # Normal stack-based lifting
            self._lift_normal(il, addr)
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        else:
            return il.const(4, 0)  # Fallback
    
    def _lift_normal(self, il: LowLevelILFunction, addr: int) -> None:
        """Normal stack-based lifting for unfused conditionals."""
        jump_offset = self.op_details.body.jump_offset
        target_addr = addr + self.length() + jump_offset
        
        # Pop condition from stack
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        
        if self._is_if_not:
            condition = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
        else:
            condition = il.compare_not_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
        
        true_label = il.get_label_for_address(il.arch, target_addr)
        false_label = LowLevelILLabel()
        
        # Generate conditional jump with the obtained label
        il.append(il.if_expr(condition, true_label, false_label))
        il.mark_label(false_label)

class SmartComparisonOp(Instruction):
    """Self-configuring comparison stack operation with fusion support."""
    
    _name: str
    _config: StackConfig

    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self.fused_operands: List['Instruction'] = []

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        else:
            return 2  # Normal comparison pops two values
    
    def produces_result(self) -> bool:
        """Comparison operations produce results that can be consumed by other instructions."""
        return True

    def fuse(self, previous: Instruction) -> Optional['SmartComparisonOp']:
        """Attempt to fuse with a push instruction."""
        # Only fuse if we need more operands (max 2 for binary comparison)
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

    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused or produces a consumable result."""
        # Check for basic push instructions
        if instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            return True
        
        # Check if instruction produces a result that can be consumed
        # This enables multi-level expression building
        if instr.produces_result():
            return True
            
        return False

    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(f"var_{operand.op_details.body.data}")]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression
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
            # This is a result-producing instruction - placeholder for now
            # Proper implementation would require significant architectural changes
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Fallback

    def render(self) -> List[Token]:
        if self.fused_operands and len(self.fused_operands) == 2:
            # Render as comparison with operands: left op right
            tokens: List[Token] = []
            
            # Get operands (in reverse order due to stack semantics)
            left_operand = self.fused_operands[1]
            right_operand = self.fused_operands[0]
            
            # Get comparison symbol
            op_symbols = {'eq': '==', 'neq': '!=', 'gt': '>', 'lt': '<', 'le': '<=', 'ge': '>='}
            op_symbol = op_symbols.get(self._name, self._name)
            
            tokens.extend(self._render_operand(left_operand))
            tokens.append(TText(f" {op_symbol} "))
            tokens.extend(self._render_operand(right_operand))
            
            return tokens
        elif self.fused_operands and len(self.fused_operands) == 1:
            # Partially fused - function-call style
            tokens_partial: List[Token] = []
            display_name = self._config.display_name or self._name
            tokens_partial.append(TInstr(f"{display_name}("))
            tokens_partial.extend(self._render_operand(self.fused_operands[0]))
            tokens_partial.append(TText(")"))
            return tokens_partial
        else:
            # Normal rendering
            display_name = self._config.display_name or self._name
            return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        if self.fused_operands and len(self.fused_operands) == 2:
            # Fused comparison - use direct operands
            left_operand = self.fused_operands[1]  # Reverse order for stack semantics
            right_operand = self.fused_operands[0]
            
            left_expr = self._lift_operand(il, left_operand)
            right_expr = self._lift_operand(il, right_operand)
            
            # Get the comparison operation from the il object
            il_func = getattr(il, self._config.il_op_name)
            comp_res = il_func(4, left_expr, right_expr)
            il.append(il.push(4, comp_res))
        else:
            # Normal stack-based lifting
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

    def fuse(self, previous: Instruction) -> Optional['SmartArrayOp']:
        """Attempt to fuse with the previous instruction."""
        if self._config.operation != "write":
            return None  # Only support fusion for write operations
        
        # Determine how many operands we need
        expected_operands = 3 if self._config.indexed else 2
        
        # Only fuse if we need more operands
        if len(self.fused_operands) >= expected_operands:
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
        if self._config.operation == "read":
            return 2 if self._config.indexed else 1
        elif self._config.operation == "write":
            base_count = 3 if self._config.indexed else 2
            # If we have fused operands, we pop fewer from the stack
            if hasattr(self, 'fused_operands'):
                return max(0, base_count - len(self.fused_operands))
            return base_count
        return 0

    def render(self) -> List[Token]:
        if hasattr(self.op_details.body, 'array'):
            array_id = self.op_details.body.array
            
            # Check for fusion in write operations
            if self._config.operation == "write" and self.fused_operands:
                # Render as array assignment: array_5[3] = 10
                tokens: List[Token] = []
                tokens.append(TInt(f"array_{array_id}"))
                tokens.append(TSep("["))
                
                # Handle operand order for array operations
                # For non-indexed: [value, index] → array[index] = value
                # For indexed: [value, index, base] → array[base + index] = value
                
                if len(self.fused_operands) >= 2:
                    # We have both index and value
                    if self._config.indexed and len(self.fused_operands) >= 3:
                        # array[base + index] = value
                        tokens.extend(self._render_operand(self.fused_operands[2]))  # base
                        tokens.append(TSep(" + "))
                        tokens.extend(self._render_operand(self.fused_operands[1]))  # index
                    else:
                        # array[index] = value
                        tokens.extend(self._render_operand(self.fused_operands[1]))  # index
                    
                    tokens.append(TSep("] = "))
                    tokens.extend(self._render_operand(self.fused_operands[0]))  # value
                    return tokens
                elif len(self.fused_operands) == 1:
                    # Partial fusion - might be just the value or just the index
                    tokens.append(TSep("?, "))
                    tokens.extend(self._render_operand(self.fused_operands[0]))
                    tokens.append(TSep("]"))
                    return tokens
            
            # Normal rendering
            return [
                TInstr(self._name),
                TSep("("),
                TInt(f"array_{array_id}"),
                TSep(")"),
            ]
        else:
            return [TInstr(self._name)]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        from binja_helpers.tokens import TInt, TText
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - extract var number
            if hasattr(operand.op_details.body, 'data'):
                data = operand.op_details.body.data
                return [TInt(f"var_{data}")]
        else:
            # Constant push - extract value
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
        
        # Fallback
        return [TText("?")]
    
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
            if self.fused_operands:
                # Build parameters from fused operands
                params = []
                for operand in self.fused_operands:
                    params.append(self._lift_operand(il, operand))
                
                # Add any remaining stack pops
                expected_operands = 3 if self._config.indexed else 2
                remaining_pops = expected_operands - len(self.fused_operands)
                for _ in range(remaining_pops):
                    params.append(il.pop(4))
                
                # Generate the intrinsic call
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    params
                ))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                # Original behavior
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
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - use il_get_var
            from ... import vars
            return vars.il_get_var(il, operand.op_details.body)
        else:
            # Constant push - use const
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return il.const(4, value)
        
        # Fallback to undefined
        return il.undefined()

class SmartSemanticIntrinsicOp(SmartFusibleIntrinsic):
    """Self-configuring semantic intrinsic following descumm philosophy with fusion support."""
    
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
        
        # If we have fused operands, we pop fewer from the stack
        if hasattr(self, 'fused_operands') and self.fused_operands:
            return max(0, self._config.pop_count - len(self.fused_operands))
        
        return self._config.pop_count
    
    def render(self) -> List[Token]:
        """Render in descumm-style function call format."""
        if self.fused_operands:
            return self._render_fused_semantic_call()
        else:
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
    
    def _render_fused_semantic_call(self) -> List[Token]:
        """Render semantic function call with fused operands."""
        tokens = [TInstr(self._config.semantic_name), TSep("(")]
        
        # Add fused operands as actual parameters
        for i, operand in enumerate(self.fused_operands):
            if i > 0:
                tokens.append(TSep(", "))
            tokens.extend(self._render_operand(operand))
        
        tokens.append(TSep(")"))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL following descumm semantic approach."""
        if self.fused_operands:
            self._lift_fused_operation(il, addr)
        elif self._config.variable_args:
            self._lift_variable_args_operation(il, addr)
        else:
            self._lift_fixed_args_operation(il, addr)
    
    def _lift_fused_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle LLIL generation for fused semantic operations."""
        # Build parameters from fused operands
        params = []
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add any remaining stack pops if we don't have all operands fused
        if not self._config.variable_args:
            remaining_pops = self._config.pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
        
        # Generate the semantic intrinsic call
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._config.semantic_name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._config.semantic_name, params))
    
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


# ============================================================================
# Loop Pattern Recognition System
# ============================================================================

class LoopInfo(NamedTuple):
    """Information about a detected loop pattern."""
    loop_type: str          # "while", "for", "do_while"
    body_start: int         # Start address of loop body
    body_end: int           # End address of loop body  
    condition: Optional['Instruction']  # Loop condition instruction
    iterator_var: Optional[int]         # Variable number if it's a counter loop
    increment_amount: Optional[int]     # Increment amount for counter loops


class SmartLoopDetector:
    """Advanced loop pattern detection for SCUMM6 bytecode."""
    
    @staticmethod
    def detect_loop_pattern(
        conditional_jump: 'SmartConditionalJump', 
        address: int
    ) -> Optional[LoopInfo]:
        """
        Detect if a conditional jump represents a loop pattern.
        
        Args:
            conditional_jump: The conditional jump instruction to analyze
            address: Current address of the instruction
            
        Returns:
            LoopInfo if a loop pattern is detected, None otherwise
        """
        jump_offset = conditional_jump.op_details.body.jump_offset
        
        # Check for backward jump (loop indicator)
        if jump_offset >= 0:
            return None  # Forward jumps are not loops
            
        # Calculate loop boundaries
        loop_start = address + conditional_jump.length() + jump_offset
        loop_end = address
        
        # Analyze the condition for loop type detection
        if conditional_jump.fused_operands:
            condition = conditional_jump.fused_operands[0]
            loop_type = SmartLoopDetector._analyze_condition_type(condition)
            iterator_var = SmartLoopDetector._detect_iterator_variable(condition)
        else:
            condition = None
            loop_type = "while"  # Default for unfused conditions
            iterator_var = None
            
        return LoopInfo(
            loop_type=loop_type,
            body_start=loop_start,
            body_end=loop_end,
            condition=condition,
            iterator_var=iterator_var,
            increment_amount=None  # TODO: Detect increment patterns
        )
    
    @staticmethod
    def _analyze_condition_type(condition: 'Instruction') -> str:
        """Analyze the condition to determine likely loop type."""
        if not hasattr(condition, 'fused_operands') or len(condition.fused_operands) < 2:
            return "while"
            
        # Check for counter-style conditions (var < constant)
        left_operand = condition.fused_operands[1]  # Due to stack order
        right_operand = condition.fused_operands[0]
        
        # If comparing variable to constant (either order), likely a for-loop
        var_const_comparison = (
            (left_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar'] and
             right_operand.__class__.__name__ in ['PushByte', 'PushWord']) or
            (left_operand.__class__.__name__ in ['PushByte', 'PushWord'] and
             right_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar'])
        )
        
        if var_const_comparison:
            if condition.__class__.__name__.lower() in ['lt', 'le', 'gt', 'ge']:
                return "for"
                
        return "while"
    
    @staticmethod
    def _detect_iterator_variable(condition: 'Instruction') -> Optional[int]:
        """Detect if a variable is being used as a loop iterator."""
        if not hasattr(condition, 'fused_operands') or len(condition.fused_operands) < 2:
            return None
            
        left_operand = condition.fused_operands[1]
        right_operand = condition.fused_operands[0]
        
        # Check if left operand is a variable push
        if left_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(left_operand.op_details.body, 'data'):
                return cast(int, left_operand.op_details.body.data)
        
        # Check if right operand is a variable push (reversed order case)
        elif right_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(right_operand.op_details.body, 'data'):
                return cast(int, right_operand.op_details.body.data)
                
        return None


class SmartLoopConditionalJump(SmartConditionalJump):
    """Enhanced conditional jump with loop pattern recognition."""
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self.detected_loop: Optional[LoopInfo] = None
    
    def detect_and_fuse_loop(self, address: int) -> bool:
        """
        Detect if this conditional jump represents a loop pattern.
        
        Args:
            address: Current instruction address
            
        Returns:
            True if a loop pattern was detected and fused
        """
        self.detected_loop = SmartLoopDetector.detect_loop_pattern(self, address)
        return self.detected_loop is not None
    
    def render(self) -> List[Token]:
        """Enhanced rendering that shows loop patterns when detected."""
        if self.detected_loop:
            return self._render_loop_pattern()
        else:
            return super().render()
    
    def _render_loop_pattern(self) -> List[Token]:
        """Render the instruction as a loop construct."""
        assert self.detected_loop is not None
        
        tokens: List[Token] = []
        loop_info = self.detected_loop
        
        if loop_info.loop_type == "for" and loop_info.iterator_var is not None:
            # Render as for-loop style
            tokens.append(TInstr("for"))
            tokens.append(TText(" (var_"))
            tokens.append(TInt(str(loop_info.iterator_var)))
            
            if loop_info.condition:
                # Add condition rendering
                condition_tokens = loop_info.condition.render()
                if condition_tokens:
                    tokens.append(TText("; "))
                    tokens.extend(condition_tokens)
            
            tokens.append(TText(") {"))
            
        else:
            # Render as while-loop style
            tokens.append(TInstr("while"))
            tokens.append(TText(" ("))
            
            if self.fused_operands and self.fused_operands[0]:
                # Render the fused condition
                condition_tokens = self._render_condition(self.fused_operands[0])
                tokens.extend(condition_tokens)
            else:
                tokens.append(TText("condition"))
            
            tokens.append(TText(") {"))
        
        # Add loop body information as comment
        body_size = loop_info.body_end - loop_info.body_start
        tokens.append(TText(f" # {body_size} bytes"))
        
        return tokens


# Enhanced conditional jump classes with loop detection
class SmartLoopIfNot(SmartLoopConditionalJump):
    """If-not conditional jump with loop pattern recognition."""
    _is_if_not = True


class SmartLoopIff(SmartLoopConditionalJump):
    """If conditional jump with loop pattern recognition."""
    _is_if_not = False