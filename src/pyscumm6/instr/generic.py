"""Generic lifters via factories and base classes for SCUMM6 instructions."""

from abc import abstractmethod
from typing import List, Type, Any, Optional
import copy
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from binaryninja.enums import BranchType
from binaryninja import InstructionInfo

from .opcodes import Instruction
from ...scumm6_opcodes import Scumm6Opcodes


def make_push_constant_instruction(
    name: str, 
    body_type: Type[Any], 
    size: int
) -> Type[Instruction]:
    """Factory to create a class for instructions that push a constant."""

    class PushConstant(Instruction):
        def render(self) -> List[Token]:
            value = self.op_details.body.data
            return [TInstr(name), TSep("("), TInt(str(value)), TSep(")")]

        def lift(self, il: LowLevelILFunction, addr: int) -> None:
            assert isinstance(self.op_details.body, body_type), \
                f"Expected {body_type.__name__} body, got {type(self.op_details.body)}"
            value = self.op_details.body.data
            # All stack operations in SCUMM6 seem to use 4-byte values
            il.append(il.push(4, il.const(4, value)))

    PushConstant.__name__ = name.title().replace("_", "")
    PushConstant.__qualname__ = name.title().replace("_", "")
    return PushConstant


def make_intrinsic_instruction(
    name: str,
    body_type: Type[Any],
    pop_count: int,
    push_count: int
) -> Type[Instruction]:
    """Factory to create a class for instructions that map to a simple intrinsic."""

    class IntrinsicInstruction(Instruction):
        @property
        def stack_pop_count(self) -> int:
            return pop_count

        def render(self) -> List[Token]:
            return [TInstr(name)]

        def lift(self, il: LowLevelILFunction, addr: int) -> None:
            assert isinstance(self.op_details.body, body_type), \
                f"Expected {body_type.__name__} body, got {type(self.op_details.body)}"

            params = [il.pop(4) for _ in range(pop_count)]
            
            if push_count > 0:
                outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(push_count)]
                il.append(il.intrinsic(outputs, name, params))
                for out_reg in outputs:
                    il.append(il.push(4, out_reg))
            else:
                il.append(il.intrinsic([], name, params))

    IntrinsicInstruction.__name__ = name.title().replace("_", "")
    IntrinsicInstruction.__qualname__ = name.title().replace("_", "")
    return IntrinsicInstruction


class BinaryStackOp(Instruction):
    """Base class for instructions that pop two values, operate, and push one."""

    @property
    @abstractmethod
    def il_op_name(self) -> str:
        """The name of the LowLevelILFunction method to call (e.g., 'add', 'sub')."""
        pass

    def render(self) -> List[Token]:
        # Map IL operation names to instruction display names
        name_map = {
            'add': 'add',
            'sub': 'sub', 
            'mult': 'mul',  # IL uses 'mult' but instruction is 'mul'
            'div_signed': 'div',
            'and_expr': 'land',  # IL uses 'and_expr' but instruction is 'land'
            'or_expr': 'lor'     # IL uses 'or_expr' but instruction is 'lor'
        }
        display_name = name_map.get(self.il_op_name, self.il_op_name)
        return [TInstr(display_name)]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the operation from the il object
        il_func = getattr(il, self.il_op_name)

        # Push result: b op a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))


class UnaryStackOp(Instruction):
    """Base class for instructions that pop one value, operate, and push one."""

    @property
    @abstractmethod
    def il_op_name(self) -> str:
        """The name of the LowLevelILFunction method to call."""
        pass

    @property
    def needs_comparison_with_zero(self) -> bool:
        """Whether this operation needs to compare with zero (for logical NOT)."""
        return False

    def render(self) -> List[Token]:
        # Map IL operation names to instruction display names
        name_map = {
            'nott': 'nott'  # Keep as is for logical NOT
        }
        display_name = name_map.get(self.il_op_name, self.il_op_name)
        return [TInstr(display_name)]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop one value
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))

        if self.needs_comparison_with_zero:
            # Special case for logical NOT - compare with zero
            comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
            il.append(il.push(4, comp_res))
        else:
            # Get the operation from the il object
            il_func = getattr(il, self.il_op_name)
            result = il_func(4, il.reg(4, LLIL_TEMP(0)))
            il.append(il.push(4, result))


class ComparisonStackOp(Instruction):
    """Base class for comparison instructions that pop two values and push a boolean result."""

    @property
    @abstractmethod
    def il_op_name(self) -> str:
        """The name of the LowLevelILFunction comparison method to call."""
        pass

    def render(self) -> List[Token]:
        # Map IL operation names to instruction display names
        name_map = {
            'compare_equal': 'eq',
            'compare_not_equal': 'neq',
            'compare_signed_greater_than': 'gt',
            'compare_signed_less_than': 'lt',
            'compare_signed_less_equal': 'le',
            'compare_signed_greater_equal': 'ge'
        }
        display_name = name_map.get(self.il_op_name, self.il_op_name)
        return [TInstr(display_name)]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the comparison operation from the il object
        il_func = getattr(il, self.il_op_name)

        # Push result: b compare a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        comp_res = il_func(4, op1, op2)
        il.append(il.push(4, comp_res))


class VariableWriteOp(Instruction):
    """Base class for instructions that pop a value and write it to a variable."""
    
    def fuse(self, previous: Instruction) -> Optional['VariableWriteOp']:
        """Attempt to fuse with the previous instruction."""
        # Only fuse if we need an operand
        if len(self.fused_operands) >= 1:
            return None
        
        # Check if previous is a fusible push instruction
        if not self._is_fusible_push(previous):
            return None
        
        # Create a new fused instruction
        fused = copy.deepcopy(self)
        
        # Add the previous instruction as our operand
        fused.fused_operands.append(previous)
        
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
        # If we have a fused operand, we don't pop from stack
        if hasattr(self, 'fused_operands') and self.fused_operands:
            return 0
        return 1
    
    @property
    @abstractmethod
    def instruction_name(self) -> str:
        """The name of this instruction for rendering."""
        pass
    
    @property
    @abstractmethod
    def expected_body_type(self) -> type:
        """The expected Kaitai struct body type."""
        pass
    
    def render(self) -> List[Token]:
        # Check for fusion first, before UnknownOp case
        if self.fused_operands:
            # For fused operands, we need to extract the variable ID
            if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
                # For write_byte_var which has a Kaitai mapping bug
                # Extract the variable ID directly from the raw bytecode
                var_id = self._extract_var_id_from_unknownop()
                tokens = []
                tokens.append(TInt(f"var_{var_id}"))
                tokens.append(TSep(" = "))
                tokens.extend(self._render_operand(self.fused_operands[0]))
                return tokens
            else:
                var_id = self.op_details.body.data
                # Show as assignment: var_10 = 5
                tokens = []
                tokens.append(TInt(f"var_{var_id}"))
                tokens.append(TSep(" = "))
                tokens.extend(self._render_operand(self.fused_operands[0]))
                return tokens
        
        # Handle potential UnknownOp case for write_byte_var due to Kaitai bug
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            # For write_byte_var which has a Kaitai mapping bug
            return [TInstr(self.instruction_name), TSep("("), TInstr("var_?"), TSep(")")]
        else:
            var_id = self.op_details.body.data
            # Normal stack-based rendering
            return [
                TInstr(self.instruction_name),
                TSep("("),
                TInt(f"var_{var_id}"),
                TSep(")"),
            ]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
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
        return [TInt("?")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ... import vars
        
        # Handle the case where write_byte_var has UnknownOp due to Kaitai bug
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            # This is a known bug in the Kaitai struct - write_byte_var falls through to UnknownOp
            # In the original implementation, trying to access body.type causes an AttributeError
            # and the method returns without adding any LLIL operations.
            # For compatibility, we need to match this behavior exactly.
            return
        else:
            # Normal case - proper variable write
            assert isinstance(self.op_details.body, self.expected_body_type), \
                f"Expected {self.expected_body_type.__name__} body, got {type(self.op_details.body)}"
            
            if self.fused_operands:
                # Direct assignment without stack pop
                value_expr = self._lift_operand(il, self.fused_operands[0])
                il.append(vars.il_set_var(il, self.op_details.body, value_expr))
            else:
                # Pop value from stack and write to variable
                value = il.pop(4)
                il.append(vars.il_set_var(il, self.op_details.body, value))
    
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

    def _extract_var_id_from_unknownop(self) -> str:
        """Extract variable ID from UnknownOp body (workaround for Kaitai bug)."""
        # For write_byte_var with UnknownOp, we can't reliably extract the var ID
        # This is a known Kaitai mapping issue
        return "?"


class ControlFlowOp(Instruction):
    """Base class for control flow instructions that need CFG analysis support."""
    
    def analyze(self, info: InstructionInfo, addr: int) -> None:
        """Analyze instruction for Control Flow Graph integration."""
        assert isinstance(self.op_details.body, Scumm6Opcodes.JumpData), \
            f"Expected JumpData body, got {type(self.op_details.body)}"
        
        # Set instruction length
        info.length = self._length
        
        # Calculate target address (relative to end of instruction)
        target_addr = addr + info.length + self.op_details.body.jump_offset
        
        # Add branches based on instruction type
        if self.is_conditional():
            # Only add TrueBranch (when jump is taken)
            # FalseBranch (fall-through) is implicit - execution continues to next instruction
            info.add_branch(BranchType.TrueBranch, target_addr)
        else:
            info.add_branch(BranchType.UnconditionalBranch, target_addr)
    
    @abstractmethod
    def is_conditional(self) -> bool:
        """Return True if this is a conditional branch, False for unconditional."""
        pass


class IntrinsicOp(Instruction):
    """Base class for complex engine instructions that map to intrinsic calls."""
    
    @property
    @abstractmethod  
    def intrinsic_name(self) -> str:
        """The name of the intrinsic to call."""
        pass
    
    @property
    def pop_count(self) -> int:
        """Number of arguments to pop from stack. Can be overridden for complex cases."""
        # Determine pop count from Kaitai type name
        body_type_name = type(self.op_details.body).__name__
        
        if 'Pop1' in body_type_name:
            return 1
        elif 'Pop2' in body_type_name:
            return 2
        elif 'Pop3' in body_type_name:
            return 3
        elif 'Pop4' in body_type_name:
            return 4
        elif 'UnknownOp' in body_type_name:
            # For UnknownOp, generate double unimplemented call
            return 0
        else:
            return 0
    
    @property
    def push_count(self) -> int:
        """Number of values to push to stack. Can be overridden for complex cases."""
        # Determine push count from Kaitai type name
        body_type_name = type(self.op_details.body).__name__
        
        if 'Push' in body_type_name:
            return 1
        else:
            return 0
    
    def render(self) -> List[Token]:
        """Default rendering just shows the intrinsic name."""
        return [TInstr(self.intrinsic_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate intrinsic call with appropriate parameter and return handling."""
        # Handle UnknownOp case - generate double unimplemented
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            il.append(il.unimplemented())
            il.append(il.unimplemented())
            return
        
        # Pop arguments from stack
        params = [il.pop(4) for _ in range(self.pop_count)]
        
        # Generate intrinsic call
        if self.push_count > 0:
            # Intrinsic with return value
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self.push_count)]
            il.append(il.intrinsic(outputs, self.intrinsic_name, params))
            # Push return values back to stack
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            # Intrinsic without return value
            il.append(il.intrinsic([], self.intrinsic_name, params))
