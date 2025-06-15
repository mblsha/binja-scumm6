"""Generic lifters via factories and base classes for SCUMM6 instructions."""

from abc import abstractmethod
from typing import List, Type, Any
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP

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
