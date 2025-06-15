"""Concrete SCUMM6 instruction implementations."""

from typing import List
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from ...scumm6_opcodes import Scumm6Opcodes

from .opcodes import Instruction

# Import the vars module to use the same LLIL generation logic
from ... import vars


class PushByte(Instruction):
    
    def render(self) -> List[Token]:
        value = self.op_details.body.data
        return [
            TInstr("push_byte"),
            TSep("("),
            TInt(str(value)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.ByteData), \
            f"Expected ByteData body, got {type(self.op_details.body)}"
        
        value = self.op_details.body.data
        il.append(il.push(4, il.const(4, value)))


class PushWord(Instruction):
    
    def render(self) -> List[Token]:
        value = self.op_details.body.data
        return [
            TInstr("push_word"),
            TSep("("),
            TInt(str(value)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.WordData), \
            f"Expected WordData body, got {type(self.op_details.body)}"
        
        value = self.op_details.body.data
        il.append(il.push(4, il.const(4, value)))


class PushByteVar(Instruction):
    
    def render(self) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr("push_byte_var"),
            TSep("("),
            TInt(f"var_{var_id}"),
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
    
    def render(self) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr("push_word_var"),
            TSep("("),
            TInt(f"var_{var_id}"),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.WordVarData), \
            f"Expected WordVarData body, got {type(self.op_details.body)}"
        
        il.append(il.push(4, vars.il_get_var(il, self.op_details.body)))


class Dup(Instruction):
    
    def render(self) -> List[Token]:
        return [TInstr("dup")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop value into temp register, then push it twice
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))


class Pop1(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("pop1")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.CallFuncPop1), \
            f"Expected CallFuncPop1 body, got {type(self.op_details.body)}"

        il.append(il.intrinsic([], "pop1", [il.pop(4)]))


class Pop2(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("pop2")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.CallFuncPop1), \
            f"Expected CallFuncPop1 body, got {type(self.op_details.body)}"

        # Despite the name "pop2", this instruction only pops 1 item (as per CallFuncPop1)
        il.append(il.intrinsic([], "pop2", [il.pop(4)]))


class Add(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("add")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b + a
        il.append(il.push(4, il.add(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Sub(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("sub")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b - a
        il.append(il.push(4, il.sub(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Mul(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("mul")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b * a
        il.append(il.push(4, il.mult(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Div(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("div")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b / a (signed division)
        il.append(il.push(4, il.div_signed(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Land(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("land")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b && a (logical AND)
        il.append(il.push(4, il.and_expr(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Lor(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("lor")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b || a (logical OR)
        il.append(il.push(4, il.or_expr(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))))


class Nott(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("nott")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop one value from stack and check if it equals 0 (logical NOT)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
        il.append(il.push(4, comp_res))


class Eq(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("eq")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b == a
        comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
        il.append(il.push(4, comp_res))


class Neq(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("neq")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b != a
        comp_res = il.compare_not_equal(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
        il.append(il.push(4, comp_res))


class Gt(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("gt")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b > a
        comp_res = il.compare_signed_greater_than(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
        il.append(il.push(4, comp_res))


class Lt(Instruction):

    def render(self) -> List[Token]:
        return [TInstr("lt")]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"

        # Pop two values from stack: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
        # Push result: b < a
        comp_res = il.compare_signed_less_than(4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
        il.append(il.push(4, comp_res))
