"""Concrete SCUMM6 instruction implementations."""

from typing import List
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction
from ...scumm6_opcodes import Scumm6Opcodes

from .opcodes import Instruction


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
        value = self.op_details.body.data
        return [
            TInstr("push_byte_var"),
            TSep("("),
            TInt(str(value)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.ByteData), \
            f"Expected ByteData body, got {type(self.op_details.body)}"

        from ... import vars as scumm_vars

        var_num = self.op_details.body.data
        il.append(
            il.push(
                4,
                il.load(
                    scumm_vars.VAR_ITEM_SIZE,
                    il.const_pointer(4, scumm_vars.get_scumm_var(var_num).address),
                ),
            )
        )
