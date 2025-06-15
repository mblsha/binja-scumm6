"""Concrete SCUMM6 instruction implementations."""

from typing import List
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction

from .opcodes import Instruction


class PushByte(Instruction):
    """
    Wraps the Kaitai-parsed 'push_byte' operation.
    Opcode: 0x00
    """
    
    def render(self) -> List[Token]:
        """
        Generates the disassembly text tokens for this instruction.
        Example: push_byte(18)
        """
        # self.op_details is the Kaitai object for the entire instruction
        # self.op_details.body is the specific part for this opcode type
        value = self.op_details.body.data
        return [
            TInstr("push_byte"),
            TSep("("),
            TInt(str(value)),
            TSep(")"),
        ]

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """
        Lifts the instruction to Low-Level IL.
        This logic is moved directly from scumm6.py
        """
        value = self.op_details.body.data
        # SCUMM6 uses a 32-bit (4-byte) stack
        il.append(il.push(4, il.const(4, value)))

# You can add more classes here as you migrate them...
# class Add(Instruction): ...