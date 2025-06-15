"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes
from .opcodes import Instruction
from . import instructions

# This map is the core of the new dispatcher.
# The key is the enum value from the Kaitai-generated parser.
# The value is the Python class that handles that instruction.
OPCODE_MAP: Dict[Scumm6Opcodes.OpType, Type[Instruction]] = {
    Scumm6Opcodes.OpType.push_byte: instructions.PushByte,
    Scumm6Opcodes.OpType.push_word: instructions.PushWord,
    Scumm6Opcodes.OpType.push_byte_var: instructions.PushByteVar,
    Scumm6Opcodes.OpType.push_word_var: instructions.PushWordVar,
    Scumm6Opcodes.OpType.dup: instructions.Dup,
    Scumm6Opcodes.OpType.pop1: instructions.Pop1,
    Scumm6Opcodes.OpType.pop2: instructions.Pop2,
    Scumm6Opcodes.OpType.add: instructions.Add,
    Scumm6Opcodes.OpType.sub: instructions.Sub,
    Scumm6Opcodes.OpType.mul: instructions.Mul,
    Scumm6Opcodes.OpType.div: instructions.Div,
    Scumm6Opcodes.OpType.land: instructions.Land,
    Scumm6Opcodes.OpType.lor: instructions.Lor,
    Scumm6Opcodes.OpType.nott: instructions.Nott,
    Scumm6Opcodes.OpType.eq: instructions.Eq,
    Scumm6Opcodes.OpType.neq: instructions.Neq,
    Scumm6Opcodes.OpType.gt: instructions.Gt,
    Scumm6Opcodes.OpType.lt: instructions.Lt,
    Scumm6Opcodes.OpType.le: instructions.Le,
    Scumm6Opcodes.OpType.ge: instructions.Ge,
    Scumm6Opcodes.OpType.abs: instructions.Abs,
    Scumm6Opcodes.OpType.band: instructions.Band,
    Scumm6Opcodes.OpType.bor: instructions.Bor,
    Scumm6Opcodes.OpType.byte_var_inc: instructions.ByteVarInc,
    Scumm6Opcodes.OpType.word_var_inc: instructions.WordVarInc,
    Scumm6Opcodes.OpType.byte_var_dec: instructions.ByteVarDec,
    Scumm6Opcodes.OpType.word_var_dec: instructions.WordVarDec,
    Scumm6Opcodes.OpType.break_here: instructions.BreakHere,
    Scumm6Opcodes.OpType.dummy: instructions.Dummy,
    Scumm6Opcodes.OpType.get_random_number: instructions.GetRandomNumber,
    Scumm6Opcodes.OpType.get_random_number_range: instructions.GetRandomNumberRange,
    Scumm6Opcodes.OpType.pick_one_of: instructions.PickOneOf,
}