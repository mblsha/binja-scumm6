"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes
from .opcodes import Instruction
from . import instructions
from .generic import make_push_constant_instruction, make_intrinsic_instruction

# This map is the core of the new dispatcher.
# The key is the enum value from the Kaitai-generated parser.
# The value is the Python class that handles that instruction.
OPCODE_MAP: Dict[Scumm6Opcodes.OpType, Type[Instruction]] = {
    # --- Using Factories ---
    Scumm6Opcodes.OpType.push_byte: make_push_constant_instruction(
        "push_byte", Scumm6Opcodes.ByteData, 4
    ),
    Scumm6Opcodes.OpType.push_word: make_push_constant_instruction(
        "push_word", Scumm6Opcodes.WordData, 4
    ),
    Scumm6Opcodes.OpType.abs: make_intrinsic_instruction(
        "abs", Scumm6Opcodes.CallFuncPop1Push, pop_count=1, push_count=1
    ),
    Scumm6Opcodes.OpType.break_here: make_intrinsic_instruction(
        "break_here", Scumm6Opcodes.NoData, pop_count=0, push_count=0
    ),
    Scumm6Opcodes.OpType.pop1: make_intrinsic_instruction(
        "pop1", Scumm6Opcodes.CallFuncPop1, pop_count=1, push_count=0
    ),
    # pop2 also has a CallFuncPop1 body
    Scumm6Opcodes.OpType.pop2: make_intrinsic_instruction(
        "pop2", Scumm6Opcodes.CallFuncPop1, pop_count=1, push_count=0
    ),
    Scumm6Opcodes.OpType.get_random_number: make_intrinsic_instruction(
        "get_random_number", Scumm6Opcodes.CallFuncPop1Push, pop_count=1, push_count=1
    ),
    Scumm6Opcodes.OpType.get_random_number_range: make_intrinsic_instruction(
        "get_random_number_range", Scumm6Opcodes.CallFuncPop2Push, pop_count=2, push_count=1
    ),

    # --- Using Base Classes ---
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

    # --- Keeping Full Implementations for Complex Cases ---
    Scumm6Opcodes.OpType.push_byte_var: instructions.PushByteVar,
    Scumm6Opcodes.OpType.push_word_var: instructions.PushWordVar,
    Scumm6Opcodes.OpType.dup: instructions.Dup,
    Scumm6Opcodes.OpType.band: instructions.Band,
    Scumm6Opcodes.OpType.bor: instructions.Bor,
    Scumm6Opcodes.OpType.byte_var_inc: instructions.ByteVarInc,
    Scumm6Opcodes.OpType.word_var_inc: instructions.WordVarInc,
    Scumm6Opcodes.OpType.byte_var_dec: instructions.ByteVarDec,
    Scumm6Opcodes.OpType.word_var_dec: instructions.WordVarDec,
    Scumm6Opcodes.OpType.dummy: instructions.Dummy,
    Scumm6Opcodes.OpType.pick_one_of: instructions.PickOneOf,
    Scumm6Opcodes.OpType.pick_one_of_default: instructions.PickOneOfDefault,
    Scumm6Opcodes.OpType.shuffle: instructions.Shuffle,
    Scumm6Opcodes.OpType.byte_array_read: instructions.ByteArrayRead,
    Scumm6Opcodes.OpType.word_array_read: instructions.WordArrayRead,
    Scumm6Opcodes.OpType.byte_array_indexed_read: instructions.ByteArrayIndexedRead,
    Scumm6Opcodes.OpType.word_array_indexed_read: instructions.WordArrayIndexedRead,
    Scumm6Opcodes.OpType.byte_array_write: instructions.ByteArrayWrite,
    Scumm6Opcodes.OpType.word_array_write: instructions.WordArrayWrite,
    Scumm6Opcodes.OpType.byte_array_indexed_write: instructions.ByteArrayIndexedWrite,
    Scumm6Opcodes.OpType.word_array_indexed_write: instructions.WordArrayIndexedWrite,
    Scumm6Opcodes.OpType.byte_array_inc: instructions.ByteArrayInc,
    Scumm6Opcodes.OpType.word_array_inc: instructions.WordArrayInc,
    Scumm6Opcodes.OpType.byte_array_dec: instructions.ByteArrayDec,
    Scumm6Opcodes.OpType.word_array_dec: instructions.WordArrayDec,
    Scumm6Opcodes.OpType.write_byte_var: instructions.WriteByteVar,
    Scumm6Opcodes.OpType.write_word_var: instructions.WriteWordVar,
}
