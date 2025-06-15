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
    # As you implement more instructions, you will add them here:
    # Scumm6Opcodes.OpType.add: instructions.Add,
}