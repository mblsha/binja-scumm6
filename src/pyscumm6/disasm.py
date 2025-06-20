"""New decoder implementation using object-oriented instruction classes."""

from typing import Optional, Iterator, Tuple
from kaitaistruct import KaitaiStream
from io import BytesIO

# Import the Kaitai-generated parser
from ..scumm6_opcodes import Scumm6Opcodes

# Import your new instruction infrastructure
from .instr.opcodes import Instruction
from .instr.opcode_table import OPCODE_MAP


def _iter_decode(data: bytes, addr: int) -> Iterator[Tuple[Instruction, int]]:
    """A generator that yields decoded instructions one by one."""
    offset = 0
    while offset < len(data):
        try:
            remaining_data = data[offset:]
            if not remaining_data:
                break
            
            ks = KaitaiStream(BytesIO(remaining_data))
            parsed_op = Scumm6Opcodes(ks).op
            length = ks.pos()
            if length == 0:
                break

            InstructionClass = OPCODE_MAP.get(parsed_op.id)
            if InstructionClass:
                instr = InstructionClass(kaitai_op=parsed_op, length=length)
                yield instr, addr + offset
                offset += length
            else:
                break
        except Exception:
            break


def _fusion(instruction_iterator: Iterator[Tuple[Instruction, int]]) -> Iterator[Tuple[Instruction, int]]:
    """A generator that attempts to fuse adjacent instructions."""
    try:
        current_instruction, current_addr = next(instruction_iterator)
    except StopIteration:
        return

    while True:
        try:
            next_instruction, next_addr = next(instruction_iterator)
            
            if fused_instruction := current_instruction.fuse(next_instruction):
                current_instruction = fused_instruction
            else:
                yield current_instruction, current_addr
                current_instruction, current_addr = next_instruction, next_addr
        except StopIteration:
            yield current_instruction, current_addr
            break


def decode(data: bytes, addr: int) -> Optional[Instruction]:
    """
    Decodes a single (potentially fused) instruction from a byte stream.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        
    Returns:
        Instruction object or None if decoding failed
    """
    fused_iterator = _fusion(_iter_decode(data, addr))
    try:
        instr, _ = next(fused_iterator)
        return instr
    except StopIteration:
        return None