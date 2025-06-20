"""New decoder implementation using object-oriented instruction classes."""

from typing import Optional, Iterator, Tuple, List
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
    """
    A generator that implements simplified look-behind fusion.
    Each consumer instruction tries to fuse with the instruction that came before it.
    """
    decoded_sequence: List[Tuple[Instruction, int]] = []
    
    for instruction, addr in instruction_iterator:
        # Try to fuse with the last instruction in the sequence
        if decoded_sequence:
            last_instruction, last_addr = decoded_sequence[-1]
            
            # Try to fuse current instruction with the last one
            fused_instruction = instruction.fuse(last_instruction)
            
            if fused_instruction:
                # Replace the last instruction with the fused one
                # Update the address to be the address of the first (earliest) instruction
                decoded_sequence[-1] = (fused_instruction, last_addr)
                
                # Iteratively try to fuse with the new sequence end
                # This handles multi-operand cases like push; push; add
                while len(decoded_sequence) >= 2:
                    current_fused, current_addr = decoded_sequence[-1]
                    previous_instr, previous_addr = decoded_sequence[-2]
                    
                    multi_fused = current_fused.fuse(previous_instr)
                    if multi_fused:
                        # Remove the previous instruction and update the current one
                        decoded_sequence.pop(-2)
                        decoded_sequence[-1] = (multi_fused, previous_addr)
                    else:
                        break
                        
                # Continue to next instruction without outputting anything yet
                continue
        
        # No fusion possible, add to sequence
        decoded_sequence.append((instruction, addr))
        
        # For fusion testing, don't yield immediately - wait until we know
        # no more fusion is possible. In a real streaming scenario, we'd need
        # more sophisticated logic to determine when it's safe to yield.
    
    # Yield any remaining instructions in the sequence
    for instruction_pair in decoded_sequence:
        yield instruction_pair


def decode(data: bytes, addr: int) -> Optional[Instruction]:
    """
    Decodes a single instruction from a byte stream.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        
    Returns:
        Instruction object or None if decoding failed
    """
    try:
        for instr, _ in _iter_decode(data, addr):
            return instr  # Return the first (only) instruction
        return None
    except StopIteration:
        return None


def decode_with_fusion(data: bytes, addr: int) -> Optional[Instruction]:
    """
    Decodes a single (potentially fused) instruction from a byte stream.
    This function applies instruction fusion for contexts like LLIL lifting.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        
    Returns:
        Instruction object (potentially fused) or None if decoding failed
    """
    fused_iterator = _fusion(_iter_decode(data, addr))
    
    # For fusion, we want the last (most complete) result
    # This handles cases where multiple instructions get fused together
    last_instruction = None
    try:
        for instr, _ in fused_iterator:
            last_instruction = instr
        return last_instruction
    except StopIteration:
        return None