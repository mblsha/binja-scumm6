"""New decoder implementation using object-oriented instruction classes."""

from typing import Optional, Iterator, Tuple, List
from kaitaistruct import KaitaiStream, KaitaiStructError
from io import BytesIO
import logging
import struct

# Import the Kaitai-generated parser
from ..scumm6_opcodes import Scumm6Opcodes

# Import your new instruction infrastructure
from .instr.opcodes import Instruction
from .instr.opcode_table import OPCODE_MAP


def _iter_decode(data: bytes, addr: int) -> Iterator[Tuple[Instruction, int]]:
    """A generator that yields decoded instructions one by one."""
    offset = 0
    while offset < len(data):
        remaining_data = data[offset:]
        if not remaining_data:
            break

        try:
            ks = KaitaiStream(BytesIO(remaining_data))
            parsed_op = Scumm6Opcodes(ks).op
        except Exception as exc:
            # Add debugging context to the exception
            debug_info = {
                'address': hex(addr + offset),
                'offset': offset,
                'remaining_bytes': len(remaining_data),
                'first_bytes': remaining_data[:min(16, len(remaining_data))].hex(),
            }
            
            # Try to identify the opcode that failed
            if remaining_data:
                opcode_byte = remaining_data[0]
                debug_info['opcode_byte'] = hex(opcode_byte)
                try:
                    opcode_enum = Scumm6Opcodes.OpType(opcode_byte)
                    debug_info['opcode_name'] = opcode_enum.name
                except ValueError:
                    debug_info['opcode_name'] = 'unknown'
            
            # Check if this is an end-of-data truncation
            is_eof = (
                isinstance(exc, EOFError) or 
                "requested" in str(exc) and "bytes available" in str(exc)
            )
            
            # Enhanced diagnostics for buffer exhaustion
            if is_eof:
                # Calculate total bytes consumed before this instruction
                total_consumed = offset
                buffer_remaining = len(data) - offset
                
                # Add buffer consumption info to debug data
                debug_info['total_consumed'] = total_consumed
                debug_info['buffer_remaining'] = buffer_remaining
                debug_info['total_buffer_size'] = len(data)
                
                # Check if we're hitting the 256-byte limit
                if len(data) == 256:
                    debug_info['at_max_buffer'] = True
                    logging.warning(
                        "Hit Binary Ninja's 256-byte buffer limit at 0x%x. "
                        "Already consumed %d bytes, need more for %s instruction. %s",
                        addr + offset, total_consumed, debug_info.get('opcode_name', 'unknown'),
                        debug_info
                    )
                elif offset > len(data) - 10:  # Near end of data
                    logging.debug(
                        "Truncated instruction at end of data block at 0x%x: %s",
                        addr + offset, debug_info
                    )
                    break  # Stop decoding gracefully
                else:
                    # Not near end, this is a real parsing error
                    pass  # Continue to error reporting below
            
            # Create enhanced error message
            error_msg = (
                f"Failed to parse SCUMM6 opcode: {exc}\n"
                f"Debug info: {debug_info}"
            )
            
            # Log the error with full context
            logging.error(error_msg)
            
            # Re-raise with enhanced message
            raise RuntimeError(error_msg) from exc

        length = ks.pos()
        if length == 0:
            break

        InstructionClass = OPCODE_MAP.get(parsed_op.id)
        if InstructionClass is None:
            logging.debug(
                "Unknown opcode %s at 0x%x", parsed_op.id, addr + offset
            )
            break

        instr = InstructionClass(kaitai_op=parsed_op, length=length, addr=addr + offset)
        yield instr, addr + offset
        offset += length


def _fusion(instruction_iterator: Iterator[Tuple[Instruction, int]]) -> Iterator[Tuple[Instruction, int]]:
    """
    A generator that implements simplified look-behind fusion.
    Each consumer instruction tries to fuse with the instruction that came before it.
    """
    decoded_sequence: List[Tuple[Instruction, int]] = []
    total_bytes_consumed = 0  # Track total bytes consumed by fusion
    
    try:
        for instruction, addr in instruction_iterator:
            # Track bytes consumed
            total_bytes_consumed += instruction.length()
            
            # Log fusion activity for debugging buffer issues
            if logging.getLogger().isEnabledFor(logging.DEBUG) and total_bytes_consumed > 200:
                logging.debug(
                    "Fusion consuming significant buffer: %d bytes total at addr 0x%x",
                    total_bytes_consumed, addr
                )
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
    
    except RuntimeError:
        # If we hit a parsing error, still yield any successfully decoded instructions
        pass
    
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


def decode_with_fusion(data: bytes, addr: int, enable_loop_detection: bool = True) -> Optional[Instruction]:
    """
    Decodes a single (potentially fused) instruction from a byte stream.
    This function applies instruction fusion for contexts like LLIL lifting.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        enable_loop_detection: Whether to apply loop pattern recognition
        
    Returns:
        Instruction object (potentially fused) or None if decoding failed
    """
    fused_iterator = _fusion(_iter_decode(data, addr))
    
    # For fusion, we want the most complete result (handles multi-instruction fusion)
    # This is different from regular decode() which returns the first instruction
    last_instruction = None
    try:
        for instr, _ in fused_iterator:
            last_instruction = instr
        
        # Apply loop pattern recognition as final step (if enabled)
        if last_instruction and enable_loop_detection:
            last_instruction = _apply_loop_detection(last_instruction, addr)
            
        return last_instruction
    except StopIteration:
        return None


def decode_with_fusion_incremental(data: bytes, addr: int, enable_loop_detection: bool = True) -> Optional[Instruction]:
    """
    Decodes a single instruction with fusion, suitable for incremental parsing.
    Returns the first (complete) instruction for step-by-step disassembly.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        enable_loop_detection: Whether to apply loop pattern recognition
        
    Returns:
        First instruction object (potentially fused) or None if decoding failed
    """
    # Add diagnostics for buffer size issues
    if len(data) < 256 and logging.getLogger().isEnabledFor(logging.DEBUG):
        # Only log when we have less than max buffer size
        logging.debug(
            "decode_with_fusion_incremental called with limited buffer: "
            "addr=0x%x, buffer_size=%d bytes (max=256), first_bytes=%s",
            addr, len(data), data[:min(16, len(data))].hex()
        )
    
    fused_iterator = _fusion(_iter_decode(data, addr))
    
    # For incremental parsing, we want the first complete result
    try:
        for instr, _ in fused_iterator:
            # Apply loop pattern recognition as final step (if enabled)
            if enable_loop_detection:
                enhanced_instr = _apply_loop_detection(instr, addr)
                return enhanced_instr
            else:
                return instr
        
        return None
    except StopIteration:
        return None


def _apply_loop_detection(instruction: Instruction, addr: int) -> Instruction:
    """
    Apply loop pattern recognition to a fused instruction.
    
    Args:
        instruction: The instruction to analyze for loop patterns
        addr: Address of the instruction
        
    Returns:
        Enhanced instruction with loop detection (may be the same object)
    """
    # Import here to avoid circular imports
    from .instr.smart_bases import SmartLoopIfNot, SmartLoopIff, SmartConditionalJump
    
    # Check if this is a conditional jump that could be a loop
    if isinstance(instruction, SmartConditionalJump):
        # Create enhanced version with loop detection
        if instruction.__class__.__name__ == "SmartIfNot":
            if_not_loop = SmartLoopIfNot(instruction.op_details, instruction._length)
            # Copy fusion state
            if_not_loop.fused_operands = instruction.fused_operands.copy()
            # Attempt loop detection
            if if_not_loop.detect_and_fuse_loop(addr):
                return if_not_loop
        elif instruction.__class__.__name__ == "SmartIff":
            iff_loop = SmartLoopIff(instruction.op_details, instruction._length)
            # Copy fusion state
            iff_loop.fused_operands = instruction.fused_operands.copy()
            # Attempt loop detection
            if iff_loop.detect_and_fuse_loop(addr):
                return iff_loop
    
    return instruction
