"""New decoder implementation using object-oriented instruction classes."""

from typing import Optional, Iterator, Tuple, List, Dict, Any
from kaitaistruct import KaitaiStream
from io import BytesIO
import logging

# Import the Kaitai-generated parser
from ..scumm6_opcodes import Scumm6Opcodes

# Import your new instruction infrastructure
from .instr.opcodes import Instruction
from .instr.opcode_table import OPCODE_MAP

# Global setting for buffer limit error logging
# Set to True to see detailed buffer limit errors (for debugging)
# These errors are NORMAL - Binary Ninja retries with different alignments
LOG_BUFFER_LIMIT_ERRORS = False


def _handle_buffer_limit_error(exc: Exception, data: bytes, addr: int, offset: int) -> Dict[str, Any]:
    """
    Handle buffer limit errors during instruction parsing.
    
    Why these errors happen:
    Binary Ninja provides a 256-byte buffer to architecture plugins for instruction parsing.
    When an instruction needs data beyond the buffer boundary, parsing fails with an EOFError.
    This is EXPECTED BEHAVIOR - Binary Ninja will automatically retry with different buffer
    alignments until it finds one where the entire instruction fits within the 256-byte window.
    
    The errors are not failures - they're part of Binary Ninja's normal retry mechanism.
    Instructions are eventually parsed successfully despite these transient errors.
    
    Args:
        exc: The exception that occurred
        data: The buffer data provided by Binary Ninja
        addr: The base address 
        offset: Current offset within the buffer
        
    Returns:
        Dictionary with debug information about the error
    """
    debug_info = {
        'address': hex(addr + offset),
        'offset': offset,
        'remaining_bytes': len(data) - offset,
        'first_bytes': data[offset:offset + min(16, len(data) - offset)].hex(),
        'total_buffer_size': len(data),
    }
    
    # Try to identify the opcode that failed
    if offset < len(data):
        opcode_byte = data[offset]
        debug_info['opcode_byte'] = hex(opcode_byte)
        try:
            opcode_enum = Scumm6Opcodes.OpType(opcode_byte)
            debug_info['opcode_name'] = opcode_enum.name
        except ValueError:
            debug_info['opcode_name'] = 'unknown'
    
    # Check if this is an end-of-data truncation
    is_eof = (
        isinstance(exc, EOFError) or 
        ("requested" in str(exc) and "bytes available" in str(exc)) or
        "end of stream reached" in str(exc)
    )
    
    if is_eof:
        debug_info['total_consumed'] = offset
        debug_info['buffer_remaining'] = len(data) - offset
        
        # Check if we're at Binary Ninja's 256-byte limit
        if len(data) == 256:
            debug_info['at_max_buffer'] = True
            if LOG_BUFFER_LIMIT_ERRORS:
                logging.warning(
                    "Hit Binary Ninja's 256-byte buffer limit at 0x%x. "
                    "Already consumed %d bytes, need more for %s instruction. "
                    "This is normal - Binary Ninja will retry with different buffer alignment. %s",
                    addr + offset, offset, debug_info.get('opcode_name', 'unknown'),
                    debug_info
                )
        elif offset > len(data) - 10:  # Near end of data
            if LOG_BUFFER_LIMIT_ERRORS:
                logging.debug(
                    "Truncated instruction at end of data block at 0x%x: %s",
                    addr + offset, debug_info
                )
    
    return debug_info


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
            # Handle buffer limit errors
            debug_info = _handle_buffer_limit_error(exc, data, addr, offset)
            
            # Check if this is an EOF at buffer boundary
            is_eof = (
                isinstance(exc, EOFError) or 
                ("requested" in str(exc) and "bytes available" in str(exc)) or
                "end of stream reached" in str(exc)
            )
            
            if is_eof and offset > len(data) - 10:  # Near end of data
                break  # Stop decoding gracefully
            
            # Create enhanced error message
            error_msg = (
                f"Failed to parse SCUMM6 opcode: {exc}\n"
                f"Debug info: {debug_info}"
            )
            
            # Only log actual errors (not expected buffer limit issues)
            # Buffer limit errors should only be logged if explicitly enabled
            if is_eof and not LOG_BUFFER_LIMIT_ERRORS:
                # This is a buffer limit error and logging is disabled - don't log
                pass
            else:
                # Either not a buffer limit error, or logging is enabled
                logging.error(error_msg)
            
            # For buffer limit errors, return gracefully to let Binary Ninja retry
            if is_eof:
                # This signals Binary Ninja to retry with a different buffer alignment
                break
            else:
                # This is a real parsing error, not a buffer limit issue
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
    
    try:
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
