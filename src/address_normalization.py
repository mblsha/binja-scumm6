"""Address normalization utilities for jump instructions.

This module provides utilities to normalize absolute addresses in disassembly output
when scripts are executed from non-zero starting points. This is used by both
test cases and the web UI to make jump addresses more readable.
"""

import re


def normalize_jump_addresses(output: str, script_start_addr: int) -> str:
    """
    Normalize jump addresses in disassembly output by subtracting the script start address.
    
    This transforms large absolute addresses like "jump 8d8b3" into smaller relative addresses
    like "jump f5" when the script starts at a non-zero address (e.g., 0x8d7aa).
    
    Args:
        output: The disassembly output containing jump instructions
        script_start_addr: The starting address of the script
        
    Returns:
        The normalized output with adjusted jump addresses
    """
    if script_start_addr == 0:
        # No normalization needed if script starts at 0
        return output
    
    def replace_jump_address(match: re.Match[str]) -> str:
        """Replace a single jump address with normalized version."""
        prefix = match.group(1)  # "jump " or "goto "
        addr_str = match.group(2)  # The hex address
        
        # Parse the hex address
        try:
            addr = int(addr_str, 16)
        except ValueError:
            # If we can't parse it, leave it unchanged
            return match.group(0)
        
        # Check if this looks like a large address that needs normalization
        # We'll normalize if the address is greater than the script start
        if addr >= script_start_addr:
            # Subtract the script start to get relative address
            normalized_addr = addr - script_start_addr
            return f"{prefix}{normalized_addr:x}"
        else:
            # Keep small addresses as-is (like "jump 3" or negative addresses)
            return match.group(0)
    
    # Pattern to match jump/goto instructions with hex addresses
    # Matches: "jump 8d8b3", "goto 8d8b3", etc.
    pattern = r'\b(jump |goto )([0-9a-fA-F]+)\b'
    
    return re.sub(pattern, replace_jump_address, output)


def normalize_instruction_addresses(output: str, script_start_addr: int) -> str:
    """
    Normalize instruction addresses in square brackets when script starts at non-zero address.
    
    This transforms addresses like "[8d7aa]" to "[0000]" by subtracting the script start address.
    
    Args:
        output: The disassembly output containing instruction addresses
        script_start_addr: The starting address of the script
        
    Returns:
        The normalized output with adjusted instruction addresses
    """
    if script_start_addr == 0:
        # No normalization needed if script starts at 0
        return output
    
    def replace_instruction_address(match: re.Match[str]) -> str:
        """Replace a single instruction address with normalized version."""
        addr_str = match.group(1)  # The hex address without brackets
        
        # Parse the hex address
        try:
            addr = int(addr_str, 16)
        except ValueError:
            # If we can't parse it, leave it unchanged
            return match.group(0)
        
        # Skip normalization if address is already small (less than 0x1000)
        # This avoids changing addresses that are already relative
        if addr < 0x1000:
            return match.group(0)
        
        # Normalize by subtracting script start
        normalized_addr = addr - script_start_addr
        
        # Keep the same width for formatting consistency
        width = len(addr_str)
        return f"[{normalized_addr:0{width}X}]"
    
    # Pattern to match instruction addresses in square brackets
    # Matches: "[8d7aa]", "[00AB]", etc.
    pattern = r'\[([0-9a-fA-F]+)\]'
    
    return re.sub(pattern, replace_instruction_address, output)


def normalize_disasm_output(output: str, script_start_addr: int) -> str:
    """
    Apply all normalizations to disassembly output.
    
    This includes:
    - Jump address normalization
    - Instruction address normalization
    
    Args:
        output: The disassembly output
        script_start_addr: The starting address of the script
        
    Returns:
        The fully normalized output
    """
    output = normalize_instruction_addresses(output, script_start_addr)
    output = normalize_jump_addresses(output, script_start_addr)
    return output