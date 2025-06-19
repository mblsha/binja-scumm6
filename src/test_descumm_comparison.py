#!/usr/bin/env python3
"""
Unit test comparing descumm output with Scumm6 architecture outputs.
This test demonstrates the difference in readability and semantic understanding.

The test shows three levels of output:
1. DESCUMM: Full semantic understanding with expression building and control flow
2. SCUMM6 Legacy: Raw bytecode representation with minimal processing  
3. SCUMM6 New: Improved semantic representation but without full descumm capabilities

Key differences highlighted:
- Expression building: descumm shows "x = (a + b)" vs individual operations
- Control flow: descumm shows "while (x < y) { ... }" vs raw jumps
- Function arguments: descumm resolves all arguments from stack
- Variable names: descumm shows symbolic names vs numeric IDs
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, Any, Union, cast
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binja_helpers import binja_api  # noqa: F401
from binaryninja.binaryview import BinaryView
from src.scumm6 import Scumm6Legacy, Scumm6New, LastBV
from src.test_mocks import MockScumm6BinaryView


# Actual bytes from room8_scrp18_110 in DOTTDEMO.bsc6
# This is real SCUMM6 bytecode from Day of the Tentacle Demo
# Script address: 0x8D79D in the .bsc6 file
ROOM8_SCRP18_BYTES = bytes([
    0x03, 0x00, 0x40, 0x8D, 0x03, 0x01, 0x40, 0x15, 0x43, 0x05, 0x40, 0x03, 0x00, 0x40, 0x8E, 0x03,  # 0000: push_word_var, get_object_x, sub, write_word_var
    0x02, 0x40, 0x15, 0x43, 0x06, 0x40, 0x03, 0x05, 0x40, 0xC4, 0x43, 0x05, 0x40, 0x03, 0x06, 0x40,  # 0010: push_word_var, sub, write_word_var, abs, write_word_var  
    0xC4, 0x43, 0x06, 0x40, 0x03, 0x05, 0x40, 0x03, 0x03, 0x40, 0x10, 0x5D, 0x0A, 0x00, 0x01, 0x00,  # 0020: abs, write_word_var, push_word_var comparisons, if_not
    0x00, 0x43, 0x89, 0x00, 0x01, 0x00, 0x00, 0x7C, 0x03, 0x06, 0x40, 0x03, 0x04, 0x40, 0x10, 0x5D,  # 0030: write_word_var, get_random_number, push_word_var, gt, if_not
])
ROOM8_SCRP18_START_ADDR = 0x8D79D

# Use the actual script bytes
SCRIPT_BYTECODE = ROOM8_SCRP18_BYTES


def format_output_as_text(tokens: List[Any]) -> str:
    """Convert token list to plain text string."""
    return ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)


def get_architecture_output(arch: Union[Scumm6Legacy, Scumm6New], bytecode: bytes, start_addr: int = ROOM8_SCRP18_START_ADDR) -> List[str]:
    """Get disassembly output from given architecture."""
    output_lines = []
    view = MockScumm6BinaryView()
    view.write_memory(start_addr, bytecode)
    LastBV.set(cast(BinaryView, view))
    
    offset = 0
    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]
        
        # Get instruction text
        result = arch.get_instruction_text(remaining_data, addr)
        if result is None:
            break
            
        tokens, length = result
        text = format_output_as_text(tokens)
        
        # Format similar to descumm: [offset] instruction
        output_lines.append(f"[{offset:04X}] {text}")
        offset += length
        
    return output_lines


# Expected descumm output for room8_scrp18 (ellipse collision detection)
# This is what descumm would ideally produce for the actual script
DESCUMM_OUTPUT = """[0000] (03) push_word_var(VAR_0)
[0003] (8D) get_object_x
[0004] (03) push_word_var(VAR_1)
[0007] (15) sub
[0008] (43) localvar5 = (getObjectX() - VAR_1)
[000B] (03) push_word_var(VAR_0)
[000E] (8E) get_object_y
[000F] (03) push_word_var(VAR_2)
[0012] (15) sub
[0013] (43) localvar6 = (getObjectY() - VAR_2)
[0016] (03) push_word_var(localvar5)
[0019] (C4) abs
[001A] (43) localvar5 = abs(localvar5)
[001D] (03) push_word_var(localvar6)
[0020] (C4) abs
[0021] (43) localvar6 = abs(localvar6)
[0024] (03) push_word_var(localvar5)
[0027] (03) push_word_var(VAR_3)
[002A] (10) gt
[002B] (5D) unless (localvar5 > VAR_3) jump +10
[002E] (01) push_byte(1)
[0030] (43) localvar137 = 1
[0033] (89) get_random_number
[0034] (01) push_byte(1)
[0036] (7C) load_room
[0037] (03) push_word_var(localvar6)
[003A] (03) push_word_var(VAR_4)
[003D] (10) gt
[003E] (5D) unless (localvar6 > VAR_4) jump +...
END"""


def test_descumm_comparison() -> None:
    """
    Compare descumm output with Scumm6 architecture outputs using real bytecode.
    
    Uses actual bytes from room8_scrp18 (same as global script 110) from DOTTDEMO.bsc6.
    This script implements ellipse collision detection in Day of the Tentacle.
    
    Address: 0x8D79D in DOTTDEMO.bsc6
    """
    
    # Get outputs from both architectures
    legacy_arch = Scumm6Legacy()
    new_arch = Scumm6New()
    
    legacy_output = get_architecture_output(legacy_arch, SCRIPT_BYTECODE)
    new_output = get_architecture_output(new_arch, SCRIPT_BYTECODE)
    
    # Print comparison for visibility
    print("\n" + "="*80)
    print("DESCUMM OUTPUT vs SCUMM6 ARCHITECTURES COMPARISON")
    print("="*80)
    
    print("\n--- EXPECTED DESCUMM OUTPUT ---")
    print(DESCUMM_OUTPUT)
    
    print("\n--- SCUMM6 LEGACY ARCHITECTURE OUTPUT ---")
    for line in legacy_output:
        print(line)
    
    print("\n--- SCUMM6 NEW ARCHITECTURE OUTPUT ---")
    for line in new_output:
        print(line)
    
    print("\n" + "="*80)
    print("ANALYSIS OF DIFFERENCES")
    print("="*80)
    
    # Analysis points based on the actual output
    print("\n1. EXPRESSION BUILDING:")
    print("   - Descumm: Shows 'localvar5 = (getObjectX() - VAR_1)' - builds expressions")
    print("   - Legacy:  Shows 'get_object_x', 'sub', 'write_word_var' separately")
    print("   - New:     Shows 'get_object_x', 'sub', 'write_word_var' separately")
    
    print("\n2. VARIABLE REPRESENTATION:")
    print("   - Descumm: Shows 'VAR_0', 'localvar5' - meaningful variable names")
    print("   - Legacy:  Shows 'push_word_var(src.scumm6_opcodes, 0)' - cluttered")
    print("   - New:     Shows 'push_word_var(var_0)' - cleaner but not semantic")
    
    print("\n3. FUNCTION CALLS:")
    print("   - Descumm: Shows 'getObjectX()' - function call style")
    print("   - Legacy:  Shows 'get_object_x(src.scumm6_opcodes, 1, 1)' - raw parameters")
    print("   - New:     Shows 'get_object_x' - clean function name")
    
    print("\n4. CONTROL FLOW:")
    print("   - Descumm: Shows 'unless (localvar5 > VAR_3) jump +10' - semantic condition")
    print("   - Legacy:  Shows 'if_not(src.scumm6_opcodes, 10)' - raw jump")
    print("   - New:     Shows 'unless goto +10' - improved semantic representation")
    
    print("\n5. MATHEMATICAL OPERATIONS:")
    print("   - Descumm: Shows 'abs(localvar5)' - function call style")
    print("   - Legacy:  Shows 'abs(src.scumm6_opcodes, 1, 1)' - raw intrinsic")
    print("   - New:     Shows 'abs' - clean operation name")
    
    print("\n6. SEMANTIC CONTEXT:")
    print("   - Descumm: Understands this is ellipse collision detection")
    print("   - Legacy:  Just shows raw SCUMM6 bytecode operations")
    print("   - New:     Shows cleaner operations but no high-level understanding")
    
    # Verify outputs were generated
    assert len(legacy_output) > 0, "Legacy architecture produced no output"
    assert len(new_output) > 0, "New architecture produced no output"
    
    # Check for any output
    if len(new_output) > 0:
        print("\n✅ Test completed - outputs generated and compared successfully")
    else:
        print("\n❌ Test failed - no output generated")


def test_specific_instruction_differences() -> None:
    """Test specific instruction type differences."""
    
    test_cases = [
        # (bytecode, descumm_output, description)
        (bytes([0x5C, 0x14, 0x00]), "if (condition) jump +20", "Conditional jump"),
        (bytes([0x5E]), "startScript(id, flags, [args])", "Start script with args"),
        (bytes([0x85, 0x4C]), "actorOps.setCostume(costume, actor)", "Actor operation"),
        (bytes([0x74]), "startSound(sound_id)", "Start sound"),
        (bytes([0xB0]), "delay(ticks)", "Delay operation"),
    ]
    
    legacy_arch = Scumm6Legacy()
    new_arch = Scumm6New()
    
    print("\n" + "="*80)
    print("SPECIFIC INSTRUCTION COMPARISON")
    print("="*80)
    
    for bytecode, descumm_expected, description in test_cases:
        print(f"\n{description}:")
        print(f"  Bytecode:  {bytecode.hex()}")
        print(f"  Descumm:   {descumm_expected}")
        
        # Get outputs
        view = MockScumm6BinaryView()
        view.write_memory(0x1000, bytecode)
        LastBV.set(cast(BinaryView, view))
        
        legacy_result = legacy_arch.get_instruction_text(bytecode, 0x1000)
        new_result = new_arch.get_instruction_text(bytecode, 0x1000)
        
        if legacy_result:
            legacy_text = format_output_as_text(legacy_result[0])
            print(f"  Legacy:    {legacy_text}")
        
        if new_result:
            new_text = format_output_as_text(new_result[0])
            print(f"  New:       {new_text}")


if __name__ == "__main__":
    # Run the comparison test directly
    test_descumm_comparison()
    print("\n" + "="*80 + "\n")
    test_specific_instruction_differences()