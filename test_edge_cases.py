#!/usr/bin/env python3
"""
Test edge cases and potential issues in SCUMM6 disassembly.
"""

import os
import sys
from pathlib import Path

# Add parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Force mock Binary Ninja for standalone execution
os.environ["FORCE_BINJA_MOCK"] = "1"

from src.container import ContainerParser as Scumm6Disasm
from src.pyscumm6.disasm import decode, decode_with_fusion_incremental
from src.test_utils import run_scumm6_disassembler, run_scumm6_disassembler_with_fusion


def test_specific_opcodes():
    """Test specific opcodes that might cause issues."""
    print("=== Testing Specific Opcodes ===\n")
    
    test_cases = [
        # Test 1: Simple stop_object_code
        {
            'name': 'stop_object_code alone',
            'bytecode': bytes([0x65]),  # stopObjectCodeA
            'description': 'Single stop instruction'
        },
        
        # Test 2: Multiple stop codes
        {
            'name': 'multiple stop codes',
            'bytecode': bytes([0x65, 0x66]),  # stopObjectCodeA, stopObjectCodeB
            'description': 'Two stop instructions in sequence'
        },
        
        # Test 3: Unknown/high opcodes
        {
            'name': 'high opcode',
            'bytecode': bytes([0xFF]),  # Potentially unknown
            'description': 'High opcode value that might be unknown'
        },
        
        # Test 4: Zero bytes
        {
            'name': 'zero bytes',
            'bytecode': bytes([0x00, 0x00, 0x00, 0x00]),
            'description': 'Multiple zero bytes'
        },
        
        # Test 5: Complex fusion case
        {
            'name': 'complex fusion',
            'bytecode': bytes([
                0x00, 0x05,  # push_byte(5)
                0x00, 0x0A,  # push_byte(10)
                0x14,        # add
                0x00, 0x02,  # push_byte(2)
                0x16,        # mul
                0x42, 0x0A   # write_byte_var(10)
            ]),
            'description': 'Multi-level expression: var_10 = (5 + 10) * 2'
        },
        
        # Test 6: Jump to invalid address
        {
            'name': 'invalid jump',
            'bytecode': bytes([
                0x73, 0xFF, 0xFF  # jump to very large offset
            ]),
            'description': 'Jump with potentially invalid target'
        },
        
        # Test 7: Array write edge case
        {
            'name': 'array write',
            'bytecode': bytes([
                0x00, 0x0A,        # push_byte(10) - value
                0x00, 0x05,        # push_byte(5)  - index
                0x7C, 0x01, 0x00   # byte_array_write(array_1)
            ]),
            'description': 'Array write operation'
        }
    ]
    
    for test in test_cases:
        print(f"--- {test['name']} ---")
        print(f"Description: {test['description']}")
        print(f"Bytecode: {test['bytecode'].hex()}")
        
        # Test normal decode
        try:
            print("\nNormal decode:")
            output = run_scumm6_disassembler(test['bytecode'], 0x1000)
            print(output if output else "  (no output)")
        except Exception as e:
            print(f"  Error: {e}")
        
        # Test fusion decode
        try:
            print("\nFusion decode:")
            output = run_scumm6_disassembler_with_fusion(test['bytecode'], 0x1000)
            print(output if output else "  (no output)")
        except Exception as e:
            print(f"  Error: {e}")
        
        print()


def test_script_boundaries():
    """Test scripts at boundaries and with unusual properties."""
    bsc6_path = "DOTTDEMO.bsc6"
    
    if not os.path.exists(bsc6_path):
        print(f"Error: {bsc6_path} not found")
        return
    
    print("\n=== Testing Script Boundaries ===\n")
    
    bsc6_data = Path(bsc6_path).read_bytes()
    result = Scumm6Disasm.decode_container(bsc6_path, bsc6_data)
    if not result:
        return
    
    script_list, state = result
    
    # Find edge case scripts
    shortest_script = min(script_list, key=lambda s: s.end - s.start)
    longest_script = max(script_list, key=lambda s: s.end - s.start)
    
    print(f"Shortest script: {shortest_script.name} ({shortest_script.end - shortest_script.start} bytes)")
    print(f"Longest script: {longest_script.name} ({longest_script.end - longest_script.start} bytes)")
    
    # Test shortest script
    print(f"\n--- Analyzing {shortest_script.name} ---")
    bytecode = bsc6_data[shortest_script.start:shortest_script.end]
    print(f"Bytecode: {bytecode.hex()}")
    
    try:
        normal = run_scumm6_disassembler(bytecode, shortest_script.start)
        print("Normal decode:")
        print(normal)
        
        fusion = run_scumm6_disassembler_with_fusion(bytecode, shortest_script.start)
        print("\nFusion decode:")
        print(fusion)
    except Exception as e:
        print(f"Error: {e}")
    
    # Look for scripts with specific patterns
    print("\n--- Scripts with many zero bytes ---")
    for script_info in script_list[:10]:  # Check first 10
        bytecode = bsc6_data[script_info.start:script_info.end]
        zero_count = bytecode.count(b'\x00')
        if zero_count > len(bytecode) * 0.3:  # More than 30% zeros
            print(f"{script_info.name}: {zero_count}/{len(bytecode)} zeros ({zero_count*100//len(bytecode)}%)")


def test_instruction_lengths():
    """Test that instruction length calculations are correct."""
    print("\n=== Testing Instruction Lengths ===\n")
    
    # Test various instruction combinations
    test_bytecodes = [
        bytes([0x00, 0x05]),  # push_byte(5) - should be 2 bytes
        bytes([0x01, 0x00, 0x01]),  # push_word(256) - should be 3 bytes
        bytes([0x14]),  # add - should be 1 byte
        bytes([0x73, 0x10, 0x00]),  # jump - should be 3 bytes
        bytes([0x8F, 0x01, 0x00, 0x00]),  # Complex instruction with parameters
    ]
    
    for bytecode in test_bytecodes:
        print(f"Testing bytecode: {bytecode.hex()}")
        
        try:
            # Decode without fusion
            instr = decode(bytecode, 0)
            if instr:
                print(f"  Instruction: {instr.__class__.__name__}")
                print(f"  Reported length: {instr.length()}")
                print(f"  Actual bytecode length: {len(bytecode)}")
                
                if instr.length() > len(bytecode):
                    print("  ⚠️  WARNING: Instruction length exceeds bytecode!")
                elif instr.length() < len(bytecode):
                    print(f"  Note: Only consumed {instr.length()} of {len(bytecode)} bytes")
            else:
                print("  Failed to decode")
        except Exception as e:
            print(f"  Error: {e}")
        
        print()


def test_error_recovery():
    """Test how the decoder handles corrupted or invalid bytecode."""
    print("\n=== Testing Error Recovery ===\n")
    
    # Test various corrupted bytecodes
    test_cases = [
        {
            'name': 'Truncated push_word',
            'bytecode': bytes([0x01, 0x00]),  # push_word missing last byte
            'description': 'push_word instruction with missing byte'
        },
        {
            'name': 'Invalid opcode sequence',
            'bytecode': bytes([0xFF, 0xFE, 0xFD]),  # Unknown opcodes
            'description': 'Sequence of unknown opcodes'
        },
        {
            'name': 'Mixed valid/invalid',
            'bytecode': bytes([0x00, 0x05, 0xFF, 0x00, 0x0A, 0x14]),
            'description': 'Valid instructions with invalid opcode in middle'
        }
    ]
    
    for test in test_cases:
        print(f"--- {test['name']} ---")
        print(f"Description: {test['description']}")
        print(f"Bytecode: {test['bytecode'].hex()}")
        
        # Test decoding
        offset = 0
        instructions = []
        errors = []
        
        while offset < len(test['bytecode']):
            try:
                remaining = test['bytecode'][offset:]
                instr = decode(remaining, offset)
                if instr:
                    instructions.append((offset, instr.__class__.__name__, instr.length()))
                    offset += instr.length()
                else:
                    errors.append((offset, "Failed to decode"))
                    offset += 1  # Skip one byte and try again
            except Exception as e:
                errors.append((offset, str(e)))
                offset += 1  # Skip one byte and try again
        
        print(f"\nDecoded {len(instructions)} instructions:")
        for off, name, length in instructions:
            print(f"  [0x{off:04X}] {name} (length={length})")
        
        if errors:
            print(f"\nEncountered {len(errors)} errors:")
            for off, err in errors:
                print(f"  [0x{off:04X}] {err}")
        
        print()


def main():
    """Main entry point."""
    print("SCUMM6 Disassembly Edge Case Testing\n")
    
    test_specific_opcodes()
    test_script_boundaries()
    test_instruction_lengths()
    test_error_recovery()
    
    print("\nEdge case testing complete!")


if __name__ == "__main__":
    main()