#!/usr/bin/env python3
"""
Test script to check for incomplete disassembly in DOTTDEMO.bsc6 scripts.
Focuses on finding scripts that might show incomplete results when disassembled.
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


def extract_script_bytecode(bsc6_path: str, script_name: str):
    """Extract a specific script's bytecode from the BSC6 file."""
    bsc6_data = Path(bsc6_path).read_bytes()
    
    result = Scumm6Disasm.decode_container(bsc6_path, bsc6_data)
    if not result:
        raise ValueError(f"Failed to parse {bsc6_path}")
    
    script_list, state = result
    
    # Find the script
    for script_info in script_list:
        if script_info.name == script_name:
            bytecode = bsc6_data[script_info.start:script_info.end]
            return bytecode, script_info.start
    
    raise ValueError(f"Script '{script_name}' not found")


def analyze_script_completeness(script_name: str, bytecode: bytes, start_addr: int):
    """Analyze a script to check if disassembly is complete."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {script_name}")
    print(f"Bytecode length: {len(bytecode)} bytes")
    print(f"Start address: 0x{start_addr:08X}")
    print(f"{'='*60}")
    
    # Test 1: Normal decode (no fusion)
    print("\n--- Normal Decode (no fusion) ---")
    try:
        normal_output = run_scumm6_disassembler(bytecode, start_addr)
        print(normal_output)
        
        # Count instructions decoded
        normal_lines = [line for line in normal_output.split('\n') if line.strip()]
        print(f"\nInstructions decoded: {len(normal_lines)}")
        
        # Check if we decoded all bytes
        last_line = normal_lines[-1] if normal_lines else ""
        if '[' in last_line:
            last_offset = int(last_line.split('[')[1].split(']')[0], 16)
            print(f"Last offset: 0x{last_offset:04X}")
            
            # Try to determine if there are remaining bytes
            offset = 0
            total_length = 0
            while offset < len(bytecode):
                try:
                    instr = decode(bytecode[offset:], offset)
                    if not instr:
                        break
                    total_length += instr.length()
                    offset += instr.length()
                except Exception as e:
                    print(f"Decode error at offset 0x{offset:04X}: {e}")
                    break
            
            print(f"Total bytes decoded: {total_length} / {len(bytecode)}")
            if total_length < len(bytecode):
                print(f"⚠️  INCOMPLETE: {len(bytecode) - total_length} bytes not decoded!")
                # Show remaining bytes
                remaining = bytecode[total_length:]
                print(f"Remaining bytes: {remaining.hex()}")
    except Exception as e:
        print(f"Error in normal decode: {e}")
    
    # Test 2: Fusion decode
    print("\n--- Fusion Decode ---")
    try:
        fusion_output = run_scumm6_disassembler_with_fusion(bytecode, start_addr)
        print(fusion_output)
        
        fusion_lines = [line for line in fusion_output.split('\n') if line.strip()]
        print(f"\nInstructions decoded: {len(fusion_lines)}")
        
        # Compare with normal decode
        if len(fusion_lines) != len(normal_lines):
            print(f"⚠️  Different instruction count! Normal: {len(normal_lines)}, Fusion: {len(fusion_lines)}")
    except Exception as e:
        print(f"Error in fusion decode: {e}")
    
    # Test 3: Check for specific problematic patterns
    print("\n--- Checking for problematic patterns ---")
    
    # Look for potential issues
    issues = []
    
    # Check for 0x65 (stop_object_code) which might terminate early
    if b'\x65' in bytecode:
        positions = [i for i, b in enumerate(bytecode) if b == 0x65]
        issues.append(f"Found stop_object_code (0x65) at positions: {positions}")
    
    # Check for 0x00 bytes that might be misinterpreted
    if b'\x00' in bytecode:
        positions = [i for i, b in enumerate(bytecode) if b == 0x00]
        if len(positions) > 5:  # Many zero bytes might indicate padding or data
            issues.append(f"Found {len(positions)} zero bytes, might indicate padding/data")
    
    # Check for unknown opcodes (0xFF range)
    high_opcodes = [i for i, b in enumerate(bytecode) if b >= 0xF0]
    if high_opcodes:
        issues.append(f"Found high opcodes (>=0xF0) at positions: {high_opcodes}")
    
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  No obvious problematic patterns found")
    
    return len(normal_lines) if 'normal_lines' in locals() else 0


def find_incomplete_scripts(bsc6_path: str, sample_size: int = 10):
    """Find scripts that might have incomplete disassembly."""
    bsc6_data = Path(bsc6_path).read_bytes()
    
    result = Scumm6Disasm.decode_container(bsc6_path, bsc6_data)
    if not result:
        raise ValueError(f"Failed to parse {bsc6_path}")
    
    script_list, state = result
    
    print(f"Total scripts found: {len(script_list)}")
    print(f"Analyzing first {sample_size} scripts for completeness...\n")
    
    incomplete_scripts = []
    
    for i, script_info in enumerate(script_list[:sample_size]):
        script_name = script_info.name
        bytecode = bsc6_data[script_info.start:script_info.end]
        
        if len(bytecode) == 0:
            print(f"⚠️  {script_name}: Empty script!")
            continue
        
        # Quick check for completeness
        try:
            offset = 0
            instruction_count = 0
            while offset < len(bytecode):
                instr = decode(bytecode[offset:], offset)
                if not instr:
                    break
                offset += instr.length()
                instruction_count += 1
            
            if offset < len(bytecode):
                incomplete_scripts.append({
                    'name': script_name,
                    'total_bytes': len(bytecode),
                    'decoded_bytes': offset,
                    'remaining_bytes': len(bytecode) - offset,
                    'instruction_count': instruction_count
                })
                print(f"❌ {script_name}: INCOMPLETE - {offset}/{len(bytecode)} bytes decoded")
            else:
                print(f"✅ {script_name}: Complete - {len(bytecode)} bytes, {instruction_count} instructions")
                
        except Exception as e:
            print(f"❌ {script_name}: Error during analysis - {e}")
            incomplete_scripts.append({
                'name': script_name,
                'total_bytes': len(bytecode),
                'error': str(e)
            })
    
    return incomplete_scripts


def main():
    """Main entry point."""
    bsc6_path = "DOTTDEMO.bsc6"
    
    if not os.path.exists(bsc6_path):
        print(f"Error: {bsc6_path} not found")
        sys.exit(1)
    
    # First, find potentially incomplete scripts
    print("=== FINDING INCOMPLETE SCRIPTS ===")
    incomplete = find_incomplete_scripts(bsc6_path, sample_size=20)
    
    if incomplete:
        print(f"\n\nFound {len(incomplete)} potentially incomplete scripts:")
        for script in incomplete:
            print(f"  - {script['name']}: {script.get('remaining_bytes', '?')} bytes remaining")
    
    # Analyze a few specific scripts in detail
    test_scripts = [
        "room1_enter",  # Simple script
        "room2_enter",  # Another simple one
        "room8_scrp18", # Complex collision detection
    ]
    
    # If we found incomplete scripts, analyze the first one in detail
    if incomplete:
        test_scripts.insert(0, incomplete[0]['name'])
    
    print("\n\n=== DETAILED ANALYSIS ===")
    for script_name in test_scripts:
        try:
            bytecode, start_addr = extract_script_bytecode(bsc6_path, script_name)
            analyze_script_completeness(script_name, bytecode, start_addr)
        except Exception as e:
            print(f"\nError analyzing {script_name}: {e}")


if __name__ == "__main__":
    main()