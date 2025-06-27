#!/usr/bin/env python3
"""Test case for room8_scrp1 ArrayOps issue causing short disassembly."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from binja_helpers import binja_api  # noqa: F401

from src.test_descumm_comparison import ScriptComparisonTestCase, ComparisonTestEnvironment, test_environment


def test_room8_scrp1_full_disassembly(test_environment: ComparisonTestEnvironment):
    """Test that room8_scrp1 is fully disassembled, not truncated at ArrayOps."""
    
    # Create test case for room8_scrp1
    case = ScriptComparisonTestCase(
        test_id="room8_scrp1_full_length",
        script_name="room8_scrp1",
    )
    
    # Find the script
    script_info = None
    for script in test_environment.scripts:
        if script.name == "room8_scrp1":
            script_info = script
            break
    
    assert script_info is not None, "room8_scrp1 not found"
    
    # Extract bytecode
    bytecode = test_environment.bsc6_data[script_info.start:script_info.end]
    total_bytes = len(bytecode)
    
    print(f"\nroom8_scrp1 total size: {total_bytes} bytes")
    
    # Run disassemblers
    from src.test_utils import run_descumm_on_bytecode, run_scumm6_disassembler, run_scumm6_disassembler_with_fusion
    
    descumm_output = run_descumm_on_bytecode(test_environment.descumm_path, bytecode)
    disasm_output = run_scumm6_disassembler(bytecode, script_info.start)
    fusion_output = run_scumm6_disassembler_with_fusion(bytecode, script_info.start)
    
    # Count lines
    descumm_lines = len([line for line in descumm_output.splitlines() if line.strip()])
    disasm_lines = len([line for line in disasm_output.splitlines() if line.strip()])
    fusion_lines = len([line for line in fusion_output.splitlines() if line.strip()])
    
    print(f"Descumm output: {descumm_lines} lines")
    print(f"SCUMM6 output: {disasm_lines} lines")
    print(f"SCUMM6 fusion output: {fusion_lines} lines")
    
    # The key issue: SCUMM6 should produce similar number of lines as descumm
    # Currently it's producing ~20 lines instead of ~97 lines
    
    # Check that we decoded more than just the first few instructions
    assert disasm_lines > 50, f"SCUMM6 only decoded {disasm_lines} lines, expected > 50"
    
    # Check that the ArrayOps instruction doesn't consume the whole script
    # Look for the string assignment in the output
    assert "Day of the Tentacle BBS Contest DEMO" in disasm_output
    
    # Check that we have instructions after the ArrayOps
    assert "var_122 = 0" in fusion_output or "write_word_var(var_122)" in disasm_output, \
        "Missing instruction after ArrayOps string assignment"
    
    # Check for key instructions near the end
    assert "stopObjectCodeB" in disasm_output or "stop_object_code2" in disasm_output, \
        "Missing final stop instruction"


def test_array_ops_string_length():
    """Test that ArrayOps with string assignment calculates correct length."""
    
    from src.pyscumm6.disasm import decode
    
    # Exact bytecode from room8_scrp1 at offset 0x31
    # push_word(0) + array_ops string assignment
    bytecode = bytes([
        0x01, 0x00, 0x00,  # push_word(0)
        0xA4, 0xCD, 0xE6,  # array_ops array_id=59085
        0x00,              # subop=assign_string
        # String content
        0x44, 0x61, 0x79, 0x20, 0x6F, 0x66, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x54, 0x65, 0x6E, 0x74, 0x61,
        0x63, 0x6C, 0x65, 0x20, 0x42, 0x42, 0x53, 0x20,
        0x43, 0x6F, 0x6E, 0x74, 0x65, 0x73, 0x74, 0x20,
        0x44, 0x45, 0x4D, 0x4F,
        0x00,              # null terminator
        # Next instruction
        0x01, 0x00, 0x00,  # push_word(0)
        0x43, 0x7A, 0x00   # write_word_var(var_122)
    ])
    
    # Decode first instruction (push_word)
    inst1 = decode(bytecode, 0x0)
    assert inst1 is not None
    assert inst1.__class__.__name__ == "PushWord"
    assert inst1.length() == 3
    
    # Decode second instruction (array_ops)
    inst2 = decode(bytecode[3:], 0x3)
    assert inst2 is not None
    assert inst2.__class__.__name__ == "ArrayOps"
    
    # The critical test: ArrayOps should have correct length
    # 1 (opcode) + 2 (array_id) + 1 (subop) + 36 (string) + 1 (null) = 41 bytes
    expected_length = 41
    actual_length = inst2.length()
    
    assert actual_length == expected_length, \
        f"ArrayOps length is {actual_length}, expected {expected_length}"
    
    # Verify we can decode the next instruction
    next_offset = 3 + inst2.length()
    inst3 = decode(bytecode[next_offset:], next_offset)
    assert inst3 is not None
    assert inst3.__class__.__name__ == "PushWord"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])