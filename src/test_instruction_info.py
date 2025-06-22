#!/usr/bin/env python3
"""
Test InstructionInfo population for conditional jumps in SCUMM6 architecture.

This test ensures that "unless goto +XX" and other conditional instructions
correctly populate the InstructionInfo with proper branch targets.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import sys
import os
from typing import TypedDict, cast

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binja_helpers import binja_api  # noqa: F401
from binaryninja.enums import BranchType

from src.scumm6 import Scumm6, LastBV
from src.test_mocks import MockScumm6BinaryView


class ConditionalTestCase(TypedDict):
    name: str
    bytecode: bytes
    addr: int
    expected_length: int
    expected_true_branch: int
    expected_false_branch: int


class UnconditionalTestCase(TypedDict):
    name: str
    bytecode: bytes
    addr: int
    expected_length: int
    expected_unconditional_branch: int


def test_instruction_info_conditional_jumps() -> None:
    """Test that conditional jump instructions properly populate InstructionInfo."""
    
    # Test the unified Scumm6 architecture
    arch = Scumm6()
    
    view = MockScumm6BinaryView()
    LastBV.set(view)
    
    # Test case 1: unless goto +18 (if_not instruction with positive offset)
    # From room11_enter script: [0005] unless goto +18
    test_cases = [
        {
            "name": "unless_goto_positive",
            "bytecode": bytes([0x5D, 0x12, 0x00]),  # 0x5D = if_not, 0x0012 = +18
            "addr": 0x1005,
            "expected_length": 3,
            "expected_true_branch": 0x1005 + 3 + 18,  # addr + length + offset = 0x101A
            "expected_false_branch": 0x1005 + 3,      # addr + length = 0x1008
        },
        {
            "name": "unless_goto_negative",
            "bytecode": bytes([0x5D, 0x9E, 0xFF]),  # 0x5D = if_not, 0xFF9E = -98 (signed 16-bit)
            "addr": 0x1130,
            "expected_length": 3,
            "expected_true_branch": 0x1130 + 3 + (-98),  # addr + length + offset = 0x10D5
            "expected_false_branch": 0x1130 + 3,         # addr + length = 0x1133
        },
        {
            "name": "if_goto_positive",
            "bytecode": bytes([0x5C, 0x0A, 0x00]),  # 0x5C = if, 0x000A = +10
            "addr": 0x102B,
            "expected_length": 3,
            "expected_true_branch": 0x102B + 3 + 10,   # addr + length + offset = 0x1038
            "expected_false_branch": 0x102B + 3,       # addr + length = 0x102E
        },
        {
            "name": "unconditional_goto",
            "bytecode": bytes([0x73, 0x0A, 0x00]),  # 0x73 = jump, 0x000A = +10
            "addr": 0x10E8,
            "expected_length": 3,
            "expected_unconditional_branch": 0x10E8 + 3 + 10,  # addr + length + offset = 0x10F5
        }
    ]
    
    for case in test_cases:
        print(f"\n=== Testing {case['name']} ===")
        
        # Assert type to help mypy understand the union and extract values
        assert isinstance(case, dict)
        case_name = cast(str, case["name"])
        case_bytecode = cast(bytes, case["bytecode"])
        case_addr = cast(int, case["addr"])
        case_expected_length = cast(int, case["expected_length"])
        
        # Write bytecode to memory
        view.write_memory(case_addr, case_bytecode)
        
        # Test architecture
        info = arch.get_instruction_info(case_bytecode, case_addr)
        print(f"InstructionInfo: {info}")
        
        assert info is not None, f"Decoder returned None for {case_name}"
        
        # Extract branches
        branches = []
        if hasattr(info, 'branches') and info.branches:
            branches = [(b.type, b.target) for b in info.branches]
            print(f"Branches: {[(b.type, hex(b.target) if b.target is not None else None) for b in info.branches]}")
        elif hasattr(info, 'mybranches') and info.mybranches:
            branches = info.mybranches
            print(f"Mybranches: {[(b[0], hex(b[1]) if b[1] is not None else None) for b in info.mybranches]}")
        
        # Check instruction length
        assert info.length == case_expected_length, \
            f"Decoder wrong length for {case_name}: expected {case_expected_length}, got {info.length}"
        
        # Check branch information
        if "expected_unconditional_branch" in case:
            # Unconditional jump
            expected_unconditional_branch = cast(int, case["expected_unconditional_branch"])
            
            assert len(branches) == 1, f"Decoder should have 1 branch for {case_name}, got {len(branches)}"
            
            branch_type, branch_target = branches[0]
            
            assert branch_type == BranchType.UnconditionalBranch, f"Decoder wrong branch type for {case_name}"
            assert branch_target == expected_unconditional_branch, \
                f"Decoder wrong branch target for {case_name}: expected {hex(expected_unconditional_branch)}, got {hex(branch_target)}"
        else:
            # Conditional jump
            expected_true_branch = cast(int, case["expected_true_branch"])
            # expected_false_branch = cast(int, case["expected_false_branch"])  # FalseBranch is now implicit
            
            assert len(branches) == 1, f"Decoder should have 1 branch for {case_name}, got {len(branches)}"
            
            # Only TrueBranch should be present (FalseBranch is implicit)
            true_branch = None
            
            for branch_type, branch_target in branches:
                if branch_type == BranchType.TrueBranch:
                    true_branch = (branch_type, branch_target)
            
            assert true_branch is not None, f"Decoder missing TrueBranch for {case_name}"
            
            # Check branch target (only TrueBranch now)
            assert true_branch[1] == expected_true_branch, \
                f"Decoder wrong true branch target for {case_name}: expected {hex(expected_true_branch)}, got {hex(true_branch[1])}"
        
        print(f"✅ {case_name} passed all checks")


def test_instruction_info_real_script_data() -> None:
    """Test InstructionInfo with real script data from room11_enter."""
    
    # Real bytecode from room11_enter script (from our test framework)
    # [0000] push_word(137)          - 01 89 00
    # [0003] is_script_running       - 5A
    # [0004] nott                    - 50
    # [0005] unless goto +18         - 5D 12 00
    # [0008] push_word(93)           - 01 5D 00
    # [000B] push_word(1)            - 01 01 00
    # [000E] push_word(1)            - 01 01 00
    # [0011] start_script_quick(...) - 5F 01 01 01
    # [0012] push_word(0)            - 01 00 00
    # [0015] push_word(200)          - 01 C8 00
    # [0018] room_ops.room_screen    - 9C 02 02
    # [001A] stop_object_code1       - 65
    
    real_bytecode = bytes([
        0x01, 0x89, 0x00,  # [0000] push_word(137)
        0x5A,              # [0003] is_script_running
        0x50,              # [0004] nott
        0x5D, 0x12, 0x00,  # [0005] unless goto +18
        0x01, 0x5D, 0x00,  # [0008] push_word(93)
        0x01, 0x01, 0x00,  # [000B] push_word(1)
        0x01, 0x01, 0x00,  # [000E] push_word(1)
        0x5F, 0x01, 0x01, 0x01,  # [0011] start_script_quick(...) 
        0x01, 0x00, 0x00,  # [0012] push_word(0)
        0x01, 0xC8, 0x00,  # [0015] push_word(200)
        0x9C, 0x02, 0x02,  # [0018] room_ops.room_screen
        0x65               # [001A] stop_object_code1
    ])
    
    new_arch = Scumm6()
    view = MockScumm6BinaryView()
    view.write_memory(0x1000, real_bytecode)
    LastBV.set(view)
    
    # Test the conditional jump at offset 0x0005
    unless_goto_offset = 5
    unless_goto_bytecode = real_bytecode[unless_goto_offset:unless_goto_offset+3]
    unless_goto_addr = 0x1000 + unless_goto_offset
    
    info = new_arch.get_instruction_info(unless_goto_bytecode, unless_goto_addr)
    
    assert info is not None, "Failed to get InstructionInfo for unless goto"
    assert info.length == 3, f"Wrong instruction length: expected 3, got {info.length}"
    
    # Extract branches from available attributes
    branches = []
    if hasattr(info, 'branches') and info.branches:
        branches = [(b.type, b.target) for b in info.branches]
    elif hasattr(info, 'mybranches') and info.mybranches:
        branches = info.mybranches
    
    assert len(branches) == 1, f"Wrong number of branches: expected 1, got {len(branches)}"
    
    # Expected branches:
    # - True branch (condition is false): addr + length + offset = 0x1005 + 3 + 18 = 0x101A
    # - False branch (continue) is implicit for CFG analysis
    
    true_branch = None
    
    for branch_type, branch_target in branches:
        if branch_type == BranchType.TrueBranch:
            true_branch = (branch_type, branch_target)
    
    assert true_branch is not None, "Missing TrueBranch"
    
    expected_true_target = 0x1005 + 3 + 18  # 0x101A
    
    assert true_branch[1] == expected_true_target, \
        f"Wrong true branch target: expected {hex(expected_true_target)}, got {hex(true_branch[1])}"
    
    print("✅ Real script data test passed")

