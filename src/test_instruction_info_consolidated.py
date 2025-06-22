#!/usr/bin/env python3
"""
Consolidated test for InstructionInfo population in SCUMM6 architecture.

This test ensures that conditional jumps, unconditional jumps, and other
control flow instructions correctly populate the InstructionInfo with
proper branch targets and lengths.
"""

from typing import List, Tuple, TypedDict
from binaryninja.enums import BranchType

from .test_utils import setup_mock_scumm6_environment, collect_branches_from_architecture


class InstructionTestCase(TypedDict):
    """Test case for instruction info validation."""
    name: str
    bytecode: bytes
    addr: int
    expected_length: int
    expected_branches: List[Tuple[BranchType, int]]


def test_instruction_info_comprehensive() -> None:
    """Test that SCUMM6 architecture correctly populates InstructionInfo for various instruction types."""
    
    arch, view = setup_mock_scumm6_environment()
    
    test_cases: List[InstructionTestCase] = [
        # Conditional jumps - unless (if_not)
        {
            "name": "unless_goto_positive",
            "bytecode": bytes([0x5D, 0x12, 0x00]),  # unless goto +18
            "addr": 0x1005,
            "expected_length": 3,
            "expected_branches": [
                (BranchType.TrueBranch, 0x101A),     # 0x1005 + 3 + 18 (jump taken)
                # FalseBranch (fall-through) is implicit
            ]
        },
        {
            "name": "unless_goto_negative",
            "bytecode": bytes([0x5D, 0x9E, 0xFF]),  # unless goto -98 (signed 16-bit)
            "addr": 0x1130,
            "expected_length": 3,
            "expected_branches": [
                (BranchType.TrueBranch, 0x10D1),     # 0x1130 + 3 + (-98) = 0x10D1 (jump taken)
                # FalseBranch (fall-through) is implicit
            ]
        },
        
        # Conditional jumps - if
        {
            "name": "if_goto_positive",
            "bytecode": bytes([0x5C, 0x0A, 0x00]),  # if goto +10
            "addr": 0x102B,
            "expected_length": 3,
            "expected_branches": [
                (BranchType.TrueBranch, 0x1038),     # 0x102B + 3 + 10 (jump taken)
                # FalseBranch (fall-through) is implicit
            ]
        },
        
        # Unconditional jumps
        {
            "name": "unconditional_goto",
            "bytecode": bytes([0x73, 0x0A, 0x00]),  # goto +10
            "addr": 0x10E8,
            "expected_length": 3,
            "expected_branches": [
                (BranchType.UnconditionalBranch, 0x10F5),  # 0x10E8 + 3 + 10
            ]
        },
        
        # Non-control flow instructions
        {
            "name": "if_class_of_is",
            "bytecode": bytes([0x6D]),  # if_class_of_is (check object class - no branches)
            "addr": 0x1500,
            "expected_length": 1,
            "expected_branches": []  # if_class_of_is is not a control flow instruction
        },
        {
            "name": "push_byte",
            "bytecode": bytes([0x00, 0x05]),  # push_byte(5)
            "addr": 0x2000,
            "expected_length": 2,
            "expected_branches": []  # No control flow
        },
        {
            "name": "add_operation",
            "bytecode": bytes([0x14]),  # add
            "addr": 0x2100,
            "expected_length": 1,
            "expected_branches": []  # No control flow
        }
    ]
    
    for case in test_cases:
        print(f"\n=== Testing {case['name']} ===")
        
        # Write bytecode to memory
        view.write_memory(case["addr"], case["bytecode"])
        
        # Get InstructionInfo
        info = arch.get_instruction_info(case["bytecode"], case["addr"])
        
        assert info is not None, f"Failed to get InstructionInfo for {case['name']}"
        
        # Check instruction length
        assert info.length == case["expected_length"], \
            f"Wrong length for {case['name']}: expected {case['expected_length']}, got {info.length}"
        
        # Extract branches using the centralized function
        actual_branches = []
        if hasattr(info, 'branches') and info.branches:
            actual_branches = [(b.type, b.target) for b in info.branches]
        elif hasattr(info, 'mybranches') and info.mybranches:
            actual_branches = info.mybranches
        
        print(f"Actual branches: {[(bt, hex(target)) for bt, target in actual_branches]}")
        print(f"Expected branches: {[(bt, hex(target)) for bt, target in case['expected_branches']]}")
        
        # Verify branch count
        assert len(actual_branches) == len(case["expected_branches"]), \
            f"Wrong number of branches for {case['name']}: expected {len(case['expected_branches'])}, got {len(actual_branches)}"
        
        # Verify each branch
        for i, (actual_branch, expected_branch) in enumerate(zip(actual_branches, case["expected_branches"])):
            actual_type, actual_target = actual_branch
            expected_type, expected_target = expected_branch
            
            assert actual_type == expected_type, \
                f"Branch {i} type mismatch for {case['name']}: expected {expected_type}, got {actual_type}"
            
            assert actual_target == expected_target, \
                f"Branch {i} target mismatch for {case['name']}: expected 0x{expected_target:X}, got 0x{actual_target:X}"
        
        print(f"✓ {case['name']} passed all checks")


def test_branch_collection_utility() -> None:
    """Test the centralized branch collection utility function."""
    
    arch, _ = setup_mock_scumm6_environment()
    
    # Test with a sequence containing multiple branch instructions
    bytecode = bytes([
        0x5D, 0x05, 0x00,  # [0000] unless goto +5 -> branch to 0x0008
        0x73, 0x0A, 0x00,  # [0003] goto +10 -> branch to 0x0010  
        0x00, 0x05,        # [0006] push_byte(5) -> no branch
    ])
    
    start_addr = 0x2000
    branches = collect_branches_from_architecture(arch, bytecode, start_addr)
    
    expected_branches = [
        (0x0000, (BranchType.TrueBranch, 0x0008)),      # unless at offset 0
        (0x0003, (BranchType.UnconditionalBranch, 0x0010))  # goto at offset 3
    ]
    
    assert len(branches) == len(expected_branches), \
        f"Expected {len(expected_branches)} branches, got {len(branches)}"
    
    for i, (actual, expected) in enumerate(zip(branches, expected_branches)):
        actual_offset, (actual_type, actual_target) = actual
        expected_offset, (expected_type, expected_target) = expected
        
        assert actual_offset == expected_offset, \
            f"Branch {i} offset mismatch: expected {expected_offset}, got {actual_offset}"
        assert actual_type == expected_type, \
            f"Branch {i} type mismatch: expected {expected_type}, got {actual_type}"
        assert actual_target == expected_target, \
            f"Branch {i} target mismatch: expected 0x{expected_target:X}, got 0x{actual_target:X}"
    
    print("✓ Branch collection utility test passed")


if __name__ == "__main__":
    test_instruction_info_comprehensive()
    test_branch_collection_utility()
    print("\n✓ All instruction info tests passed!")