#!/usr/bin/env python3
"""
Simple test for InstructionInfo population in new SCUMM6 decoder.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import sys
import os
from typing import List, Tuple, TypedDict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binja_helpers import binja_api  # noqa: F401
from binaryninja.enums import BranchType

from src.scumm6 import Scumm6New, LastBV
from src.test_mocks import MockScumm6BinaryView


class InstructionTestCase(TypedDict):
    name: str
    bytecode: bytes
    addr: int
    expected_branches: List[Tuple[BranchType, int]]


def test_new_decoder_instruction_info() -> None:
    """Test that the new decoder correctly populates InstructionInfo."""
    
    arch = Scumm6New()
    view = MockScumm6BinaryView()
    LastBV.set(view)
    
    test_cases: List[InstructionTestCase] = [
        {
            "name": "unless_goto_positive",
            "bytecode": bytes([0x5D, 0x12, 0x00]),  # unless goto +18
            "addr": 0x1005,
            "expected_branches": [
                (BranchType.TrueBranch, 0x101A),     # 0x1005 + 3 + 18
                (BranchType.FalseBranch, 0x1008),    # 0x1005 + 3
            ]
        },
        {
            "name": "unconditional_goto",
            "bytecode": bytes([0x73, 0x0A, 0x00]),  # goto +10
            "addr": 0x10E8,
            "expected_branches": [
                (BranchType.UnconditionalBranch, 0x10F5),  # 0x10E8 + 3 + 10
            ]
        },
        {
            "name": "if_goto",
            "bytecode": bytes([0x5C, 0x0A, 0x00]),  # if goto +10
            "addr": 0x102B,
            "expected_branches": [
                (BranchType.TrueBranch, 0x1038),     # 0x102B + 3 + 10
                (BranchType.FalseBranch, 0x102E),    # 0x102B + 3
            ]
        }
    ]
    
    for case in test_cases:
        print(f"\n=== Testing {case['name']} ===")
        
        # Write bytecode to memory
        view.write_memory(case["addr"], case["bytecode"])
        
        # Get InstructionInfo
        info = arch.get_instruction_info(case["bytecode"], case["addr"])
        
        assert info is not None, f"Failed to get InstructionInfo for {case['name']}"
        assert info.length == 3, f"Wrong length for {case['name']}: expected 3, got {info.length}"
        
        # Extract branches
        branches = []
        if hasattr(info, 'branches') and info.branches:
            branches = [(b.type, b.target) for b in info.branches]
        elif hasattr(info, 'mybranches') and info.mybranches:
            branches = info.mybranches
        
        print(f"Actual branches: {[(bt, hex(target)) for bt, target in branches]}")
        print(f"Expected branches: {[(bt, hex(target)) for bt, target in case['expected_branches']]}")
        
        assert len(branches) == len(case["expected_branches"]), \
            f"Wrong number of branches for {case['name']}: expected {len(case['expected_branches'])}, got {len(branches)}"
        
        # Check each expected branch exists
        for expected_type, expected_target in case["expected_branches"]:
            found = False
            for actual_type, actual_target in branches:
                if actual_type == expected_type and actual_target == expected_target:
                    found = True
                    break
            
            assert found, \
                f"Missing branch for {case['name']}: expected ({expected_type}, {hex(expected_target)}), got {branches}"
        
        print(f"✅ {case['name']} passed all checks")


if __name__ == "__main__":
    test_new_decoder_instruction_info()
    print("\n🎉 All InstructionInfo tests passed!")