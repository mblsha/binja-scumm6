#!/usr/bin/env python3
"""
Declarative testing framework for InstructionInfo validation.

This module demonstrates the migration from TypedDict to dataclass
for instruction info tests, providing a more consistent and extensible
approach aligned with the project's declarative testing standards.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import pytest
from binja_helpers import binja_api  # noqa: F401
from binaryninja.enums import BranchType

from src.test_utils import setup_mock_scumm6_environment


@dataclass
class InstructionInfoTestCase:
    """Declarative test case for instruction info validation."""
    test_id: str
    bytecode: bytes
    addr: int
    expected_length: int
    expected_branches: List[Tuple[BranchType, int]]
    description: Optional[str] = None
    category: str = "general"


@dataclass
class BranchAnalysisTestCase(InstructionInfoTestCase):
    """Specialized test case for branch analysis."""
    expected_branches: List[Tuple[BranchType, int]] = field(default_factory=list)
    expected_true_branch: Optional[int] = None
    expected_false_branch: Optional[int] = None
    expected_unconditional_branch: Optional[int] = None
    is_conditional: bool = True
    
    def __post_init__(self) -> None:
        """Convert specialized fields to standard branch format."""
        self.expected_branches = []
        
        if self.expected_unconditional_branch is not None:
            self.expected_branches.append((BranchType.UnconditionalBranch, self.expected_unconditional_branch))
            self.is_conditional = False
        
        if self.expected_true_branch is not None:
            self.expected_branches.append((BranchType.TrueBranch, self.expected_true_branch))
        
        # Note: FalseBranch is typically implicit (fall-through)
        if self.expected_false_branch is not None:
            self.expected_branches.append((BranchType.FalseBranch, self.expected_false_branch))


def run_instruction_info_test(case: InstructionInfoTestCase) -> None:
    """
    Executes a single instruction info test case and asserts its correctness.
    
    This function encapsulates the "how" of testing instruction info,
    while the test data represents the "what" to test.
    """
    arch, view = setup_mock_scumm6_environment()
    
    # Write bytecode to memory
    view.write_memory(case.addr, case.bytecode)
    
    # Get InstructionInfo
    info = arch.get_instruction_info(case.bytecode, case.addr)
    
    assert info is not None, f"Failed to get InstructionInfo for {case.test_id}"
    
    # Check instruction length
    assert info.length == case.expected_length, \
        f"Wrong length for {case.test_id}: expected {case.expected_length}, got {info.length}"
    
    # Extract branches
    actual_branches = []
    if hasattr(info, 'branches') and info.branches:
        actual_branches = [(b.type, b.target) for b in info.branches]
    elif hasattr(info, 'mybranches') and info.mybranches:
        actual_branches = info.mybranches
    
    # Verify branch count
    assert len(actual_branches) == len(case.expected_branches), \
        f"Wrong number of branches for {case.test_id}: expected {len(case.expected_branches)}, got {len(actual_branches)}"
    
    # Verify each branch
    for i, (actual_branch, expected_branch) in enumerate(zip(actual_branches, case.expected_branches)):
        actual_type, actual_target = actual_branch
        expected_type, expected_target = expected_branch
        
        assert actual_type == expected_type, \
            f"Branch {i} type mismatch for {case.test_id}: expected {expected_type}, got {actual_type}"
        
        assert actual_target == expected_target, \
            f"Branch {i} target mismatch for {case.test_id}: expected 0x{expected_target:X}, got 0x{actual_target:X}"


# ============================================================================
# CONDITIONAL JUMP TEST CASES
# ============================================================================

conditional_jump_cases = [
    BranchAnalysisTestCase(
        test_id="unless_goto_positive",
        bytecode=bytes([0x5D, 0x12, 0x00]),  # unless goto +18
        addr=0x1005,
        expected_length=3,
        expected_true_branch=0x101A,  # 0x1005 + 3 + 18 (jump taken)
        description="Conditional jump with positive offset"
    ),
    
    BranchAnalysisTestCase(
        test_id="unless_goto_negative",
        bytecode=bytes([0x5D, 0x9E, 0xFF]),  # unless goto -98 (signed 16-bit)
        addr=0x1130,
        expected_length=3,
        expected_true_branch=0x10D1,  # 0x1130 + 3 + (-98) = 0x10D1 (jump taken)
        description="Conditional jump with negative offset (loop back)"
    ),
    
    BranchAnalysisTestCase(
        test_id="if_goto_positive",
        bytecode=bytes([0x5C, 0x0A, 0x00]),  # if goto +10
        addr=0x102B,
        expected_length=3,
        expected_true_branch=0x1038,  # 0x102B + 3 + 10 (jump taken)
        description="If-conditional jump with positive offset"
    ),
    
    BranchAnalysisTestCase(
        test_id="if_goto_short_jump",
        bytecode=bytes([0x5C, 0x05, 0x00]),  # if goto +5
        addr=0x2000,
        expected_length=3,
        expected_true_branch=0x2008,  # 0x2000 + 3 + 5
        description="Short conditional jump"
    ),
]

# ============================================================================
# UNCONDITIONAL JUMP TEST CASES
# ============================================================================

unconditional_jump_cases = [
    BranchAnalysisTestCase(
        test_id="unconditional_goto",
        bytecode=bytes([0x73, 0x0A, 0x00]),  # goto +10
        addr=0x10E8,
        expected_length=3,
        expected_unconditional_branch=0x10F5,  # 0x10E8 + 3 + 10
        is_conditional=False,
        description="Unconditional forward jump"
    ),
    
    BranchAnalysisTestCase(
        test_id="unconditional_goto_backward",
        bytecode=bytes([0x73, 0xF0, 0xFF]),  # goto -16
        addr=0x1100,
        expected_length=3,
        expected_unconditional_branch=0x10F3,  # 0x1100 + 3 + (-16)
        is_conditional=False,
        description="Unconditional backward jump (infinite loop)"
    ),
    
    BranchAnalysisTestCase(
        test_id="unconditional_goto_zero",
        bytecode=bytes([0x73, 0x00, 0x00]),  # goto +0 (infinite loop)
        addr=0x1200,
        expected_length=3,
        expected_unconditional_branch=0x1203,  # 0x1200 + 3 + 0
        is_conditional=False,
        description="Zero-offset unconditional jump (tight loop)"
    ),
]

# ============================================================================
# NON-CONTROL FLOW INSTRUCTION TEST CASES
# ============================================================================

non_control_flow_cases = [
    InstructionInfoTestCase(
        test_id="if_class_of_is",
        bytecode=bytes([0x6D]),  # if_class_of_is (check object class - no branches)
        addr=0x1500,
        expected_length=1,
        expected_branches=[],  # if_class_of_is is not a control flow instruction
        description="Intrinsic instruction with no control flow",
        category="intrinsic"
    ),
    
    InstructionInfoTestCase(
        test_id="push_byte",
        bytecode=bytes([0x00, 0x05]),  # push_byte(5)
        addr=0x2000,
        expected_length=2,
        expected_branches=[],  # No control flow
        description="Stack operation with no control flow",
        category="stack"
    ),
    
    InstructionInfoTestCase(
        test_id="add_operation",
        bytecode=bytes([0x14]),  # add
        addr=0x2100,
        expected_length=1,
        expected_branches=[],  # No control flow
        description="Arithmetic operation with no control flow",
        category="arithmetic"
    ),
    
    InstructionInfoTestCase(
        test_id="write_word_var",
        bytecode=bytes([0x43, 0x0A, 0x00]),  # write_word_var(var_10)
        addr=0x3000,
        expected_length=3,
        expected_branches=[],  # No control flow
        description="Variable write with no control flow",
        category="variable"
    ),
    
    InstructionInfoTestCase(
        test_id="complex_intrinsic",
        bytecode=bytes([0xB6]),  # printDebug.begin() - complex intrinsic
        addr=0x4000,
        expected_length=1,
        expected_branches=[],  # No control flow
        description="Complex intrinsic with no control flow",
        category="intrinsic"
    ),
]

# ============================================================================
# EDGE CASE TEST CASES
# ============================================================================

edge_case_tests = [
    InstructionInfoTestCase(
        test_id="maximum_positive_jump",
        bytecode=bytes([0x5D, 0xFF, 0x7F]),  # unless goto +32767 (max positive 16-bit)
        addr=0x1000,
        expected_length=3,
        expected_branches=[(BranchType.TrueBranch, 0x1000 + 3 + 32767)],
        description="Maximum positive jump offset",
        category="edge_case"
    ),
    
    InstructionInfoTestCase(
        test_id="maximum_negative_jump",
        bytecode=bytes([0x5D, 0x00, 0x80]),  # unless goto -32768 (max negative 16-bit)
        addr=0x9000,
        expected_length=3,
        expected_branches=[(BranchType.TrueBranch, 0x9000 + 3 - 32768)],
        description="Maximum negative jump offset",
        category="edge_case"
    ),
    
    InstructionInfoTestCase(
        test_id="single_byte_instruction",
        bytecode=bytes([0x0C]),  # dup
        addr=0x5000,
        expected_length=1,
        expected_branches=[],
        description="Single-byte instruction",
        category="edge_case"
    ),
]

# ============================================================================
# PARAMETRIZED TESTS
# ============================================================================

@pytest.mark.parametrize("case", conditional_jump_cases, ids=lambda c: c.test_id)
def test_conditional_jumps(case: BranchAnalysisTestCase) -> None:
    """Test conditional jump instruction info."""
    run_instruction_info_test(case)


@pytest.mark.parametrize("case", unconditional_jump_cases, ids=lambda c: c.test_id)
def test_unconditional_jumps(case: BranchAnalysisTestCase) -> None:
    """Test unconditional jump instruction info."""
    run_instruction_info_test(case)


@pytest.mark.parametrize("case", non_control_flow_cases, ids=lambda c: c.test_id)
def test_non_control_flow_instructions(case: InstructionInfoTestCase) -> None:
    """Test non-control flow instruction info."""
    run_instruction_info_test(case)


@pytest.mark.parametrize("case", edge_case_tests, ids=lambda c: c.test_id)
def test_edge_cases(case: InstructionInfoTestCase) -> None:
    """Test edge case scenarios for instruction info."""
    run_instruction_info_test(case)


# ============================================================================
# COMPREHENSIVE VALIDATION
# ============================================================================

def test_instruction_info_coverage() -> None:
    """
    Verify comprehensive coverage of instruction info scenarios.
    
    This meta-test ensures we have adequate coverage across different
    instruction types and control flow patterns.
    """
    all_cases = (
        conditional_jump_cases + 
        unconditional_jump_cases + 
        non_control_flow_cases + 
        edge_case_tests
    )
    
    total_cases = len(all_cases)
    assert total_cases >= 12, f"Expected at least 12 test cases, got {total_cases}"
    
    # Check coverage by category
    categories = set()
    control_flow_cases = 0
    non_control_flow_count = 0
    
    for case in all_cases:
        if hasattr(case, 'category'):
            categories.add(case.category)
        
        if case.expected_branches:
            control_flow_cases += 1
        else:
            non_control_flow_count += 1
    
    assert control_flow_cases >= 5, f"Expected at least 5 control flow test cases, got {control_flow_cases}"
    assert non_control_flow_count >= 5, f"Expected at least 5 non-control flow test cases, got {non_control_flow_count}"
    
    # Check that we have both conditional and unconditional branches
    conditional_count = len(conditional_jump_cases)
    unconditional_count = len(unconditional_jump_cases)
    
    assert conditional_count >= 3, f"Expected at least 3 conditional jump cases, got {conditional_count}"
    assert unconditional_count >= 2, f"Expected at least 2 unconditional jump cases, got {unconditional_count}"
    
    print(f"✅ Instruction info coverage verified: {total_cases} test cases")
    print(f"   - Control flow cases: {control_flow_cases}")
    print(f"   - Non-control flow cases: {non_control_flow_count}")
    print(f"   - Categories covered: {sorted(categories)}")


def test_branch_calculation_accuracy() -> None:
    """
    Test the accuracy of branch target calculations.
    
    This test verifies that our expected branch targets are calculated
    correctly according to SCUMM6 addressing semantics.
    """
    # Test a known case with manual calculation
    addr = 0x1005
    offset = 18  # +18
    expected_target = addr + 3 + offset  # instruction_addr + instruction_length + offset
    
    case = InstructionInfoTestCase(
        test_id="manual_calculation_test",
        bytecode=bytes([0x5D, 0x12, 0x00]),  # unless goto +18
        addr=addr,
        expected_length=3,
        expected_branches=[(BranchType.TrueBranch, expected_target)]
    )
    
    run_instruction_info_test(case)
    
    # Verify our calculation matches the expected result
    assert expected_target == 0x101A, f"Manual calculation error: expected 0x101A, got 0x{expected_target:X}"
    
    print(f"✅ Branch calculation verified: 0x{addr:X} + 3 + {offset} = 0x{expected_target:X}")


if __name__ == "__main__":
    pytest.main([__file__])

# Type checking issues resolved
