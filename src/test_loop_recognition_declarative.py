#!/usr/bin/env python3
"""
Declarative testing framework for loop pattern recognition.

This module demonstrates how to apply the declarative testing pattern
to loop recognition tests, converting imperative test functions into
data-driven test cases.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from dataclasses import dataclass
from typing import List, Optional
import pytest
from binja_helpers import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode_with_fusion
from src.pyscumm6.instr.smart_bases import SmartLoopConditionalJump


@dataclass
class LoopRecognitionTestCase:
    """Declarative test case for loop pattern recognition."""
    test_id: str
    bytecode: bytes
    expected_loop_detected: bool
    expected_loop_type: Optional[str] = None  # "while", "for", "do-while"
    expected_smart_class: Optional[str] = None  # "SmartLoopIfNot", "SmartLoopIf"
    expected_condition_variable: Optional[str] = None
    expected_limit_value: Optional[int] = None
    expected_render_contains: Optional[List[str]] = None
    addr: int = 0x1000
    description: Optional[str] = None


@dataclass
class LoopBodyTestCase:
    """Test case for loop body analysis."""
    test_id: str
    bytecode: bytes
    expected_body_size: int
    expected_body_instructions: List[str]
    expected_loop_variable_updates: List[str]
    addr: int = 0x1000
    description: Optional[str] = None


def run_loop_recognition_test(case: LoopRecognitionTestCase) -> None:
    """
    Executes a single loop recognition test case and asserts its correctness.
    
    This function encapsulates the "how" of testing loop recognition,
    while the test data represents the "what" to test.
    """
    # Test fusion with loop detection
    fused = decode_with_fusion(case.bytecode, case.addr)
    
    if case.expected_loop_detected:
        assert fused is not None, f"Fusion decoding failed for {case.test_id}"
        assert isinstance(fused, SmartLoopConditionalJump), \
            f"Expected SmartLoopConditionalJump, got {type(fused)} for {case.test_id}"
        
        if case.expected_smart_class:
            assert fused.__class__.__name__ == case.expected_smart_class, \
                f"Expected {case.expected_smart_class}, got {fused.__class__.__name__} for {case.test_id}"
        
        # Verify loop detection worked
        assert fused.detected_loop is not None, f"No loop detected for {case.test_id}"
        
        if case.expected_loop_type:
            assert fused.detected_loop.loop_type == case.expected_loop_type, \
                f"Expected loop type '{case.expected_loop_type}', got '{fused.detected_loop.loop_type}' for {case.test_id}"
        
        # Test rendering
        tokens = fused.render()
        text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
        
        if case.expected_render_contains:
            for expected_text in case.expected_render_contains:
                assert expected_text in text, \
                    f"Expected '{expected_text}' in render output, got '{text}' for {case.test_id}"
        
        if case.expected_condition_variable:
            assert case.expected_condition_variable in text, \
                f"Expected condition variable '{case.expected_condition_variable}' in output for {case.test_id}"
        
        if case.expected_limit_value is not None:
            assert str(case.expected_limit_value) in text, \
                f"Expected limit value '{case.expected_limit_value}' in output for {case.test_id}"
    
    else:
        # Negative test case - loop should NOT be detected
        if fused is not None:
            assert not isinstance(fused, SmartLoopConditionalJump), \
                f"Unexpected loop detection for {case.test_id}"


def run_loop_body_test(case: LoopBodyTestCase) -> None:
    """Execute loop body analysis test case."""
    fused = decode_with_fusion(case.bytecode, case.addr)
    
    assert fused is not None, f"Fusion decoding failed for {case.test_id}"
    assert isinstance(fused, SmartLoopConditionalJump), \
        f"Expected SmartLoopConditionalJump for {case.test_id}"
    
    loop_info = fused.detected_loop
    assert loop_info is not None, f"No loop detected for {case.test_id}"
    
    # Check body size
    if hasattr(loop_info, 'body_size'):
        body_size = getattr(loop_info, 'body_size')
        assert body_size == case.expected_body_size, \
            f"Expected body size {case.expected_body_size}, got {body_size} for {case.test_id}"
    
    # Check body instructions
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    
    for expected_instr in case.expected_body_instructions:
        assert expected_instr in text, \
            f"Expected instruction '{expected_instr}' in body for {case.test_id}"


# ============================================================================
# LOOP RECOGNITION TEST CASES
# ============================================================================

loop_recognition_cases = [
    LoopRecognitionTestCase(
        test_id="simple_backward_jump",
        bytecode=bytes([
            0x02, 0x0C,        # push_byte_var(var_12)
            0x5D, 0x9E, 0xFF   # unless goto -98 (backward jump - loop!)
        ]),
        expected_loop_detected=True,
        expected_smart_class="SmartLoopIfNot",
        expected_loop_type="while",
        expected_condition_variable="var_12",
        expected_render_contains=["while", "var_12"],
        description="Basic backward jump detection"
    ),
    
    LoopRecognitionTestCase(
        test_id="for_loop_pattern",
        bytecode=bytes([
            0x02, 0x05,        # push_byte_var(var_5) - iterator
            0x00, 0x0A,        # push_byte(10)         - limit
            0x11,              # lt                    - comparison
            0x5D, 0xEC, 0xFF   # unless goto -20 (backward jump)
        ]),
        expected_loop_detected=True,
        expected_smart_class="SmartLoopIfNot",
        expected_loop_type="for",
        expected_condition_variable="var_5",
        expected_limit_value=10,
        expected_render_contains=["for", "var_5", "10"],
        description="For-loop pattern with variable < constant"
    ),
    
    LoopRecognitionTestCase(
        test_id="while_loop_with_complex_condition",
        bytecode=bytes([
            0x02, 0x08,        # push_byte_var(var_8)
            0x02, 0x09,        # push_byte_var(var_9)
            0x14,              # add
            0x00, 0x64,        # push_byte(100)
            0x11,              # lt
            0x5D, 0xE8, 0xFF   # unless goto -24
        ]),
        expected_loop_detected=True,
        expected_smart_class="SmartLoopIfNot",
        expected_loop_type="while",
        expected_render_contains=["while", "var_8", "var_9", "100"],
        description="While loop with complex condition (var_8 + var_9 < 100)"
    ),
    
    LoopRecognitionTestCase(
        test_id="do_while_pattern",
        bytecode=bytes([
            0x02, 0x0A,        # push_byte_var(var_10)
            0x00, 0x00,        # push_byte(0)
            0x10,              # gt
            0x5C, 0xF4, 0xFF   # if goto -12 (backward jump after body)
        ]),
        expected_loop_detected=True,
        expected_smart_class="SmartLoopIf",
        expected_loop_type="do-while",
        expected_condition_variable="var_10",
        expected_render_contains=["do", "while", "var_10"],
        description="Do-while pattern with condition at end"
    ),
    
    LoopRecognitionTestCase(
        test_id="nested_loop_outer",
        bytecode=bytes([
            0x02, 0x01,        # push_byte_var(var_1) - outer loop variable
            0x00, 0x05,        # push_byte(5)         - outer limit
            0x11,              # lt
            0x5D, 0x20, 0x00   # unless goto +32 (forward jump - exit outer loop)
        ]),
        expected_loop_detected=False,  # Forward jump, not a loop
        description="Nested loop outer condition (forward jump, not loop)"
    ),
]

# ============================================================================
# NEGATIVE TEST CASES (NO LOOP EXPECTED)
# ============================================================================

no_loop_cases = [
    LoopRecognitionTestCase(
        test_id="forward_jump_only",
        bytecode=bytes([
            0x02, 0x05,        # push_byte_var(var_5)
            0x5D, 0x10, 0x00   # unless goto +16 (forward jump - not a loop)
        ]),
        expected_loop_detected=False,
        description="Forward jump should not be detected as loop"
    ),
    
    LoopRecognitionTestCase(
        test_id="simple_conditional_no_jump",
        bytecode=bytes([
            0x02, 0x05,        # push_byte_var(var_5)
            0x00, 0x0A,        # push_byte(10)
            0x11               # lt (no jump instruction)
        ]),
        expected_loop_detected=False,
        description="Comparison without jump should not be loop"
    ),
    
    LoopRecognitionTestCase(
        test_id="unconditional_backward_jump",
        bytecode=bytes([
            0x73, 0xF0, 0xFF   # goto -16 (unconditional backward jump)
        ]),
        expected_loop_detected=False,
        description="Unconditional backward jump is infinite loop, not pattern"
    ),
]

# ============================================================================
# LOOP BODY ANALYSIS TEST CASES
# ============================================================================

loop_body_cases = [
    LoopBodyTestCase(
        test_id="simple_increment_body",
        bytecode=bytes([
            # Loop condition
            0x02, 0x05,        # push_byte_var(var_5)
            0x00, 0x0A,        # push_byte(10)
            0x11,              # lt
            0x5D, 0x0C, 0x00,  # unless goto +12 (exit loop)
            
            # Loop body
            0x02, 0x05,        # push_byte_var(var_5)
            0x00, 0x01,        # push_byte(1)
            0x14,              # add
            0x43, 0x05, 0x00,  # write_word_var(var_5) - increment
            
            # Back to condition
            0x73, 0xF0, 0xFF   # goto -16 (back to condition)
        ]),
        expected_body_size=7,  # Instructions between condition and back-jump
        expected_body_instructions=["var_5", "add", "write_word_var"],
        expected_loop_variable_updates=["var_5"],
        description="Simple for-loop with increment in body"
    ),
]

# ============================================================================
# PARAMETRIZED TESTS
# ============================================================================

@pytest.mark.parametrize("case", loop_recognition_cases, ids=lambda c: c.test_id)
def test_loop_pattern_recognition(case: LoopRecognitionTestCase) -> None:
    """Test loop pattern recognition for various loop types."""
    run_loop_recognition_test(case)


@pytest.mark.parametrize("case", no_loop_cases, ids=lambda c: c.test_id)
def test_no_loop_detection(case: LoopRecognitionTestCase) -> None:
    """Test scenarios where loops should NOT be detected."""
    run_loop_recognition_test(case)


@pytest.mark.parametrize("case", loop_body_cases, ids=lambda c: c.test_id)
def test_loop_body_analysis(case: LoopBodyTestCase) -> None:
    """Test loop body analysis and variable tracking."""
    run_loop_body_test(case)


# ============================================================================
# COMPREHENSIVE TEST SUITE VALIDATION
# ============================================================================

def test_loop_recognition_coverage() -> None:
    """
    Verify comprehensive coverage of loop recognition scenarios.
    
    This meta-test ensures we have adequate coverage across different
    loop types and edge cases.
    """
    total_cases = len(loop_recognition_cases) + len(no_loop_cases) + len(loop_body_cases)
    assert total_cases >= 8, f"Expected at least 8 test cases, got {total_cases}"
    
    # Check that we have both positive and negative test cases
    positive_cases = len([c for c in loop_recognition_cases if c.expected_loop_detected])
    negative_cases = len([c for c in loop_recognition_cases if not c.expected_loop_detected]) + len(no_loop_cases)
    
    assert positive_cases >= 3, f"Expected at least 3 positive test cases, got {positive_cases}"
    assert negative_cases >= 3, f"Expected at least 3 negative test cases, got {negative_cases}"
    
    # Check coverage of different loop types
    loop_types = set()
    for case in loop_recognition_cases:
        if case.expected_loop_type:
            loop_types.add(case.expected_loop_type)
    
    expected_types = {"while", "for", "do-while"}
    assert loop_types >= expected_types, f"Missing loop types: {expected_types - loop_types}"
    
    print(f"✅ Loop recognition coverage verified: {total_cases} test cases")
    print(f"   - Positive cases: {positive_cases}")
    print(f"   - Negative cases: {negative_cases}")
    print(f"   - Loop types covered: {sorted(loop_types)}")


if __name__ == "__main__":
    pytest.main([__file__])
