"""Test loop pattern recognition on real-world SCUMM6 bytecode patterns."""

import os
from dataclasses import dataclass, field
from typing import List, Optional

import pytest

os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode, decode_with_fusion
from src.pyscumm6.instr.smart_bases import SmartLoopConditionalJump


@dataclass
class LoopPatternTestCase:
    """Container for a single loop pattern test."""

    test_id: str
    bytecode: bytes
    start_addr: int
    expected_class_name: str
    loop_type: Optional[str] = None
    body_size: Optional[int] = None
    iterator_var: Optional[int] = None
    contains_text: List[str] = field(default_factory=list)
    not_contains_text: List[str] = field(default_factory=list)
    check_normal_class: Optional[str] = None
    compare_raw_output: bool = False


loop_test_cases = [
    LoopPatternTestCase(
        test_id="room8_scrp18_loop_pattern",
        bytecode=bytes([
            0x03,
            0x0C,
            0x00,
            0x5D,
            0x9E,
            0xFF,
        ]),
        start_addr=0x2130,
        expected_class_name="SmartLoopIfNot",
        loop_type="while",
        body_size=92,
        contains_text=["while", "!var_12", "92 bytes"],
        check_normal_class="PushWordVar",
    ),
    LoopPatternTestCase(
        test_id="room8_local200_scaling_loop",
        bytecode=bytes([
            0x03,
            0x00,
            0x00,
            0x01,
            0xFF,
            0x00,
            0x0E,
            0x5D,
            0xB9,
            0xFF,
        ]),
        start_addr=0x20A9,
        expected_class_name="SmartLoopIfNot",
        loop_type="while",
        iterator_var=0,
        contains_text=["while", "var_0"],
    ),
    LoopPatternTestCase(
        test_id="multiple_backward_jumps_pattern",
        bytecode=bytes([
            0x02,
            0x05,
            0x5D,
            0xF9,
            0xFF,
        ]),
        start_addr=0x1026,
        expected_class_name="SmartLoopIfNot",
        loop_type="while",
        body_size=2,
        contains_text=["while", "2 bytes"],
    ),
    LoopPatternTestCase(
        test_id="complex_loop_with_nested_jumps",
        bytecode=bytes([
            0x02,
            0x08,
            0x00,
            0x0A,
            0x11,
            0x5D,
            0xA3,
            0xFF,
        ]),
        start_addr=0x234A,
        expected_class_name="SmartLoopIfNot",
        loop_type="for",
        body_size=85,
        iterator_var=8,
        contains_text=["for", "var_8", "< 10"],
    ),
    LoopPatternTestCase(
        test_id="iff_loop_pattern",
        bytecode=bytes([
            0x02,
            0x03,
            0x00,
            0x00,
            0x0F,
            0x5C,
            0xF8,
            0xFF,
        ]),
        start_addr=0x1000,
        expected_class_name="SmartLoopIff",
        loop_type="while",
        contains_text=["while", "var_3"],
    ),
    LoopPatternTestCase(
        test_id="no_loop_detection_for_regular_conditionals",
        bytecode=bytes([
            0x02,
            0x05,
            0x00,
            0x0A,
            0x10,
            0x5D,
            0x20,
            0x00,
        ]),
        start_addr=0x1000,
        expected_class_name="SmartIfNot",
        contains_text=["if"],
        not_contains_text=["while", "for"],
    ),
    LoopPatternTestCase(
        test_id="descumm_style_output_comparison",
        bytecode=bytes([
            0x02,
            0x0C,
            0x5D,
            0x9E,
            0xFF,
        ]),
        start_addr=0x1000,
        expected_class_name="SmartLoopIfNot",
        loop_type="while",
        contains_text=["while (!var_12)", "bytes"],
        compare_raw_output=True,
    ),
]


@pytest.mark.parametrize("case", loop_test_cases, ids=lambda c: c.test_id)
def test_loop_pattern(case: LoopPatternTestCase) -> None:
    """Run loop pattern test defined in :data:`loop_test_cases`."""

    if case.check_normal_class is not None:
        normal = decode(case.bytecode, case.start_addr)
        assert normal is not None
        assert normal.__class__.__name__ == case.check_normal_class

    fused = decode_with_fusion(case.bytecode, case.start_addr)
    assert fused is not None
    assert fused.__class__.__name__ == case.expected_class_name

    if case.loop_type is not None:
        assert isinstance(fused, SmartLoopConditionalJump)
        assert fused.detected_loop is not None
        assert fused.detected_loop.loop_type == case.loop_type
        if case.body_size is not None:
            body_size = fused.detected_loop.body_end - fused.detected_loop.body_start
            assert body_size == case.body_size
        if case.iterator_var is not None:
            assert fused.detected_loop.iterator_var == case.iterator_var
    else:
        assert not hasattr(fused, "detected_loop") or fused.detected_loop is None

    tokens = fused.render()
    text = "".join(str(t.text if hasattr(t, "text") else t) for t in tokens)
    for item in case.contains_text:
        assert item in text
    for item in case.not_contains_text:
        assert item not in text

    if case.compare_raw_output:
        normal = decode(case.bytecode, case.start_addr)
        assert normal is not None
        raw_tokens = normal.render()
        raw_text = "".join(str(t.text if hasattr(t, "text") else t) for t in raw_tokens)
        assert len(text) > len(raw_text)
        print(f"Raw output: {raw_text}")
        print(f"Loop output: {text}")

