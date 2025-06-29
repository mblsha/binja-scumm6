#!/usr/bin/env python3
"""Declarative tests for variable write instruction fusion."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from dataclasses import dataclass
from typing import Optional, Callable, Any

import pytest
from binja_helpers import binja_api  # noqa: F401

from .pyscumm6.disasm import decode_with_fusion


@dataclass
class FusionTestCase:
    test_id: str
    bytecode: bytes
    expected_class: str
    expected_fused_operands: int
    expected_stack_pops: int
    expected_render_text: Optional[str] = None
    additional_validation: Optional[Callable[[Any], None]] = None
    addr: int = 0x1000


def run_fusion_test(case: FusionTestCase) -> None:
    instr = decode_with_fusion(case.bytecode, case.addr)
    assert instr is not None, f"Failed to decode {case.test_id}"
    assert instr.__class__.__name__ == case.expected_class
    assert len(instr.fused_operands) == case.expected_fused_operands
    assert instr.stack_pop_count == case.expected_stack_pops
    tokens = instr.render()
    token_text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    if case.expected_render_text is not None:
        assert token_text == case.expected_render_text
    if case.additional_validation:
        case.additional_validation(instr)


fusion_test_cases = [
    FusionTestCase(
        test_id="write_byte_const",
        bytecode=bytes([0x00, 0x05, 0x42, 0x0A]),
        expected_class="WriteByteVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="var_? = 5",
    ),
    FusionTestCase(
        test_id="write_word_const",
        bytecode=bytes([0x01, 0xE8, 0x03, 0x43, 0x14, 0x00]),
        expected_class="WriteWordVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="VAR_VIRT_MOUSE_X = 1000",  # VAR_VIRT_MOUSE_X = 20, now shows semantic names
    ),
    FusionTestCase(
        test_id="write_from_var",
        bytecode=bytes([0x02, 0x05, 0x42, 0x0A]),
        expected_class="WriteByteVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="var_? = var5",  # VAR_OVERRIDE = 5, but assignments use raw names
    ),
    FusionTestCase(
        test_id="word_from_byte",
        bytecode=bytes([0x00, 0x64, 0x43, 0x1E, 0x00]),
        expected_class="WriteWordVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="VAR_EXIT_SCRIPT = 100",  # VAR_EXIT_SCRIPT = 30, now shows semantic names
    ),
    FusionTestCase(
        test_id="no_fusion_non_push",
        bytecode=bytes([0x0C, 0x42, 0x0A]),
        expected_class="WriteByteVar",
        expected_fused_operands=0,
        expected_stack_pops=1,
        expected_render_text="write_byte_var(var_?)",
    ),
    FusionTestCase(
        test_id="negative_value",
        bytecode=bytes([0x00, 0xFB, 0x42, 0x0F]),
        expected_class="WriteByteVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="var_? = -5",
    ),
    FusionTestCase(
        test_id="zero_value",
        bytecode=bytes([0x00, 0x00, 0x42, 0x63]),
        expected_class="WriteByteVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="var_? = 0",
    ),
    FusionTestCase(
        test_id="max_word",
        bytecode=bytes([0x01, 0xFF, 0xFF, 0x43, 0xFF, 0x00]),
        expected_class="WriteWordVar",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="var255 = -1",
    ),
]


@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_variable_write_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)
