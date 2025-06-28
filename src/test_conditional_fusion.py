#!/usr/bin/env python3
"""Declarative tests for conditional instruction fusion."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from dataclasses import dataclass
from typing import Optional, Callable, Any

import pytest
from binja_helpers import binja_api  # noqa: F401

from .pyscumm6.disasm import decode, decode_with_fusion


@dataclass
class FusionTestCase:
    test_id: str
    bytecode: bytes
    expected_class: str
    expected_fused_operands: int
    expected_stack_pops: int
    expected_render_text: Optional[str]
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
    if case.expected_render_text:
        assert case.expected_render_text in token_text
    if case.additional_validation:
        case.additional_validation(instr)


def check_normal_decode(bytecode: bytes, expected: str) -> Callable[[Any], None]:
    def _check(_: Any) -> None:
        normal = decode(bytecode, 0x1000)
        assert normal.__class__.__name__ == expected
    return _check


fusion_test_cases = [
    FusionTestCase(
        test_id="comparison_constants",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x05, 0x10]),
        expected_class="Gt",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="10 > 5",
        additional_validation=check_normal_decode(bytes([0x00, 0x0A, 0x00, 0x05, 0x10]), "PushByte"),
    ),
    FusionTestCase(
        test_id="comparison_variables",
        bytecode=bytes([0x02, 0x0A, 0x00, 0x14, 0x11]),
        expected_class="Lt",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="VAR_CURRENTDRIVE < 20",
    ),
    FusionTestCase(
        test_id="if_not_jump",
        bytecode=bytes([0x02, 0x05, 0x00, 0x0A, 0x10, 0x5D, 0x14, 0x00]),
        expected_class="SmartIfNot",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="if ((VAR_OVERRIDE > 10)) jump",
    ),
    FusionTestCase(
        test_id="iff_jump",
        bytecode=bytes([0x00, 0x32, 0x02, 0x0F, 0x0E, 0x5C, 0x0C, 0x00]),
        expected_class="SmartIff",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="50 == VAR_ACTOR_RANGE_MIN",
    ),
    FusionTestCase(
        test_id="partial_comparison",
        bytecode=bytes([0x00, 0x0F, 0x10]),
        expected_class="Gt",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="gt(15)",
    ),
    FusionTestCase(
        test_id="neq_conditional",
        bytecode=bytes([0x00, 0x00, 0x02, 0x03, 0x0F, 0x5D, 0x08, 0x00]),
        expected_class="SmartIfNot",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="if ((0 != VAR_HAVE_MSG)) jump",
    ),
    FusionTestCase(
        test_id="le_ge",
        bytecode=bytes([0x02, 0x08, 0x00, 0x64, 0x12]),
        expected_class="Le",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="VAR_NUM_ACTOR <= 100",
    ),
    FusionTestCase(
        test_id="ge_part",
        bytecode=bytes([0x00, 0x32, 0x02, 0x07, 0x13]),
        expected_class="Ge",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="50 >= VAR_ME",
    ),
    FusionTestCase(
        test_id="no_fusion_not_comparison",
        bytecode=bytes([0x00, 0x05, 0x00, 0x03, 0x14, 0x5D, 0x10, 0x00]),
        expected_class="SmartIfNot",
        expected_fused_operands=1,
        expected_stack_pops=0,
        expected_render_text="if (((5 + 3))) jump",
    ),
]


@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_conditional_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)
