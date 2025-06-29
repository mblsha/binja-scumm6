#!/usr/bin/env python3
"""Declarative tests for instruction fusion."""

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
    expected_length: Optional[int] = None
    additional_validation: Optional[Callable[[Any], None]] = None
    addr: int = 0x1000


def run_fusion_test(case: FusionTestCase) -> None:
    instr = decode_with_fusion(case.bytecode, case.addr)
    assert instr is not None, f"Failed to decode {case.test_id}"
    assert instr.__class__.__name__ == case.expected_class
    assert len(instr.fused_operands) == case.expected_fused_operands
    assert instr.stack_pop_count == case.expected_stack_pops
    if case.expected_length is not None:
        assert instr.length() == case.expected_length
    tokens = instr.render()
    token_text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    if case.expected_render_text is not None:
        assert case.expected_render_text in token_text
    if case.additional_validation:
        case.additional_validation(instr)


fusion_test_cases = [
    FusionTestCase(
        test_id="single_operand_add",
        bytecode=bytes([0x00, 0x05, 0x14]),
        expected_class="Add",
        expected_fused_operands=1,
        expected_stack_pops=1,
        expected_render_text="add(5, ...)",
        expected_length=3,
    ),
    FusionTestCase(
        test_id="double_operand_add",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x05, 0x14]),
        expected_class="Add",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="(10 + 5)",
        expected_length=5,
    ),
    FusionTestCase(
        test_id="push_word_add",
        bytecode=bytes([0x01, 0xE8, 0x03, 0x14]),
        expected_class="Add",
        expected_fused_operands=1,
        expected_stack_pops=1,
        expected_render_text="add(1000, ...)",
        expected_length=4,
    ),
    FusionTestCase(
        test_id="push_var_add",
        bytecode=bytes([0x02, 0x38, 0x14]),
        expected_class="Add",
        expected_fused_operands=1,
        expected_stack_pops=1,
        expected_render_text="add(VAR_SOUNDRESULT, ...)",
    ),
    FusionTestCase(
        test_id="no_fusion_non_push",
        bytecode=bytes([0x0C, 0x14]),
        expected_class="Add",
        expected_fused_operands=0,
        expected_stack_pops=2,
        expected_length=1,
    ),
    FusionTestCase(
        test_id="sub_instruction",
        bytecode=bytes([0x00, 0x14, 0x00, 0x05, 0x15]),
        expected_class="Sub",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="(20 - 5)",
    ),
    FusionTestCase(
        test_id="mixed_push_types",
        bytecode=bytes([0x01, 0xF4, 0x01, 0x00, 0x03, 0x14]),
        expected_class="Add",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="(500 + 3)",
    ),
]


def validate_operand_order(instr: Any) -> None:
    first = instr.fused_operands[0]
    second = instr.fused_operands[1]
    assert hasattr(first.op_details.body, "data")
    assert first.op_details.body.data == 10
    assert hasattr(second.op_details.body, "data")
    assert second.op_details.body.data == 5


fusion_test_cases.append(
    FusionTestCase(
        test_id="operand_order",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x05, 0x14]),
        expected_class="Add",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="(10 + 5)",
        additional_validation=validate_operand_order,
    )
)


@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_instruction_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)
