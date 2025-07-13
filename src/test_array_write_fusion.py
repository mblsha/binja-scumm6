#!/usr/bin/env python3
"""Declarative tests for array write instruction fusion."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"


import pytest
from binja_helpers import binja_api  # noqa: F401

from .test_utils import FusionTestCase, run_fusion_test




fusion_test_cases = [
    FusionTestCase(
        test_id="byte_array_write",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x03, 0x46, 0x05]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_5[10] = 3",  # Matches descumm: first push = index
    ),
    FusionTestCase(
        test_id="word_array_write",
        bytecode=bytes([0x01, 0xE8, 0x03, 0x00, 0x07, 0x47, 0x0A, 0x00]),
        expected_class="WordArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_10[1000] = 7",  # Matches descumm: first push = index
    ),
    FusionTestCase(
        test_id="array_write_with_vars",
        bytecode=bytes([0x02, 0x14, 0x03, 0x05, 0x00, 0x46, 0x03]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_3[var20] = var5",  # Matches descumm: first push = index
    ),
    FusionTestCase(
        test_id="array_write_partial",
        bytecode=bytes([0x00, 0x05, 0x46, 0x01]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=1,
        expected_stack_pops=1,
        expected_render_text="array_1[?, 5]",
    ),
    FusionTestCase(
        test_id="array_write_no_fusion",
        bytecode=bytes([0x0C, 0x46, 0x02]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=0,
        expected_stack_pops=2,
        expected_render_text="byte_array_write(array_2)",
    ),
    FusionTestCase(
        test_id="array_write_mixed",
        bytecode=bytes([0x03, 0x64, 0x00, 0x01, 0x32, 0x00, 0x47, 0x07, 0x00]),
        expected_class="WordArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_7[var100] = 50",  # Matches descumm: first push = index
    ),
    FusionTestCase(
        test_id="array_zero_index",
        bytecode=bytes([0x00, 0x2A, 0x00, 0x00, 0x46, 0x00]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_0[42] = 0",  # Matches descumm: first push = index
    ),
    FusionTestCase(
        test_id="array_negative_value",
        bytecode=bytes([0x00, 0xFF, 0x00, 0x05, 0x46, 0x0F]),
        expected_class="ByteArrayWrite",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="array_15[-1] = 5",  # 0xFF is interpreted as signed -1
    ),
]


@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_array_write_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)
