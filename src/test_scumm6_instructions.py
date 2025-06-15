"""
Minimalistic test cases for SCUMM6 instruction types.
Based on the binja_helpers/sc62015/pysc62015 test patterns.

This module tests individual SCUMM6 instruction types for:
1. Proper decoding from byte sequences
2. Text disassembly rendering
3. LLIL (Low Level Intermediate Language) lifting

Each test case focuses on a specific OpType and verifies both the
disassembly output and the LLIL representation.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import pytest

from binja_helpers.binja_helpers import binja_api  # noqa: F401

from .disasm import Instruction, Scumm6Disasm
from .scumm6_opcodes import Scumm6Opcodes

# Import test utilities from binja_helpers
from binja_helpers.binja_helpers.mock_llil import (
    MockLowLevelILFunction,
    mllil,
)

OpType = Scumm6Opcodes.OpType
VarType = Scumm6Opcodes.VarType

# Test data extracted from DOTTDEMO.bsc6
# Each OpType maps to a representative byte sequence
INSTRUCTION_TEST_DATA: Dict[OpType, bytes] = {
    OpType.push_byte: b"\x00\x12",
    OpType.push_word: b"\x01\x34\x12",
    OpType.push_byte_var: b"\x02\x38\x00",
    OpType.push_word_var: b"\x03\x38\x00",
    OpType.dup: b"\x0c",
    OpType.nott: b"\x0d",
    OpType.eq: b"\x0e",
    OpType.neq: b"\x0f",
    OpType.gt: b"\x10",
    OpType.lt: b"\x11",
    OpType.le: b"\x12",
    OpType.ge: b"\x13",
    OpType.add: b"\x14",
    OpType.sub: b"\x15",
    OpType.mul: b"\x16",
    OpType.div: b"\x17",
    OpType.land: b"\x18",
    OpType.lor: b"\x19",
    OpType.pop1: b"\x1a",
    OpType.write_byte_var: b"\x42\x38\x00",
    OpType.write_word_var: b"\x43\x38\x00",
}


def decode_instruction(data: bytes, addr: int = 0x1234) -> Instruction:
    """
    Decode a SCUMM6 instruction from byte data.

    Args:
        data: Raw instruction bytes
        addr: Address where the instruction is located

    Returns:
        Decoded Instruction object

    Raises:
        ValueError: If instruction cannot be decoded
    """
    disasm = Scumm6Disasm()
    instruction = disasm.decode_instruction(data, addr)
    if instruction is None:
        raise ValueError(f"Failed to decode {data.hex()} at {addr:#x}")
    return instruction


def render_instruction(instruction: Instruction) -> str:
    """
    Render an instruction to its text disassembly representation.

    Args:
        instruction: The instruction to render

    Returns:
        String representation of the disassembly
    """
    # Basic rendering - this should be enhanced to match actual SCUMM6 disassembly format
    op_name = instruction.id.upper()

    # Add operand information based on instruction type
    if hasattr(instruction.op, 'body') and hasattr(instruction.op.body, 'data'):
        data = instruction.op.body.data
        if instruction.op.id in [OpType.push_byte, OpType.push_word]:
            return f"{op_name} {data}"
        elif instruction.op.id in [OpType.push_byte_var, OpType.push_word_var,
                                   OpType.write_byte_var, OpType.write_word_var]:
            return f"{op_name} var_{data}"

    # For simple operations without operands
    return op_name


def lift_instruction(instruction: Instruction, addr: int = 0x1234) -> List[Any]:
    """
    Lift an instruction to LLIL representation.

    Args:
        instruction: The instruction to lift
        addr: Address of the instruction

    Returns:
        List of LLIL operations
    """
    il = MockLowLevelILFunction()

    # Basic LLIL lifting for SCUMM6 instructions
    # This is a simplified implementation - actual lifting would be more complex

    if instruction.op.id == OpType.push_byte:
        # Push byte constant onto stack
        value = instruction.op.body.data
        il.append(mllil("PUSH.b", [mllil("CONST.b", [value])]))

    elif instruction.op.id == OpType.push_word:
        # Push word constant onto stack
        value = instruction.op.body.data
        il.append(mllil("PUSH.w", [mllil("CONST.w", [value])]))

    elif instruction.op.id == OpType.push_byte_var:
        # Push byte variable onto stack
        var_id = instruction.op.body.data
        il.append(mllil("PUSH.b", [mllil("LOAD.b", [mllil("CONST.l", [var_id])])]))

    elif instruction.op.id == OpType.push_word_var:
        # Push word variable onto stack
        var_id = instruction.op.body.data
        il.append(mllil("PUSH.w", [mllil("LOAD.w", [mllil("CONST.l", [var_id])])]))

    elif instruction.op.id == OpType.add:
        # Pop two values, add them, push result
        il.append(mllil("PUSH.w", [mllil("ADD.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.sub:
        # Pop two values, subtract them, push result
        il.append(mllil("PUSH.w", [mllil("SUB.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.mul:
        # Pop two values, multiply them, push result
        il.append(mllil("PUSH.w", [mllil("MUL.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.div:
        # Pop two values, divide them, push result
        il.append(mllil("PUSH.w", [mllil("DIV.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.eq:
        # Pop two values, compare for equality, push result
        il.append(mllil("PUSH.b", [mllil("CMP_E.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.neq:
        # Pop two values, compare for inequality, push result
        il.append(mllil("PUSH.b", [mllil("CMP_NE.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.gt:
        # Pop two values, compare greater than, push result
        il.append(mllil("PUSH.b", [mllil("CMP_SGT.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.lt:
        # Pop two values, compare less than, push result
        il.append(mllil("PUSH.b", [mllil("CMP_SLT.w", [mllil("POP.w", []), mllil("POP.w", [])])]))

    elif instruction.op.id == OpType.dup:
        # Duplicate top of stack
        il.append(mllil("PUSH.w", [mllil("POP.w", [])]))
        il.append(mllil("PUSH.w", [mllil("POP.w", [])]))

    elif instruction.op.id == OpType.pop1:
        # Pop one item from stack
        il.append(mllil("POP.w", []))

    elif instruction.op.id == OpType.nott:
        # Logical NOT of top stack item
        il.append(mllil("PUSH.b", [mllil("NOT.b", [mllil("POP.b", [])])]))

    elif instruction.op.id == OpType.land:
        # Logical AND of two stack items
        il.append(mllil("PUSH.b", [mllil("AND.b", [mllil("POP.b", []), mllil("POP.b", [])])]))

    elif instruction.op.id == OpType.lor:
        # Logical OR of two stack items
        il.append(mllil("PUSH.b", [mllil("OR.b", [mllil("POP.b", []), mllil("POP.b", [])])]))

    elif instruction.op.id == OpType.write_byte_var:
        # Pop value and write to byte variable
        var_id = instruction.op.body.data
        il.append(mllil("STORE.b", [mllil("CONST.l", [var_id]), mllil("POP.b", [])]))

    elif instruction.op.id == OpType.write_word_var:
        # Pop value and write to word variable
        var_id = instruction.op.body.data
        il.append(mllil("STORE.w", [mllil("CONST.l", [var_id]), mllil("POP.w", [])]))

    else:
        # For unimplemented instructions, add a placeholder
        il.append(mllil("UNIMPL", []))

    return il.ils


@dataclass
class InstructionTestCase:
    """Container describing a single instruction test."""

    test_id: str
    data: bytes
    op_type: OpType
    id_str: str
    length: int
    operand_val: Optional[int] = None
    render_substr: Optional[str] = None
    llil_count: Optional[int] = None


INSTRUCTION_TEST_CASES = [
    InstructionTestCase(
        "push_byte_pos",
        b"\x00\x12",
        OpType.push_byte,
        "push_byte",
        2,
        operand_val=0x12,
        render_substr="push_byte",
        llil_count=1,
    ),
    InstructionTestCase(
        "push_byte_neg",
        b"\x00\xff",
        OpType.push_byte,
        "push_byte",
        2,
        operand_val=-1,
        render_substr="push_byte",
        llil_count=1,
    ),
    InstructionTestCase(
        "push_word",
        b"\x01\x34\x12",
        OpType.push_word,
        "push_word",
        3,
        render_substr="push_word",
        llil_count=1,
    ),
    InstructionTestCase(
        "push_byte_var",
        b"\x02\x38\x00",
        OpType.push_byte_var,
        "push_byte_var",
        2,
        operand_val=0x38,
        render_substr="var_",
        llil_count=1,
    ),
    InstructionTestCase(
        "push_word_var",
        b"\x03\x38\x00",
        OpType.push_word_var,
        "push_word_var",
        3,
        operand_val=56,
        render_substr="var_56",
        llil_count=1,
    ),
    InstructionTestCase("add", b"\x14", OpType.add, "add", 1, llil_count=1),
    InstructionTestCase("sub", b"\x15", OpType.sub, "sub", 1, llil_count=1),
    InstructionTestCase("mul", b"\x16", OpType.mul, "mul", 1, llil_count=1),
    InstructionTestCase("div", b"\x17", OpType.div, "div", 1, llil_count=1),
    InstructionTestCase("eq", b"\x0e", OpType.eq, "eq", 1, llil_count=1),
    InstructionTestCase("neq", b"\x0f", OpType.neq, "neq", 1, llil_count=1),
    InstructionTestCase("gt", b"\x10", OpType.gt, "gt", 1, llil_count=1),
    InstructionTestCase("lt", b"\x11", OpType.lt, "lt", 1, llil_count=1),
    InstructionTestCase("le", b"\x12", OpType.le, "le", 1, llil_count=1),
    InstructionTestCase("ge", b"\x13", OpType.ge, "ge", 1, llil_count=1),
    InstructionTestCase("land", b"\x18", OpType.land, "land", 1, llil_count=1),
    InstructionTestCase("lor", b"\x19", OpType.lor, "lor", 1, llil_count=1),
    InstructionTestCase("nott", b"\x0d", OpType.nott, "nott", 1, llil_count=1),
    InstructionTestCase("dup", b"\x0c", OpType.dup, "dup", 1, llil_count=2),
    InstructionTestCase("pop1", b"\x1a", OpType.pop1, "pop1", 1, llil_count=1),
    InstructionTestCase(
        "write_byte_var",
        b"\x42\x38\x00",
        OpType.write_byte_var,
        "write_byte_var",
        3,
        operand_val=None,
        render_substr="var_",
        llil_count=1,
    ),
    InstructionTestCase(
        "write_word_var",
        b"\x43\x38\x00",
        OpType.write_word_var,
        "write_word_var",
        3,
        operand_val=None,
        render_substr="var_",
        llil_count=1,
    ),
]


@pytest.mark.parametrize(
    "case",
    INSTRUCTION_TEST_CASES,
    ids=[c.test_id for c in INSTRUCTION_TEST_CASES],
)
def test_instruction_case(case: InstructionTestCase) -> None:
    """Generic test covering decoding, rendering and lifting."""

    instr = decode_instruction(case.data, 0x1000)
    assert instr.op.id == case.op_type
    assert instr.id == case.id_str
    assert instr.length == case.length
    assert instr.data[:instr.length] == case.data[: instr.length]

    if case.operand_val is not None:
        assert instr.op.body.data == case.operand_val

    rendered = render_instruction(instr)
    if case.render_substr:
        assert case.render_substr.lower() in rendered.lower()

    llil_ops = lift_instruction(instr)
    assert isinstance(llil_ops, list)
    if case.llil_count is not None:
        assert len(llil_ops) == case.llil_count


def test_instruction_comparison_with_dottdemo() -> None:
    """Decode and lift instructions seen in DOTTDEMO."""
    real_patterns = [
        b"\x00\x01",
        b"\x00\x00",
        b"\x01\x00\x01",
        b"\x03\x38\x00",
        b"\x14",
        b"\x0e",
        b"\x42\x38\x00",
    ]

    for pattern in real_patterns:
        instr = decode_instruction(pattern, 0x1000)
        assert instr is not None
        assert instr.length > 0

        rendered = render_instruction(instr)
        assert len(rendered) > 0

        llil_ops = lift_instruction(instr)
        assert isinstance(llil_ops, list)


def test_invalid_instruction() -> None:
    """Test handling of invalid instruction data."""
    disasm = Scumm6Disasm()

    # Empty data
    assert disasm.decode_instruction(b"", 0) is None

    # Insufficient data for push_byte (needs 2 bytes)
    assert disasm.decode_instruction(b"\x00", 0) is None


def test_instruction_lengths() -> None:
    """Test that instruction lengths are correctly calculated."""
    test_cases = [
        (b"\x00\x12", 2),  # push_byte
        (b"\x01\x34\x12", 3),  # push_word
        (b"\x02\x38\x00", 2),  # push_byte_var - Fixed: length is 2
        (b"\x03\x38\x00", 3),  # push_word_var
        (b"\x0c", 1),  # dup
        (b"\x14", 1),  # add
        (b"\x42\x38\x00", 3),  # write_byte_var
    ]

    for data, expected_length in test_cases:
        instr = decode_instruction(data, 0x1000)
        assert instr.length == expected_length

# TODO: Add more comprehensive tests for:
# - Array operations (byte_array_read, word_array_read, etc.)
# - Control flow operations (iff, if_not, jump, etc.)
# - SCUMM-specific operations (start_script, draw_object, etc.)
# - LLIL lifting verification once implemented
# - Text rendering verification once implemented
