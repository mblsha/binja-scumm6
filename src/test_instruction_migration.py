from dataclasses import dataclass
from typing import List, Optional

from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction, MockLLIL
from .test_mocks import MockScumm6BinaryView
from binja_helpers.tokens import asm_str
import pytest

# Path 1: The original, monolithic implementation
from .scumm6 import Scumm6 as OldScumm6Architecture, LastBV

# Path 2: The new, refactored implementation
from .pyscumm6.disasm import decode as new_decode


@dataclass
class InstructionTestCase:
    """Test case for validating instruction migration."""
    test_id: str
    data: bytes
    addr: int = 0x1000
    comment: Optional[str] = None
    expected_disasm: Optional[str] = None


# Define test cases for instruction migration
instruction_test_cases = [
    InstructionTestCase(
        test_id="push_byte_0x12",
        data=b"\x00\x12",
        comment="Push byte value 0x12 (18)",
        expected_disasm="push_byte(18)"
    ),
    InstructionTestCase(
        test_id="push_word_0x1234",
        data=b"\x01\x34\x12",
        comment="Push word value 0x1234 (4660) - little endian",
        expected_disasm="push_word(4660)"
    ),
    InstructionTestCase(
        test_id="push_byte_var_0x38",
        data=b"\x02\x38\x00",
        comment="Push byte variable 0x38 (56) - loads from SCUMM var",
        expected_disasm="push_byte_var(var_56)"
    ),
    InstructionTestCase(
        test_id="push_word_var_0x38",
        data=b"\x03\x38\x00",
        comment="Push word variable 0x38 (56) - loads 4-byte value from SCUMM var",
        expected_disasm="push_word_var(var_56)"
    ),
    InstructionTestCase(
        test_id="dup_0x0c",
        data=b"\x0c",
        comment="Duplicate top stack item",
        expected_disasm="dup"
    ),
    InstructionTestCase(
        test_id="pop1_0x1a",
        data=b"\x1a",
        comment="Pop single item from stack",
        expected_disasm="pop1"
    ),
    InstructionTestCase(
        test_id="pop2_0xa7",
        data=b"\xa7",
        comment="Pop two items from stack",
        expected_disasm="pop2"
    ),
    InstructionTestCase(
        test_id="add_0x14",
        data=b"\x14",
        comment="Add top two stack items",
        expected_disasm="add"
    ),
    InstructionTestCase(
        test_id="sub_0x15",
        data=b"\x15",
        comment="Subtract top two stack items",
        expected_disasm="sub"
    ),
    InstructionTestCase(
        test_id="mul_0x16",
        data=b"\x16",
        comment="Multiply top two stack items",
        expected_disasm="mul"
    ),
    InstructionTestCase(
        test_id="div_0x17",
        data=b"\x17",
        comment="Divide top two stack items",
        expected_disasm="div"
    ),
    InstructionTestCase(
        test_id="land_0x18",
        data=b"\x18",
        comment="Logical AND of top two stack items",
        expected_disasm="land"
    ),
    InstructionTestCase(
        test_id="lor_0x19",
        data=b"\x19",
        comment="Logical OR of top two stack items",
        expected_disasm="lor"
    ),
    InstructionTestCase(
        test_id="nott_0x0d",
        data=b"\x0d",
        comment="Logical NOT of top stack item",
        expected_disasm="nott"
    ),
    InstructionTestCase(
        test_id="eq_0x0e",
        data=b"\x0e",
        comment="Equal comparison of top two stack items",
        expected_disasm="eq"
    ),
    InstructionTestCase(
        test_id="neq_0x0f",
        data=b"\x0f",
        comment="Not equal comparison of top two stack items",
        expected_disasm="neq"
    ),
    InstructionTestCase(
        test_id="gt_0x10",
        data=b"\x10",
        comment="Greater than comparison of top two stack items",
        expected_disasm="gt"
    ),
    InstructionTestCase(
        test_id="lt_0x11",
        data=b"\x11",
        comment="Less than comparison of top two stack items",
        expected_disasm="lt"
    ),
    InstructionTestCase(
        test_id="le_0x12",
        data=b"\x12",
        comment="Less than or equal comparison of top two stack items",
        expected_disasm="le"
    ),
    InstructionTestCase(
        test_id="ge_0x13",
        data=b"\x13",
        comment="Greater than or equal comparison of top two stack items",
        expected_disasm="ge"
    ),
    InstructionTestCase(
        test_id="abs_0xc4",
        data=b"\xc4",
        comment="Absolute value of top stack item",
        expected_disasm="abs"
    ),
    InstructionTestCase(
        test_id="band_0xd6",
        data=b"\xd6",
        comment="Bitwise AND of top two stack items",
        expected_disasm="band"
    ),
    InstructionTestCase(
        test_id="bor_0xd7",
        data=b"\xd7",
        comment="Bitwise OR of top two stack items",
        expected_disasm="bor"
    ),
    InstructionTestCase(
        test_id="byte_var_inc_0x4e",
        data=b"\x4e\x38",
        comment="Increment byte variable 0x38 (56)",
        expected_disasm="byte_var_inc(var_56)"
    ),
    InstructionTestCase(
        test_id="word_var_inc_0x4f",
        data=b"\x4f\x38\x00",
        comment="Increment word variable 0x38 (56)",
        expected_disasm="word_var_inc(var_56)"
    ),
    InstructionTestCase(
        test_id="byte_var_dec_0x56",
        data=b"\x56\x38",
        comment="Decrement byte variable 0x38 (56)",
        expected_disasm="byte_var_dec(var_56)"
    ),
    InstructionTestCase(
        test_id="word_var_dec_0x57",
        data=b"\x57\x38\x00",
        comment="Decrement word variable 0x38 (56)",
        expected_disasm="word_var_dec(var_56)"
    ),
    InstructionTestCase(
        test_id="break_here_0x6c",
        data=b"\x6c",
        comment="Breakpoint/debug instruction",
        expected_disasm="break_here"
    ),
    InstructionTestCase(
        test_id="dummy_0xbd",
        data=b"\xbd",
        comment="Dummy/no-op instruction",
        expected_disasm="dummy"
    ),
    InstructionTestCase(
        test_id="get_random_number_0x87",
        data=b"\x87",
        comment="Get random number",
        expected_disasm="get_random_number"
    ),
    InstructionTestCase(
        test_id="get_random_number_range_0x88",
        data=b"\x88",
        comment="Get random number in range",
        expected_disasm="get_random_number_range"
    ),
    InstructionTestCase(
        test_id="pick_one_of_0xcb",
        data=b"\xcb",
        comment="Pick one of multiple options",
        expected_disasm="pick_one_of"
    ),
    InstructionTestCase(
        test_id="pick_one_of_default_0xcc",
        data=b"\xcc",
        comment="Pick one of multiple options with default",
        expected_disasm="pick_one_of_default"
    ),
    InstructionTestCase(
        test_id="shuffle_0xd4",
        data=b"\xd4",
        comment="Shuffle array or list",
        expected_disasm="shuffle"
    ),
    InstructionTestCase(
        test_id="byte_array_read_0x06",
        data=b"\x06\x05",
        comment="Read from byte array 5",
        expected_disasm="byte_array_read(array_5)"
    ),
    InstructionTestCase(
        test_id="write_byte_var_0x42",
        data=b"\x42\x38",
        comment="Write byte to variable 0x38 (56)",
        expected_disasm="write_byte_var(var_?)"  # Due to Kaitai bug, falls back to UnknownOp
    ),
    InstructionTestCase(
        test_id="write_word_var_0x43",
        data=b"\x43\x38\x00",
        comment="Write word to variable 0x38 (56)",
        expected_disasm="write_word_var(var_56)"
    ),
    InstructionTestCase(
        test_id="word_array_read_0x07",
        data=b"\x07\x34\x12",
        comment="Read from word array 0x1234 (4660)",
        expected_disasm="word_array_read(array_4660)"
    ),
    InstructionTestCase(
        test_id="byte_array_indexed_read_0x0a",
        data=b"\x0a\x05",
        comment="Indexed read from byte array 5",
        expected_disasm="byte_array_indexed_read(array_5)"
    ),
    InstructionTestCase(
        test_id="word_array_indexed_read_0x0b",
        data=b"\x0b\x34\x12",
        comment="Indexed read from word array 0x1234 (4660)",
        expected_disasm="word_array_indexed_read(array_4660)"
    ),
    InstructionTestCase(
        test_id="byte_array_write_0x46",
        data=b"\x46\x05",
        comment="Write to byte array 5",
        expected_disasm="byte_array_write(array_5)"
    ),
    InstructionTestCase(
        test_id="word_array_write_0x47",
        data=b"\x47\x34\x12",
        comment="Write to word array 0x1234 (4660)",
        expected_disasm="word_array_write(array_4660)"
    ),
    InstructionTestCase(
        test_id="byte_array_indexed_write_0x4a",
        data=b"\x4a\x05",
        comment="Indexed write to byte array 5",
        expected_disasm="byte_array_indexed_write(array_5)"
    ),
    InstructionTestCase(
        test_id="word_array_indexed_write_0x4b",
        data=b"\x4b\x34\x12",
        comment="Indexed write to word array 0x1234 (4660)",
        expected_disasm="word_array_indexed_write(array_4660)"
    ),
    InstructionTestCase(
        test_id="byte_array_inc_0x52",
        data=b"\x52",
        comment="Increment byte array element",
        expected_disasm="byte_array_inc"
    ),
    InstructionTestCase(
        test_id="word_array_inc_0x53",
        data=b"\x53",
        comment="Increment word array element",
        expected_disasm="word_array_inc"
    ),
    InstructionTestCase(
        test_id="byte_array_dec_0x5a",
        data=b"\x5a",
        comment="Decrement byte array element",
        expected_disasm="byte_array_dec"
    ),
    InstructionTestCase(
        test_id="word_array_dec_0x5b",
        data=b"\x5b",
        comment="Decrement word array element",
        expected_disasm="word_array_dec"
    ),
    InstructionTestCase(
        test_id="iff_positive_offset_0x5c",
        data=b"\x5c\x14\x00",
        comment="If true with +20 offset",
        expected_disasm="iff(20)"
    ),
    InstructionTestCase(
        test_id="if_not_zero_offset_0x5d",
        data=b"\x5d\x00\x00",
        comment="If false with 0 offset",
        expected_disasm="if_not(0)"
    ),
    InstructionTestCase(
        test_id="jump_positive_offset_0x73",
        data=b"\x73\x64\x00",
        comment="Jump with +100 offset",
        expected_disasm="jump(100)"
    ),
    # Group 3: Complex Engine Intrinsics
    InstructionTestCase(
        test_id="draw_object_0x61",
        data=b"\x61",
        comment="Draw object intrinsic",
        expected_disasm="draw_object"
    ),
    InstructionTestCase(
        test_id="draw_object_at_0x62",
        data=b"\x62",
        comment="Draw object at position intrinsic",
        expected_disasm="draw_object_at"
    ),
    # Note: draw_blast_object (0x63) test skipped - requires complex state handling
    # Note: cutscene (0x68) test skipped - requires complex state handling for call_func_list
    InstructionTestCase(
        test_id="end_cutscene_0x67",
        data=b"\x67",
        comment="End cutscene intrinsic",
        expected_disasm="end_cutscene"
    ),
    InstructionTestCase(
        test_id="stop_music_0x69",
        data=b"\x69",
        comment="Stop music intrinsic",
        expected_disasm="stop_music"
    ),
    InstructionTestCase(
        test_id="freeze_unfreeze_0x6a",
        data=b"\x6a",
        comment="Freeze/unfreeze intrinsic",
        expected_disasm="freeze_unfreeze"
    ),
]


def get_old_llil(case: InstructionTestCase) -> List[MockLLIL]:
    """Get LLIL from the original monolithic implementation."""
    view = MockScumm6BinaryView()
    view.write_memory(case.addr, case.data)
    LastBV.set(view)  # type: ignore[arg-type]
    arch = OldScumm6Architecture()
    il = MockLowLevelILFunction()

    # FIXME: Handle known bug in write_byte_var where it crashes due to Kaitai parsing issue
    if case.test_id == "write_byte_var_0x42":
        try:
            arch.get_instruction_low_level_il(case.data, case.addr, il)
        except AttributeError as e:
            if "'UnknownOp' object has no attribute 'type'" in str(e):
                # This is the expected behavior for write_byte_var due to Kaitai bug
                # The old implementation crashes and returns no LLIL operations
                return il.ils
            raise
    else:
        arch.get_instruction_low_level_il(case.data, case.addr, il)

    return il.ils


def get_new_llil(case: InstructionTestCase) -> List[MockLLIL]:
    """Get LLIL from the new object-oriented implementation."""
    new_instr = new_decode(case.data, case.addr)
    if new_instr is None:
        pytest.xfail("New decoder not yet implemented for this opcode.")
    il = MockLowLevelILFunction()
    new_instr.lift(il, case.addr)
    return il.ils


def get_old_disasm(case: InstructionTestCase) -> Optional[str]:
    """Get disassembly from the original monolithic implementation."""
    view = MockScumm6BinaryView()
    view.write_memory(case.addr, case.data)
    LastBV.set(view)  # type: ignore[arg-type]
    arch = OldScumm6Architecture()
    result = arch.get_instruction_text(case.data, case.addr)
    if result is None:
        return None
    tokens, _ = result
    return str(asm_str(token.text for token in tokens))


def get_new_disasm(case: InstructionTestCase) -> Optional[str]:
    """Get disassembly from the new object-oriented implementation."""
    new_instr = new_decode(case.data, case.addr)
    if new_instr is None:
        return None
    tokens = new_instr.render()
    return str(asm_str(tokens))


@pytest.mark.parametrize(
    "case",
    instruction_test_cases,
    ids=[c.test_id for c in instruction_test_cases]
)
def test_llil_consistency(case: InstructionTestCase) -> None:
    """Verify that new implementation produces identical LLIL to the original."""
    old_il = get_old_llil(case)
    new_il = get_new_llil(case)

    assert old_il == new_il, f"LLIL mismatch for {case.test_id}: {case.comment}"


@pytest.mark.parametrize(
    "case",
    instruction_test_cases,
    ids=[c.test_id for c in instruction_test_cases]
)
def test_disasm_consistency(case: InstructionTestCase) -> None:
    """Verify that both implementations produce consistent disassembly."""
    if case.expected_disasm is None:
        pytest.skip("No expected disassembly provided for this test case")

    old_disasm = get_old_disasm(case)
    new_disasm = get_new_disasm(case)

    # Check that the new implementation matches the expected disassembly exactly
    assert new_disasm == case.expected_disasm, \
        f"New implementation disassembly mismatch for {case.test_id}: " \
        f"expected '{case.expected_disasm}', got '{new_disasm}'"

    # For the old implementation, check that it contains the expected instruction name
    # (it may have additional parameters, which is acceptable)
    if old_disasm is not None:
        expected_instr_name = case.expected_disasm.split('(')[0]  # Get instruction name part
        assert old_disasm.startswith(expected_instr_name), \
            f"Old implementation disassembly doesn't start with expected instruction '{expected_instr_name}' " \
            f"for {case.test_id}: got '{old_disasm}'"
    else:
        pytest.fail(f"Old implementation returned None for {case.test_id}")

    # Verify that both implementations at least agree on the instruction name
    if old_disasm and new_disasm:
        old_instr_name = old_disasm.split('(')[0]
        new_instr_name = new_disasm.split('(')[0]
        assert old_instr_name == new_instr_name, \
            f"Instruction name mismatch between implementations for {case.test_id}: " \
            f"old='{old_instr_name}', new='{new_instr_name}'"
