from dataclasses import dataclass
from typing import List, Optional

from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction, MockLLIL
from .test_mocks import MockScumm6BinaryView
from binja_helpers.tokens import asm_str  # noqa: F401
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


# Define test cases for instruction migration
instruction_test_cases = [
    InstructionTestCase(
        test_id="push_byte_0x12",
        data=b"\x00\x12",
        comment="Push byte value 0x12 (18)"
    ),
    InstructionTestCase(
        test_id="push_word_0x1234", 
        data=b"\x01\x34\x12",
        comment="Push word value 0x1234 (4660) - little endian"
    ),
    InstructionTestCase(
        test_id="push_byte_var_0x38",
        data=b"\x02\x38\x00",
        comment="Push byte variable 0x38 (56) - loads from SCUMM var"
    ),
    InstructionTestCase(
        test_id="push_word_var_0x38",
        data=b"\x03\x38\x00",
        comment="Push word variable 0x38 (56) - loads 4-byte value from SCUMM var"
    ),
    InstructionTestCase(
        test_id="dup_0x0c",
        data=b"\x0c",
        comment="Duplicate top stack item"
    ),
    InstructionTestCase(
        test_id="pop1_0x1a",
        data=b"\x1a",
        comment="Pop single item from stack"
    ),
    InstructionTestCase(
        test_id="pop2_0xa7",
        data=b"\xa7",
        comment="Pop two items from stack"
    ),
    InstructionTestCase(
        test_id="add_0x14",
        data=b"\x14",
        comment="Add top two stack items"
    ),
    InstructionTestCase(
        test_id="sub_0x15",
        data=b"\x15",
        comment="Subtract top two stack items"
    ),
    InstructionTestCase(
        test_id="mul_0x16",
        data=b"\x16",
        comment="Multiply top two stack items"
    ),
    InstructionTestCase(
        test_id="div_0x17",
        data=b"\x17",
        comment="Divide top two stack items"
    ),
    InstructionTestCase(
        test_id="land_0x18",
        data=b"\x18",
        comment="Logical AND of top two stack items"
    ),
    InstructionTestCase(
        test_id="lor_0x19",
        data=b"\x19",
        comment="Logical OR of top two stack items"
    ),
    InstructionTestCase(
        test_id="nott_0x0d",
        data=b"\x0d",
        comment="Logical NOT of top stack item"
    ),
    InstructionTestCase(
        test_id="eq_0x0e",
        data=b"\x0e",
        comment="Equal comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="neq_0x0f",
        data=b"\x0f",
        comment="Not equal comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="gt_0x10",
        data=b"\x10",
        comment="Greater than comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="lt_0x11",
        data=b"\x11",
        comment="Less than comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="le_0x12",
        data=b"\x12",
        comment="Less than or equal comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="ge_0x13",
        data=b"\x13",
        comment="Greater than or equal comparison of top two stack items"
    ),
    InstructionTestCase(
        test_id="abs_0xc4",
        data=b"\xc4",
        comment="Absolute value of top stack item"
    ),
    InstructionTestCase(
        test_id="band_0xd6",
        data=b"\xd6",
        comment="Bitwise AND of top two stack items"
    ),
    InstructionTestCase(
        test_id="bor_0xd7",
        data=b"\xd7",
        comment="Bitwise OR of top two stack items"
    ),
    InstructionTestCase(
        test_id="byte_var_inc_0x4e",
        data=b"\x4e\x38",
        comment="Increment byte variable 0x38 (56)"
    ),
]


def get_old_llil(case: InstructionTestCase) -> List[MockLLIL]:
    """Get LLIL from the original monolithic implementation."""
    view = MockScumm6BinaryView()
    view.write_memory(case.addr, case.data)
    LastBV.set(view)
    arch = OldScumm6Architecture()
    il = MockLowLevelILFunction()
    arch.get_instruction_low_level_il(case.data, case.addr, il)
    return il.ils  # type: ignore


def get_new_llil(case: InstructionTestCase) -> List[MockLLIL]:
    """Get LLIL from the new object-oriented implementation."""
    new_instr = new_decode(case.data, case.addr)
    if new_instr is None:
        pytest.xfail("New decoder not yet implemented for this opcode.")
    il = MockLowLevelILFunction()
    new_instr.lift(il, case.addr)
    return il.ils  # type: ignore


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
