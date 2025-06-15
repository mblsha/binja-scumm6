from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction, MockLLIL
from .test_mocks import MockScumm6BinaryView
from binja_helpers.tokens import asm_str  # noqa: F401
import pytest
from typing import List

# Path 1: The original, monolithic implementation
from .scumm6 import Scumm6 as OldScumm6Architecture, LastBV

# Path 2: The new, refactored implementation (decoder to be created)
from .pyscumm6.disasm import decode as new_decode


# Wrapper to get LLIL from the old architecture
def get_old_llil(data: bytes, addr: int) -> List[MockLLIL]:
    view = MockScumm6BinaryView()
    view.write_memory(addr, data)
    LastBV.set(view)
    arch = OldScumm6Architecture()
    il = MockLowLevelILFunction()
    arch.get_instruction_low_level_il(data, addr, il)
    return il.ils  # type: ignore


# Wrapper to get LLIL from the new instruction object
def get_new_llil(data: bytes, addr: int) -> List[MockLLIL]:
    new_instr = new_decode(data, addr)
    if new_instr is None:
        pytest.xfail("New decoder not yet implemented for this opcode.")
    il = MockLowLevelILFunction()
    new_instr.lift(il, addr)
    return il.ils  # type: ignore


@pytest.mark.parametrize("opcode_name, opcode_bytes", [
    ("push_byte", b"\x00\x12"),
    ("push_word", b"\x01\x34\x12"),  # 0x1234 = 4660
    # ... more test cases will be added here
])
def test_llil_consistency(opcode_name: str, opcode_bytes: bytes) -> None:
    old_il = get_old_llil(opcode_bytes, 0x1000)
    new_il = get_new_llil(opcode_bytes, 0x1000)

    # This assertion should now pass for push_byte
    assert old_il == new_il
