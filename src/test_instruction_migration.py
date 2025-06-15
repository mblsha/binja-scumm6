from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction, MockLLIL
from binja_helpers.tokens import asm_str  # noqa: F401
import pytest
from typing import List, cast
import sys
import types
from binaryninja.binaryview import BinaryView

# Set up additional mock modules needed by scumm6.py
bn = sys.modules.get("binaryninja")
if bn and not hasattr(bn, "core_ui_enabled"):
    bn.core_ui_enabled = lambda: False  # type: ignore[attr-defined]
    if "binaryninja.function" not in sys.modules:
        func_mod = types.ModuleType("binaryninja.function")
        func_mod.RegisterInfo = bn.RegisterInfo  # type: ignore[attr-defined]
        func_mod.InstructionInfo = bn.InstructionInfo  # type: ignore[attr-defined]
        func_mod.InstructionTextToken = bn.InstructionTextToken  # type: ignore[attr-defined]
        sys.modules["binaryninja.function"] = func_mod

# Path 1: The original, monolithic implementation
from .scumm6 import Scumm6 as OldScumm6Architecture, LastBV  # noqa: E402

# Path 2: The new, refactored implementation (decoder to be created)
# from src.pyscumm6.disasm import decode as new_decode


# Wrapper to get LLIL from the old architecture
def get_old_llil(data: bytes, addr: int) -> List[MockLLIL]:
    class DummyFile:
        filename = "<dummy>"

    class DummyView(BinaryView):
        def __init__(self, buf: bytes, base: int) -> None:
            super().__init__()
            self._buf = buf
            self._base = base
            self.file = DummyFile()

        def read(self, a: int, length: int) -> bytes:
            start = a - self._base
            end = start + length
            return self._buf[start:end]

    view = DummyView(data, addr)
    LastBV.set(view)
    arch = OldScumm6Architecture()
    il = MockLowLevelILFunction()
    arch.get_instruction_low_level_il(data, addr, il)
    return cast(List[MockLLIL], il.ils)


# Wrapper to get LLIL from the new instruction object
def get_new_llil(data: bytes, addr: int) -> List[MockLLIL]:
    # new_instr = new_decode(data, addr)
    # il = MockLowLevelILFunction()
    # new_instr.lift(il, addr)
    # return il.ils
    pytest.xfail("New decoder not yet implemented for this opcode.")


@pytest.mark.parametrize("opcode_name, opcode_bytes", [
    ("push_byte", b"\x00\x12"),
    # ... more test cases will be added here
])
def test_llil_consistency(opcode_name: str, opcode_bytes: bytes) -> None:
    old_il = get_old_llil(opcode_bytes, 0x1000)
    new_il = get_new_llil(opcode_bytes, 0x1000)

    assert old_il == new_il
