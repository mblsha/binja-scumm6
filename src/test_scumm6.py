from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import pytest

from binja_helpers import binja_api  # noqa: F401
import sys
import types
import enum
from binaryninja.enums import BranchType

bn = sys.modules.get("binaryninja")
if bn and not hasattr(bn, "core_ui_enabled"):
    bn.core_ui_enabled = lambda: False  # type: ignore[attr-defined]
    arch_mod = sys.modules.get("binaryninja.architecture")
    if arch_mod is not None and not hasattr(arch_mod, "IntrinsicInfo"):
        arch_mod.IntrinsicInfo = bn.IntrinsicInfo  # type: ignore[attr-defined]
    if "binaryninja.function" not in sys.modules:
        func_mod = types.ModuleType("binaryninja.function")
        class RegisterInfo(bn.RegisterInfo):  # type: ignore
            def __init__(self, name: str, size: int, offset: int = 0, extend: object | None = None) -> None:
                super().__init__(name, size, offset)

        bn.RegisterInfo = RegisterInfo  # type: ignore[attr-defined]
        func_mod.RegisterInfo = RegisterInfo  # type: ignore[attr-defined]
        func_mod.InstructionInfo = bn.InstructionInfo  # type: ignore[attr-defined]
        func_mod.InstructionTextToken = bn.InstructionTextToken  # type: ignore[attr-defined]
        sys.modules["binaryninja.function"] = func_mod
    enums_mod = sys.modules.get("binaryninja.enums")
    if enums_mod is not None and not hasattr(enums_mod, "ImplicitRegisterExtend"):
        class ImplicitRegisterExtend(enum.Enum):
            SignExtendToFullWidth = 0

        enums_mod.ImplicitRegisterExtend = ImplicitRegisterExtend  # type: ignore[attr-defined]
        class FlagRole(enum.Enum):
            NegativeSignFlagRole = 0
            ZeroFlagRole = 1
            OverflowFlagRole = 2
            CarryFlagRole = 3

        enums_mod.FlagRole = FlagRole  # type: ignore[attr-defined]

from .scumm6 import Scumm6, LastBV  # noqa: E402
from .test_mocks import MockScumm6BinaryView  # noqa: E402


@dataclass
class InfoTestCase:
    test_id: str
    data: bytes
    addr: int = 0x1000
    decode_fails: bool = False
    expected_length: Optional[int] = None
    expected_mock_branches: List[Tuple[BranchType, Optional[int]]] = field(
        default_factory=list
    )


test_cases = [
    InfoTestCase(test_id="invalid_opcode", data=b"\xff", decode_fails=True),
    InfoTestCase(test_id="incomplete_push_byte", data=b"\x00", decode_fails=True),
    InfoTestCase(test_id="incomplete_jump", data=b"\x73\x01", decode_fails=True),
    InfoTestCase(
        test_id="add_instruction",
        data=b"\x14",
        expected_length=1,
        expected_mock_branches=[],
    ),
    InfoTestCase(
        test_id="push_word_instruction",
        data=b"\x01\x34\x12",
        expected_length=3,
        expected_mock_branches=[],
    ),
    InfoTestCase(
        test_id="stop_object_code",
        data=b"\x65",
        expected_length=1,
        expected_mock_branches=[
            (BranchType.FunctionReturn, None),  # Indicates execution stops here
        ],
    ),
    InfoTestCase(
        test_id="iff_positive_offset",
        data=b"\x5c\x14\x00",
        addr=0x1000,
        expected_length=3,
        expected_mock_branches=[
            (BranchType.TrueBranch, 0x1000 + 3 + 20),
            (BranchType.FalseBranch, 0x1000 + 3),  # FalseBranch (fall-through)
        ],
    ),
    InfoTestCase(
        test_id="iff_negative_offset",
        data=b"\x5c\xec\xff",
        addr=0x1000,
        expected_length=3,
        expected_mock_branches=[
            (BranchType.TrueBranch, 0x1000 + 3 - 20),
            (BranchType.FalseBranch, 0x1000 + 3),  # FalseBranch (fall-through)
        ],
    ),
    InfoTestCase(
        test_id="if_not_zero_offset",
        data=b"\x5d\x00\x00",
        addr=0x2000,
        expected_length=3,
        expected_mock_branches=[
            (BranchType.TrueBranch, 0x2000 + 3),
            (BranchType.FalseBranch, 0x2000 + 3),  # FalseBranch (fall-through)
        ],
    ),
    InfoTestCase(
        test_id="jump_positive_offset",
        data=b"\x73\x64\x00",
        addr=0x3000,
        expected_length=3,
        expected_mock_branches=[
            (BranchType.UnconditionalBranch, 0x3000 + 3 + 100),
            # Unconditional jump - no false branch
        ],
    ),
]


@pytest.mark.parametrize("case", test_cases, ids=[c.test_id for c in test_cases])
def test_instruction_analysis(case: InfoTestCase) -> None:
    # Use unified decoder
    arch = Scumm6()
    view = MockScumm6BinaryView()
    view.write_memory(case.addr, case.data)
    LastBV.set(view)
    
    info = arch.get_instruction_info(case.data, case.addr)

    if case.decode_fails:
        assert info is None
        return

    assert info is not None
    assert info.length == case.expected_length
    
    # Extract branches from the new architecture's InstructionInfo
    branches = []
    if hasattr(info, 'branches') and info.branches:
        branches = [(b.type, b.target) for b in info.branches]
    elif hasattr(info, 'mybranches') and info.mybranches:
        branches = info.mybranches
    
    assert branches == case.expected_mock_branches
