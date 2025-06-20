#!/usr/bin/env python3

import pytest
import types
import sys
import enum
from typing import Any, Optional

from binja_helpers import binja_api  # noqa: F401
import binaryninja

# Configure mock BinaryView for SCUMM6 testing
binaryninja.configure_mock_binaryview(filename="test.bsc6", memory_size=0x100000)

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

from .disasm import State, Resource  # noqa: E402


class MockScumm6View:
    """A simple mock BinaryView class for testing state-dependent operations."""
    
    def __init__(self, state: Any, filename: Optional[str] = None, memory_size: Optional[int] = None) -> None:
        self.state = state
        
        # Use dependency injection pattern - get defaults from mock config if not specified
        if filename is None:
            filename = "test.bsc6"  # SCUMM6-specific default
        if memory_size is None:
            memory_size = 0x100000  # 1MB default
            
        self.file = types.SimpleNamespace(filename=filename)
        # Add a memory buffer for testing instructions that need it
        self._memory = bytearray(b'\x00' * memory_size)
    
    def read(self, addr: int, length: int) -> bytes:
        """Read bytes from the mock memory buffer."""
        if addr + length > len(self._memory):
            return b'\x00' * length  # Return zeros for out-of-bounds reads
        return bytes(self._memory[addr:addr+length])
    
    def write_memory(self, addr: int, data: bytes) -> None:
        """Write data to mock memory for testing."""
        if addr + len(data) <= len(self._memory):
            self._memory[addr:addr+len(data)] = data


def create_mock_state_with_strings() -> State:
    """Create a mock State object with test string mappings."""
    mock_state = State()
    # Add test strings to the bstr dictionary
    mock_state.bstr["Hello World"] = 0xCAFE0000
    mock_state.bstr["How are you?"] = 0xCAFE0100
    mock_state.bstr["Goodbye!"] = 0xCAFE0200
    return mock_state


def create_mock_state_with_scripts() -> State:
    """Create a mock State object with test script mappings."""
    mock_state = State()
    
    # Initialize empty lists/dicts to proper sizes  
    mock_state.dscr = [None] * 20  # type: ignore[list-item] # Room for script descriptors 0-19
    mock_state.room_ids = {}
    mock_state.block_to_script = {}
    
    # Set up test script descriptors
    # Script 1 in room 10 at offset 0x50 (for testing)
    mock_state.dscr[1] = Resource(room_no=10, room_offset=0x50)
    
    # Script 5 in room 10 at offset 0x100
    mock_state.dscr[5] = Resource(room_no=10, room_offset=0x100)
    
    # Script 15 in room 20 at offset 0x200
    mock_state.dscr[15] = Resource(room_no=20, room_offset=0x200)
    
    # Map room IDs to addresses
    mock_state.room_ids[10] = 0x2000  # Room 10 starts at 0x2000
    mock_state.room_ids[20] = 0x3000  # Room 20 starts at 0x3000
    
    # Map block addresses to script addresses
    mock_state.block_to_script[0x2050] = 0x123456  # Script 1 at 0x123456
    mock_state.block_to_script[0x2100] = 0xABCDEF  # Script 5 at 0xABCDEF
    mock_state.block_to_script[0x3200] = 0xDEFABC  # Script 15 at 0xDEFABC
    
    return mock_state


# These tests were removed because they depended on legacy decoder functionality
# that has been replaced by the new object-oriented decoder:
# - test_lift_talk_actor_with_state: Relied on complex state-based message parsing
# - test_lift_talk_actor_with_unknown_string: Tested legacy string resolution
# - test_lift_start_script_with_state: Used prev_instruction method (removed)
# - test_lift_start_script_with_multiple_args: Used prev_instruction method (removed)
#
# The new decoder handles these instructions more simply as intrinsic operations
# without the complex state tracking that the legacy decoder implemented.


def test_state_object_creation() -> None:
    """Test that our mock state objects are created correctly."""
    # Test string state
    string_state = create_mock_state_with_strings()
    assert "Hello World" in string_state.bstr
    assert string_state.bstr["Hello World"] == 0xCAFE0000
    
    # Test script state
    script_state = create_mock_state_with_scripts()
    assert len(script_state.dscr) == 20
    assert script_state.dscr[5] is not None
    assert script_state.dscr[5].room_no == 10
    assert script_state.dscr[5].room_offset == 0x100
    assert script_state.room_ids[10] == 0x2000
    assert script_state.block_to_script[0x2100] == 0xABCDEF


def test_mock_view_functionality() -> None:
    """Test that our MockScumm6View works correctly."""
    mock_state = State()
    mock_view = MockScumm6View(mock_state, "test_file.bsc6")
    
    # Test basic properties
    assert mock_view.state == mock_state
    assert mock_view.file.filename == "test_file.bsc6"
    
    # Test memory operations
    test_data = b'\xba\x5f\x00\x05'
    mock_view.write_memory(0x1000, test_data)
    
    read_data = mock_view.read(0x1000, 4)
    assert read_data == test_data
    
    # Test out-of-bounds read
    oob_data = mock_view.read(0x200000, 10)  # Beyond 1MB buffer
    assert oob_data == b'\x00' * 10


if __name__ == "__main__":
    pytest.main([__file__])
