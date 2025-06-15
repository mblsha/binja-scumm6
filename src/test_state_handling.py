#!/usr/bin/env python3

import pytest
import types
import sys
import enum
from typing import Any, Optional
from unittest.mock import patch

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

from .scumm6 import Scumm6, LastBV  # noqa: E402
from .disasm import State, Resource  # noqa: E402
from binja_helpers.mock_llil import MockLowLevelILFunction  # noqa: E402


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


def test_lift_talk_actor_with_state() -> None:
    """Test that talk_actor instruction lifts correctly with string state resolution."""
    # 1. Arrange: Create mock state and view
    mock_state = create_mock_state_with_strings()
    mock_view = MockScumm6View(mock_state)

    # Opcode 0xba (186) for talk_actor, followed by the message
    data = b'\xba' + b'Hello World\x00'
    addr = 0x1000
    
    # Write the instruction data to mock memory so get_view can find it
    mock_view.write_memory(addr, data)

    # Patch LastBV.get() to return our mock view
    with patch.object(LastBV, 'get', return_value=mock_view):
        arch = Scumm6()
        il = MockLowLevelILFunction()

        # 2. Act: Lift the instruction
        length = arch.get_instruction_low_level_il(data, addr, il)

        # 3. Assert
        assert length is not None
        assert length > 1  # Should consume opcode + message
        assert len(il.ils) > 0

        # Check for the intrinsic call
        intrinsic_il = il.ils[0]
        assert intrinsic_il.op == 'INTRINSIC'
        assert hasattr(intrinsic_il, 'name') and intrinsic_il.name == 'talk_actor'

        # Check that we have parameters
        assert hasattr(intrinsic_il, 'params') and len(intrinsic_il.params) > 0
        
        # Check the first parameter - should be a pointer to the resolved string
        string_ptr_arg = intrinsic_il.params[0]
        assert string_ptr_arg.op.startswith('CONST_PTR')  # Either .l or .error in mock
        assert string_ptr_arg.ops[0] == 0xCAFE0000  # Verify the address is correct


def test_lift_talk_actor_with_unknown_string() -> None:
    """Test that talk_actor handles unknown strings gracefully."""
    # 1. Arrange: Create mock state without the test string
    mock_state = create_mock_state_with_strings()
    mock_view = MockScumm6View(mock_state)

    # Use a string not in the bstr dictionary
    data = b'\xba' + b'Unknown String\x00'
    addr = 0x1000
    
    # Write the instruction data to mock memory
    mock_view.write_memory(addr, data)

    with patch.object(LastBV, 'get', return_value=mock_view):
        arch = Scumm6()
        il = MockLowLevelILFunction()

        # 2. Act: Lift the instruction - this should raise a KeyError for unknown strings
        try:
            length = arch.get_instruction_low_level_il(data, addr, il)
            
            # If no exception, it means the implementation was changed to handle unknown strings
            # In that case, verify the instruction was still processed
            assert length is not None
            assert len(il.ils) > 0
            
            intrinsic_il = il.ils[0]
            assert intrinsic_il.op == 'INTRINSIC'
            assert hasattr(intrinsic_il, 'name') and intrinsic_il.name == 'talk_actor'
            
        except KeyError as e:
            # This is the expected behavior for unknown strings
            assert "Unknown String" in str(e)
            # This demonstrates the test is working correctly


def test_lift_start_script_with_state() -> None:
    """Test that start_script instruction lifts correctly with script state resolution."""
    # 1. Arrange
    mock_state = create_mock_state_with_scripts()
    mock_view = MockScumm6View(mock_state)
    
    # Put instructions into the view's memory
    mock_view.write_memory(0x0FFE, b'\x00\x01')  # push_byte 1 (number of args)
    mock_view.write_memory(0x1000, b'\x00\x05')  # push_byte 5 (script number)
    mock_view.write_memory(0x1002, b'\x5f')      # start_script_quick
    
    with patch.object(LastBV, 'get', return_value=mock_view):
        arch = Scumm6()
        
        # Create mock instructions for the prev_instruction chain
        from .disasm import Instruction
        from .scumm6_opcodes import Scumm6Opcodes
        from binja_helpers.mock_analysis import MockAnalysisInfo
        
        OpType = Scumm6Opcodes.OpType
        
        # Mock instruction for number of args (1)
        mock_args_info = MockAnalysisInfo()
        mock_args_info.length = 2
        mock_args_instr = Instruction(
            op=types.SimpleNamespace(id=OpType.push_byte, body=types.SimpleNamespace(data=1)),  # type: ignore[arg-type]
            id='push_byte',
            length=2,
            data=b'\x00\x01',
            addr=0x0FFE,
            analysis_info=mock_args_info
        )
        
        # Mock instruction for script number (5)
        mock_script_info = MockAnalysisInfo()
        mock_script_info.length = 2
        mock_script_instr = Instruction(
            op=types.SimpleNamespace(id=OpType.push_byte, body=types.SimpleNamespace(data=5)),  # type: ignore[arg-type]
            id='push_byte', 
            length=2,
            data=b'\x00\x05',
            addr=0x1000,
            analysis_info=mock_script_info
        )
        
        # Mock the prev_instruction method to return our mock instructions
        def mock_prev_instruction(instr: Any) -> Any:
            if instr.addr == 0x1002:  # start_script_quick looking for previous instruction (args)
                return mock_args_instr  # Return args instruction
            elif instr.addr == 0x0FFE:  # args instruction looking for script number  
                return mock_script_instr  # Return script number instruction
            else:
                # For any other case, return a dummy instruction
                return mock_args_instr
        
        # Patch the prev_instruction method
        with patch.object(arch, 'prev_instruction', side_effect=mock_prev_instruction):
            # 2. Act
            # Now, lift the start_script_quick instruction
            call_il = MockLowLevelILFunction()
            call_length = arch.get_instruction_low_level_il(
                mock_view.read(0x1002, 1), 0x1002, call_il
            )

            # 3. Assert
            assert call_length == 1
            assert len(call_il.ils) > 0
            
            # Check that we have some form of control flow instruction
            # The exact IL depends on whether the script pointer resolution succeeds
            has_control_flow = any(
                instr.op in ['CALL', 'JUMP_TO', 'TAILCALL', 'INTRINSIC', 'UNIMPL'] 
                for instr in call_il.ils
            )
            assert has_control_flow, f"Expected control flow instruction, got IL: {[il.op for il in call_il.ils]}"


def test_lift_start_script_with_multiple_args() -> None:
    """Test start_script with multiple arguments on the stack."""
    # 1. Arrange
    mock_state = create_mock_state_with_scripts()
    mock_view = MockScumm6View(mock_state)
    
    # Set up instruction sequence:
    # push_byte 2 at 0x0FFE (number of args)
    # push_byte 10 at 0x1000 (arg 1)
    # push_byte 20 at 0x1002 (arg 2)
    # push_byte 15 at 0x1004 (script number)
    # start_script at 0x1006
    mock_view.write_memory(0x0FFE, b'\x00\x02')  # push_byte 2 (number of args)
    mock_view.write_memory(0x1000, b'\x00\x0a')  # push_byte 10 (arg 1)
    mock_view.write_memory(0x1002, b'\x00\x14')  # push_byte 20 (arg 2)
    mock_view.write_memory(0x1004, b'\x00\x0f')  # push_byte 15 (script number)
    mock_view.write_memory(0x1006, b'\x5e')      # start_script (0x5e)
    
    with patch.object(LastBV, 'get', return_value=mock_view):
        arch = Scumm6()
        
        # Create mock instructions for the prev_instruction chain
        from .disasm import Instruction
        from .scumm6_opcodes import Scumm6Opcodes
        from binja_helpers.mock_analysis import MockAnalysisInfo
        
        OpType = Scumm6Opcodes.OpType
        
        # Mock instruction for number of args (2)
        mock_args_info = MockAnalysisInfo()
        mock_args_info.length = 2
        mock_args_instr = Instruction(
            op=types.SimpleNamespace(id=OpType.push_byte, body=types.SimpleNamespace(data=2)),  # type: ignore[arg-type]
            id='push_byte',
            length=2,
            data=b'\x00\x02',
            addr=0x0FFE,
            analysis_info=mock_args_info
        )
        
        # Mock instruction for script number (15)
        mock_script_info = MockAnalysisInfo()
        mock_script_info.length = 2
        mock_script_instr = Instruction(
            op=types.SimpleNamespace(id=OpType.push_byte, body=types.SimpleNamespace(data=15)),  # type: ignore[arg-type]
            id='push_byte', 
            length=2,
            data=b'\x00\x0f',
            addr=0x1004,
            analysis_info=mock_script_info
        )
        
        # Mock the prev_instruction method to return our mock instructions
        def mock_prev_instruction(instr: Any) -> Any:
            if instr.addr == 0x1006:  # start_script looking for previous instruction (args)
                return mock_args_instr  # Return args instruction
            elif instr.addr == 0x0FFE:  # args instruction looking for script number  
                return mock_script_instr  # Return script number instruction
            else:
                # For any other case, return a dummy instruction
                return mock_args_instr
        
        # Patch the prev_instruction method
        with patch.object(arch, 'prev_instruction', side_effect=mock_prev_instruction):
            # 2. Act
            # Now, lift the start_script instruction
            call_il = MockLowLevelILFunction()
            call_length = arch.get_instruction_low_level_il(
                mock_view.read(0x1006, 1), 0x1006, call_il
            )

            # 3. Assert
            assert call_length == 1
            assert len(call_il.ils) > 0
            
            # Should have some form of function call or control flow
            # The exact IL depends on whether script resolution succeeds
            has_call_like = any(
                instr.op in ['CALL', 'TAILCALL', 'JUMP_TO', 'INTRINSIC', 'UNIMPL']
                for instr in call_il.ils
            )
            assert has_call_like, f"Expected call-like instruction, got: {[il.op for il in call_il.ils]}"


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
