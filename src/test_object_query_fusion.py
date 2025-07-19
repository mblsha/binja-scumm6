#!/usr/bin/env python3
"""Test fusion for object query functions like getObjectX, getObjectY, get_state."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from binja_test_mocks import binja_api  # noqa: F401
from .pyscumm6.disasm import decode_with_fusion
from .test_utils import safe_token_text




def test_get_object_x_fusion() -> None:
    """Test that getObjectX fuses with push_word_var."""
    # push_word_var(var_5) - system variable VAR_OVERRIDE
    # getObjectX
    bytecode = bytes([
        0x03, 0x05, 0x00,  # push_word_var(var_5) - system variable
        0x8D               # getObjectX
    ])
    
    instruction = decode_with_fusion(bytecode, 0x0)
    assert instruction is not None
    assert instruction.__class__.__name__ == "GetObjectX"
    assert len(instruction.fused_operands) == 1
    assert instruction.fused_operands[0].__class__.__name__ == "PushWordVar"
    assert instruction.stack_pop_count == 0  # No stack pops needed
    
    text = safe_token_text(instruction.render())
    assert text == "getObjectX(VAR_OVERRIDE)"


def test_get_object_y_fusion() -> None:
    """Test that getObjectY fuses with push_word_var."""
    # push_word_var(var_10) - system variable VAR_CURRENTDRIVE
    # getObjectY
    bytecode = bytes([
        0x03, 0x0A, 0x00,  # push_word_var(var_10) - system variable
        0x8E               # getObjectY
    ])
    
    instruction = decode_with_fusion(bytecode, 0x0)
    assert instruction is not None
    assert instruction.__class__.__name__ == "GetObjectY"
    assert len(instruction.fused_operands) == 1
    assert instruction.fused_operands[0].__class__.__name__ == "PushWordVar"
    assert instruction.stack_pop_count == 0
    
    text = safe_token_text(instruction.render())
    assert text == "getObjectY(VAR_CURRENTDRIVE)"


def test_get_state_fusion() -> None:
    """Test that get_state fuses with push_word_var."""
    # push_word_var(var_0) - system variable VAR_KEYPRESS
    # get_state
    bytecode = bytes([
        0x03, 0x00, 0x00,  # push_word_var(var_0) - system variable
        0x6F               # get_state (111 = 0x6F)
    ])
    
    instruction = decode_with_fusion(bytecode, 0x0)
    assert instruction is not None
    assert instruction.__class__.__name__ == "GetState"
    assert len(instruction.fused_operands) == 1
    assert instruction.fused_operands[0].__class__.__name__ == "PushWordVar"
    assert instruction.stack_pop_count == 0
    
    text = safe_token_text(instruction.render())
    assert text == "getState(VAR_KEYPRESS)"


def test_get_object_x_fusion_with_constant() -> None:
    """Test that getObjectX fuses with push_word (constant)."""
    # push_word(42)
    # getObjectX
    bytecode = bytes([
        0x01, 0x2A, 0x00,  # push_word(42)
        0x8D               # getObjectX
    ])
    
    instruction = decode_with_fusion(bytecode, 0x0)
    assert instruction is not None
    assert instruction.__class__.__name__ == "GetObjectX"
    assert len(instruction.fused_operands) == 1
    assert instruction.fused_operands[0].__class__.__name__ == "PushWord"
    assert instruction.stack_pop_count == 0
    
    text = safe_token_text(instruction.render())
    assert text == "getObjectX(42)"


def test_complex_expression_with_object_queries() -> None:
    """Test complex expression: sub(getObjectX(var_0), var_1).
    
    Note: Due to the current fusion algorithm's behavior, this complex
    expression gets parsed differently than expected. The test documents
    the actual behavior rather than the ideal behavior.
    """
    # This is from the actual room8_scrp18 script
    bytecode = bytes([
        0x03, 0x00, 0x40,  # push_word_var(var_0)
        0x8D,              # getObjectX
        0x03, 0x01, 0x40,  # push_word_var(var_1)
        0x15               # sub
    ])
    
    # Decode the full sequence
    addr = 0
    instructions = []
    while addr < len(bytecode):
        instr = decode_with_fusion(bytecode[addr:], addr)
        if instr is None:
            break
        instructions.append(instr)
        addr += instr.length()
    
    # With the enhanced fusion algorithm, this now correctly creates a single
    # Sub instruction that has fused with both getObjectX and the push_word_var
    assert len(instructions) == 1
    
    # The single instruction is a Sub with fused operands
    assert instructions[0].__class__.__name__ == "Sub"
    assert len(instructions[0].fused_operands) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])