"""Test cases for array write instruction fusion.

This module tests fusion of push instructions with array write instructions
(byte_array_write, word_array_write) to create array assignment-style rendering.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"
from binja_helpers import binja_api  # noqa: F401

from .pyscumm6.disasm import decode_with_fusion


class TestArrayWriteFusion:
    """Test cases for array write instruction fusion patterns."""
    
    def test_byte_array_write_fusion(self) -> None:
        """Test fusion of push instructions with byte_array_write."""
        # Bytecode: push_byte(10), push_byte(3), byte_array_write(array_5)
        bytecode = bytes([
            0x00, 0x0A,  # push_byte(10) - value
            0x00, 0x03,  # push_byte(3)  - index
            0x46, 0x05   # byte_array_write(array_5)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with two fused operands
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_5[3] = 10"
    
    def test_word_array_write_fusion(self) -> None:
        """Test fusion of push instructions with word_array_write."""
        # Bytecode: push_word(1000), push_byte(7), word_array_write(array_10)  
        bytecode = bytes([
            0x01, 0xE8, 0x03,  # push_word(1000) - value
            0x00, 0x07,        # push_byte(7)    - index
            0x47, 0x0A, 0x00   # word_array_write(array_10) - note: 2-byte array ID
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be word_array_write with two fused operands
        assert instruction.__class__.__name__ == "WordArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_10[7] = 1000"
    
    def test_array_write_with_variables_fusion(self) -> None:
        """Test fusion with variable operands."""
        # Bytecode: push_byte_var(var_20), push_word_var(var_5), byte_array_write(array_3)
        bytecode = bytes([
            0x02, 0x14,  # push_byte_var(var_20) - value
            0x03, 0x05, 0x00,  # push_word_var(var_5)  - index  
            0x46, 0x03   # byte_array_write(array_3)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with two fused operands
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_3[var_5] = var_20"
    
    def test_array_write_partial_fusion(self) -> None:
        """Test partial fusion with array write (only one operand fused)."""
        # Bytecode: push_byte(5), byte_array_write(array_1) (missing index)
        bytecode = bytes([
            0x00, 0x05,  # push_byte(5) - value
            0x46, 0x01   # byte_array_write(array_1)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with one fused operand
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 1
        assert instruction.stack_pop_count == 1  # Still needs one from stack
        
        # Check render output (partial fusion should show some indication)
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "array_1[?, 5]" in token_text
    
    def test_array_write_no_fusion(self) -> None:
        """Test that array writes don't fuse with non-push instructions."""
        # Bytecode: dup, byte_array_write(array_2)
        bytecode = bytes([
            0x0C,        # dup
            0x46, 0x02   # byte_array_write(array_2)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with no fused operands
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 0
        assert instruction.stack_pop_count == 2  # Normal stack pops
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "byte_array_write(array_2)"
    
    def test_array_write_mixed_types_fusion(self) -> None:
        """Test fusion with mix of constant and variable operands."""
        # Bytecode: push_word_var(var_100), push_word(50), word_array_write(array_7)
        bytecode = bytes([
            0x03, 0x64, 0x00,  # push_word_var(var_100) - value
            0x01, 0x32, 0x00,  # push_word(50)          - index
            0x47, 0x07, 0x00   # word_array_write(array_7) - note: 2-byte array ID
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be word_array_write with two fused operands
        assert instruction.__class__.__name__ == "WordArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_7[50] = var_100"
    
    def test_array_write_zero_index_fusion(self) -> None:
        """Test fusion with zero index (common pattern)."""
        # Bytecode: push_byte(42), push_byte(0), byte_array_write(array_0)
        bytecode = bytes([
            0x00, 0x2A,  # push_byte(42) - value
            0x00, 0x00,  # push_byte(0)  - index
            0x46, 0x00   # byte_array_write(array_0)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with two fused operands
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_0[0] = 42"
    
    def test_array_write_negative_values_fusion(self) -> None:
        """Test fusion with negative values."""
        # Bytecode: push_byte(-1), push_byte(5), byte_array_write(array_15)
        bytecode = bytes([
            0x00, 0xFF,  # push_byte(-1) - value (255 unsigned, -1 signed)
            0x00, 0x05,  # push_byte(5)  - index
            0x46, 0x0F   # byte_array_write(array_15)
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be byte_array_write with two fused operands
        assert instruction.__class__.__name__ == "ByteArrayWrite"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output (note: value displayed as signed)
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "array_15[5] = -1"