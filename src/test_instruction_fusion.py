#!/usr/bin/env python3
"""
Tests for instruction fusion functionality.

Tests the simplified look-behind fusion mechanism where consumer instructions
(like add, sub) attempt to fuse with preceding push instructions.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from binja_helpers import binja_api  # noqa: F401

from .pyscumm6.disasm import decode_with_fusion


class TestInstructionFusion:
    """Test cases for instruction fusion patterns."""
    
    def test_single_operand_fusion(self) -> None:
        """Test fusion of push_byte + add (partial fusion)."""
        # Bytecode: push_byte(5), add
        # Expected: add(5, ...) - one operand fused, still needs one from stack
        bytecode = bytes([
            0x00, 0x05,  # push_byte(5) - corrected opcode
            0x14         # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Debug: print what we actually got
        print(f"Got instruction: {instruction.__class__.__name__}")
        print(f"Fused operands: {len(instruction.fused_operands)}")
        
        # Should be an add instruction
        assert instruction.__class__.__name__ == "Add"
        
        # Should have one fused operand
        assert len(instruction.fused_operands) == 1
        
        # Should still need one stack pop (2 - 1 fused = 1)
        assert instruction.stack_pop_count == 1
        
        # Total length should include both instructions
        assert instruction.length() == 3  # push_byte(2) + add(1)
        
        # Render should show partial fusion
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(5, ...)" in token_text
    
    def test_double_operand_fusion(self) -> None:
        """Test fusion of push_byte + push_byte + add (complete fusion)."""
        # Bytecode: push_byte(10), push_byte(5), add
        # Expected: add(10, 5) - both operands fused, no stack pops needed
        bytecode = bytes([
            0x00, 0x0A,  # push_byte(10) - corrected opcode
            0x00, 0x05,  # push_byte(5) - corrected opcode
            0x14         # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be an add instruction
        assert instruction.__class__.__name__ == "Add"
        
        # Should have two fused operands
        assert len(instruction.fused_operands) == 2
        
        # Should not need any stack pops (2 - 2 fused = 0)
        assert instruction.stack_pop_count == 0
        
        # Total length should include all three instructions
        assert instruction.length() == 5  # push_byte(2) + push_byte(2) + add(1)
        
        # Render should show complete fusion
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(10, 5)" in token_text
    
    def test_push_word_fusion(self) -> None:
        """Test fusion with push_word instead of push_byte."""
        # Bytecode: push_word(1000), add
        bytecode = bytes([
            0x01, 0xE8, 0x03,  # push_word(1000) - corrected opcode, little endian
            0x14               # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be an add instruction with one fused operand
        assert instruction.__class__.__name__ == "Add"
        assert len(instruction.fused_operands) == 1
        assert instruction.stack_pop_count == 1
        
        # Total length
        assert instruction.length() == 4  # push_word(3) + add(1)
        
        # Should show the correct value
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(1000, ...)" in token_text
    
    def test_push_var_fusion(self) -> None:
        """Test fusion with push_byte_var."""
        # Bytecode: push_byte_var(56), add  
        bytecode = bytes([
            0x02, 0x38,  # push_byte_var(var_56) - 2 bytes total (opcode + data)
            0x14         # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be an add instruction with one fused operand
        assert instruction.__class__.__name__ == "Add"
        assert len(instruction.fused_operands) == 1
        assert instruction.stack_pop_count == 1
        
        # Should show the variable name
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(var_56, ...)" in token_text
    
    def test_no_fusion_with_non_push(self) -> None:
        """Test that fusion doesn't happen with non-push instructions."""
        # Bytecode: dup, add (dup is not a push instruction)
        bytecode = bytes([
            0x0C,  # dup
            0x14   # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # The decoder returns the last instruction, which should be an Add
        # but with no fused operands since Dup is not fusible
        assert instruction.__class__.__name__ == "Add"
        
        # Should have no fused operands (dup is not fusible)
        assert len(instruction.fused_operands) == 0
        
        # Should still need 2 stack pops since no fusion occurred
        assert instruction.stack_pop_count == 2
        
        # Length should be just the add instruction (1 byte)
        assert instruction.length() == 1
    
    def test_sub_instruction_fusion(self) -> None:
        """Test that fusion works with other binary operations like sub."""
        # Bytecode: push_byte(20), push_byte(5), sub
        # Expected: sub(20, 5) 
        bytecode = bytes([
            0x00, 0x14,  # push_byte(20) - corrected opcode
            0x00, 0x05,  # push_byte(5) - corrected opcode
            0x15         # sub
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be a sub instruction
        assert instruction.__class__.__name__ == "Sub"
        
        # Should have two fused operands
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Should show correct operation
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "sub(20, 5)" in token_text
    
    def test_mixed_push_types_fusion(self) -> None:
        """Test fusion with mixed push types (byte and word)."""
        # Bytecode: push_word(500), push_byte(3), add
        bytecode = bytes([
            0x01, 0xF4, 0x01,  # push_word(500) - corrected opcode
            0x00, 0x03,        # push_byte(3) - corrected opcode
            0x14               # add
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should have both operands fused
        assert instruction.__class__.__name__ == "Add"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Should show both values
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(500, 3)" in token_text
    
    def test_fusion_operand_order(self) -> None:
        """Test that operand order is correct in fusion (stack semantics)."""
        # In stack semantics: push A; push B; add means B + A (last pushed is first operand)
        # So push(10); push(5); add should render as add(10, 5) meaning 10 + 5
        bytecode = bytes([
            0x00, 0x0A,  # push_byte(10) - corrected opcode - this goes on stack first
            0x00, 0x05,  # push_byte(5) - corrected opcode - this goes on stack second (top)
            0x14         # add - should pop 5 first, then 10, so result is 10 + 5
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # The fused operands should preserve the semantic order
        assert len(instruction.fused_operands) == 2
        
        # First fused operand should be the first pushed (10)
        first_operand = instruction.fused_operands[0]
        assert hasattr(first_operand.op_details.body, 'data')
        assert first_operand.op_details.body.data == 10
        
        # Second fused operand should be the second pushed (5)
        second_operand = instruction.fused_operands[1]
        assert hasattr(second_operand.op_details.body, 'data')
        assert second_operand.op_details.body.data == 5
        
        # Should render as add(10, 5)
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "add(10, 5)" in token_text


if __name__ == "__main__":
    pytest.main([__file__])