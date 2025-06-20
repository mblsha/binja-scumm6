"""Test cases for function call instruction fusion.

This module tests fusion of push instructions with function call instructions
like draw_object, start_script, walk_actor_to, etc.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from binja_helpers import binja_api  # noqa: F401

from .pyscumm6.disasm import decode_with_fusion


class TestFunctionCallFusion:
    """Test cases for function call instruction fusion patterns."""
    
    def test_draw_object_fusion(self) -> None:
        """Test fusion of push instructions with draw_object."""
        # Bytecode: push_word(100), push_byte(2), draw_object
        bytecode = bytes([
            0x01, 0x64, 0x00,  # push_word(100) - object_id
            0x00, 0x02,        # push_byte(2)   - state
            0x61               # draw_object
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be draw_object with two fused operands
        assert instruction.__class__.__name__ == "DrawObject"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "draw_object(100, 2)"
    
    def test_draw_object_partial_fusion(self) -> None:
        """Test partial fusion with draw_object (only one operand fused)."""
        # Bytecode: push_byte(2), draw_object (missing first operand)
        bytecode = bytes([
            0x00, 0x02,  # push_byte(2) - state
            0x61         # draw_object
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be draw_object with one fused operand
        assert instruction.__class__.__name__ == "DrawObject"
        assert len(instruction.fused_operands) == 1
        assert instruction.stack_pop_count == 1  # Still needs one from stack
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert "draw_object(2)" in token_text
    
    def test_walk_actor_to_fusion(self) -> None:
        """Test fusion with walk_actor_to (3 parameters)."""
        # Bytecode: push_byte(1), push_word(200), push_word(150), walk_actor_to
        bytecode = bytes([
            0x00, 0x01,        # push_byte(1)    - actor_id
            0x01, 0xC8, 0x00,  # push_word(200)  - x
            0x01, 0x96, 0x00,  # push_word(150)  - y
            0x7E               # walk_actor_to
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be walk_actor_to with three fused operands
        assert instruction.__class__.__name__ == "WalkActorTo"
        assert len(instruction.fused_operands) == 3
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "walk_actor_to(1, 200, 150)"
    
    def test_start_sound_fusion(self) -> None:
        """Test fusion with single-parameter function (start_sound)."""
        # Bytecode: push_word(42), start_sound
        bytecode = bytes([
            0x01, 0x2A, 0x00,  # push_word(42) - sound_id
            0x74               # start_sound
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be start_sound with one fused operand
        assert instruction.__class__.__name__ == "StartSound"
        assert len(instruction.fused_operands) == 1
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "start_sound(42)"
    
    def test_function_with_var_fusion(self) -> None:
        """Test fusion with variable operands."""
        # Bytecode: push_byte_var(10), push_word(100), draw_object
        bytecode = bytes([
            0x02, 0x0A,        # push_byte_var(var_10) - object_id
            0x01, 0x64, 0x00,  # push_word(100)        - state
            0x61               # draw_object
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be draw_object with two fused operands
        assert instruction.__class__.__name__ == "DrawObject"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "draw_object(var_10, 100)"
    
    def test_put_actor_at_xy_fusion(self) -> None:
        """Test fusion with 4-parameter function."""
        # Bytecode: push_byte(1), push_word(100), push_word(200), push_byte(0), put_actor_at_xy
        bytecode = bytes([
            0x00, 0x01,        # push_byte(1)    - actor_id
            0x01, 0x64, 0x00,  # push_word(100)  - x
            0x01, 0xC8, 0x00,  # push_word(200)  - y
            0x00, 0x00,        # push_byte(0)    - ?
            0x7F               # put_actor_at_xy
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be put_actor_at_xy with four fused operands
        assert instruction.__class__.__name__ == "PutActorAtXy"
        assert len(instruction.fused_operands) == 4
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "put_actor_at_xy(1, 100, 200, 0)"
    
    def test_no_fusion_without_pushes(self) -> None:
        """Test that functions don't fuse with non-push instructions."""
        # Bytecode: dup, draw_object
        bytecode = bytes([
            0x0C,  # dup
            0x61   # draw_object
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be draw_object with no fused operands
        assert instruction.__class__.__name__ == "DrawObject"
        assert len(instruction.fused_operands) == 0
        assert instruction.stack_pop_count == 2  # Normal stack pops
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "draw_object"
    
    def test_mixed_constant_and_var_fusion(self) -> None:
        """Test fusion with mix of constants and variables."""
        # Bytecode: push_word_var(5), push_byte(10), push_word_var(7), walk_actor_to
        bytecode = bytes([
            0x03, 0x05, 0x00,  # push_word_var(var_5) - actor_id
            0x00, 0x0A,        # push_byte(10)        - x
            0x03, 0x07, 0x00,  # push_word_var(var_7) - y
            0x7E               # walk_actor_to
        ])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        
        # Should be walk_actor_to with three fused operands
        assert instruction.__class__.__name__ == "WalkActorTo"
        assert len(instruction.fused_operands) == 3
        assert instruction.stack_pop_count == 0
        
        # Check render output
        tokens = instruction.render()
        token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
        assert token_text == "walk_actor_to(var_5, 10, var_7)"