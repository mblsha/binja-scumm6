"""Test cases for function call instruction fusion.

This module tests fusion of push instructions with function call instructions
like draw_object, start_script, walk_actor_to, etc.
"""

from .test_utils import assert_fusion_result, assert_partial_fusion, assert_no_fusion


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
        
        assert_fusion_result(bytecode, "DrawObject", 2, "drawObject(100, 2)")
    
    def test_draw_object_partial_fusion(self) -> None:
        """Test partial fusion with draw_object (only one operand fused)."""
        # Bytecode: push_byte(2), draw_object (missing first operand)
        bytecode = bytes([
            0x00, 0x02,  # push_byte(2) - state
            0x61         # draw_object
        ])
        
        assert_partial_fusion(bytecode, "DrawObject", 1, 1)
    
    def test_walk_actor_to_fusion(self) -> None:
        """Test fusion with walk_actor_to (3 parameters)."""
        # Bytecode: push_byte(1), push_word(200), push_word(150), walk_actor_to
        bytecode = bytes([
            0x00, 0x01,        # push_byte(1)    - actor_id
            0x01, 0xC8, 0x00,  # push_word(200)  - x
            0x01, 0x96, 0x00,  # push_word(150)  - y
            0x7E               # walk_actor_to
        ])
        
        assert_fusion_result(bytecode, "WalkActorTo", 3, "walkActorTo(1, 200, 150)")
    
    def test_start_sound_fusion(self) -> None:
        """Test fusion with single-parameter function (start_sound)."""
        # Bytecode: push_word(42), start_sound
        bytecode = bytes([
            0x01, 0x2A, 0x00,  # push_word(42) - sound_id
            0x74               # start_sound
        ])
        
        assert_fusion_result(bytecode, "StartSound", 1, "startSound(42)")
    
    def test_function_with_var_fusion(self) -> None:
        """Test fusion with variable operands."""
        # Bytecode: push_byte_var(10), push_word(100), draw_object
        bytecode = bytes([
            0x02, 0x0A,        # push_byte_var(var_10) - object_id
            0x01, 0x64, 0x00,  # push_word(100)        - state
            0x61               # draw_object
        ])
        
        assert_fusion_result(bytecode, "DrawObject", 2, "drawObject(VAR_CURRENTDRIVE, 100)")
    
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
        
        assert_fusion_result(bytecode, "PutActorAtXy", 4, "putActorAtXY(1, 100, 200, 0)")
    
    def test_no_fusion_without_pushes(self) -> None:
        """Test that functions don't fuse with non-push instructions."""
        # Bytecode: dup, draw_object
        bytecode = bytes([
            0x0C,  # dup
            0x61   # draw_object
        ])
        
        assert_no_fusion(bytecode, "DrawObject")
    
    def test_mixed_constant_and_var_fusion(self) -> None:
        """Test fusion with mix of constants and variables."""
        # Bytecode: push_word_var(5), push_byte(10), push_word_var(7), walk_actor_to
        bytecode = bytes([
            0x03, 0x05, 0x00,  # push_word_var(var_5) - actor_id
            0x00, 0x0A,        # push_byte(10)        - x
            0x03, 0x07, 0x00,  # push_word_var(var_7) - y
            0x7E               # walk_actor_to
        ])
        
        assert_fusion_result(bytecode, "WalkActorTo", 3, "walkActorTo(VAR_OVERRIDE, 10, VAR_ME)")
