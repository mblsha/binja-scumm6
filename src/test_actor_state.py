"""Tests for actor state virtual memory mapping.

This file demonstrates different testing styles for the actor_state module.
"""
# mypy: disable-error-code=no-untyped-def

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from .actor_state import (
    get_actor_property_address, get_current_actor_property_address,
    ActorMemory, ActorState, ActorProperty,
    get_actor_base_address, get_property_info, is_valid_actor_address,
    get_actor_and_property_from_address, generate_actor_struct_definition,
    MAX_ACTORS, ACTORS_START, ACTOR_STRUCT_SIZE, ACTOR_PROPERTIES, 
    CURRENT_ACTOR_ADDRESS
)


# ==============================================================================
# Testing Style 1: Traditional unit tests with explicit assertions
# ==============================================================================

class TestTraditionalStyle:
    """Traditional testing style with explicit test methods."""
    
    def test_simple_function_api(self):
        """Test the simple function-based API."""
        # Test valid property access with enum
        addr = get_actor_property_address(0, ActorProperty.X)
        assert addr == ACTORS_START + 0x08  # Base + x offset
        
        # Test with string for compatibility
        addr = get_actor_property_address(0, "x")
        assert addr == ACTORS_START + 0x08  # Same result
        
        addr = get_actor_property_address(5, ActorProperty.COSTUME)
        assert addr == ACTORS_START + (5 * 64) + 0x02
        
        # Test bounds checking
        with pytest.raises(ValueError, match="out of bounds"):
            get_actor_property_address(32, ActorProperty.X)
        
        with pytest.raises(ValueError, match="Unknown actor property"):
            get_actor_property_address(0, "invalid_prop")
    
    def test_fluent_api(self):
        """Test the fluent interface API."""
        # Test chained calls with enum
        am = ActorMemory()
        addr = am.actor(3).prop(ActorProperty.FLAGS).address
        assert addr == ACTORS_START + (3 * 64) + 0x22
        
        # Test with string property
        addr = am.actor(3).prop("flags").address
        assert addr == ACTORS_START + (3 * 64) + 0x22
        
        # Test getting property info
        info = am.actor(0).prop(ActorProperty.ELEVATION).info()
        assert info.size == 2
        assert info.type == "s16"
        
        # Test base address without property
        base = am.actor(10).address
        assert base == ACTORS_START + (10 * 64)
    
    def test_dictionary_api(self):
        """Test the dictionary-style API."""
        actors = ActorState()
        
        # Test property access with enum
        addr, info = actors[7][ActorProperty.WALK_SPEED_X]
        assert addr == ACTORS_START + (7 * 64) + 0x14
        assert info.size == 2
        assert info.type == "u16"
        
        # Test with string property
        addr, info = actors[7]["walk_speed_x"]
        assert addr == ACTORS_START + (7 * 64) + 0x14
        assert info.size == 2
        assert info.type == "u16"
        
        # Test base address
        base = actors[15].base_address
        assert base == ACTORS_START + (15 * 64)
    
    def test_helper_functions(self):
        """Test various helper functions."""
        # Test base address calculation
        assert get_actor_base_address(0) == ACTORS_START
        assert get_actor_base_address(31) == ACTORS_START + (31 * 64)
        
        # Test property info lookup
        info = get_property_info("anim_counter")
        assert info.offset == 0x24
        assert info.size == 2
        
        # Test address validation
        assert is_valid_actor_address(ACTORS_START)
        assert is_valid_actor_address(ACTORS_START + (31 * 64) + 63)
        assert not is_valid_actor_address(ACTORS_START - 1)
        assert not is_valid_actor_address(ACTORS_START + (32 * 64))
        
        # Test reverse lookup
        result = get_actor_and_property_from_address(ACTORS_START + 0x08)
        assert result == (0, "x")
        
        result = get_actor_and_property_from_address(ACTORS_START + (5 * 64) + 0x02)
        assert result == (5, "costume")
    
    def test_current_actor_functionality(self):
        """Test current actor property address calculations."""
        # Test current actor address calculation with enum
        current_addr, prop_offset = get_current_actor_property_address(ActorProperty.X)
        assert current_addr == CURRENT_ACTOR_ADDRESS
        assert prop_offset == 0x08
        
        # Test with string property
        current_addr, prop_offset = get_current_actor_property_address("flags")
        assert current_addr == CURRENT_ACTOR_ADDRESS
        assert prop_offset == 0x22


# ==============================================================================
# Testing Style 2: BDD-style tests with given-when-then structure
# ==============================================================================

class TestBDDStyle:
    """Behavior-driven development style tests."""
    
    def test_actor_position_tracking(self):
        """
        Given an actor at index 3
        When I access its position properties
        Then I should get the correct memory addresses
        """
        # Given
        actor_index = 3
        
        # When
        x_addr = get_actor_property_address(actor_index, "x")
        y_addr = get_actor_property_address(actor_index, "y")
        
        # Then
        expected_base = ACTORS_START + (actor_index * ACTOR_STRUCT_SIZE)
        assert x_addr == expected_base + 0x08
        assert y_addr == expected_base + 0x0A
        assert y_addr == x_addr + 2  # y follows x
    
    def test_actor_state_modification_scenario(self):
        """
        Given an actor that needs to be initialized
        When I set multiple properties
        Then I should get sequential memory addresses for efficient updates
        """
        # Given
        actor = ActorMemory().actor(10)
        
        # When
        costume_addr = actor.prop("costume").address
        x_addr = actor.prop("x").address
        y_addr = actor.prop("y").address
        room_addr = actor.prop("room").address
        
        # Then
        # Properties in the same section should be close together
        assert x_addr == y_addr - 2  # Sequential in Position section
        assert room_addr == y_addr + 4  # After elevation
        assert costume_addr < x_addr  # Costume is in Identity section


# ==============================================================================
# Testing Style 3: Parameterized tests for comprehensive coverage
# ==============================================================================

class TestParameterizedStyle:
    """Parameterized tests for comprehensive property coverage."""
    
    @pytest.mark.parametrize("actor_index", [0, 1, 15, 31])
    @pytest.mark.parametrize("property_name,expected_offset", [
        ("id", 0x00),
        ("x", 0x08),
        ("flags", 0x22),
        ("anim_counter", 0x24),
        ("talk_pos_x", 0x2C),
    ])
    def test_property_addresses(self, actor_index, property_name, expected_offset):
        """Test that all properties have correct offsets for any actor."""
        addr = get_actor_property_address(actor_index, property_name)
        expected = ACTORS_START + (actor_index * ACTOR_STRUCT_SIZE) + expected_offset
        assert addr == expected
    
    @pytest.mark.parametrize("invalid_index", [-1, 32, 100])
    def test_invalid_actor_indices(self, invalid_index):
        """Test that invalid actor indices are rejected."""
        with pytest.raises(ValueError):
            get_actor_property_address(invalid_index, "x")
    
    @pytest.mark.parametrize("api_call,expected_addr", [
        (lambda: get_actor_property_address(0, "x"), 0x40001c58),
        (lambda: ActorMemory().actor(0).prop("x").address, 0x40001c58),
        (lambda: ActorState()[0]["x"][0], 0x40001c58),
    ])
    def test_api_consistency(self, api_call, expected_addr):
        """Test that all APIs return the same address."""
        assert api_call() == expected_addr


# ==============================================================================
# Testing Style 4: Property-based testing with hypothesis
# ==============================================================================

try:
    from hypothesis import given, strategies as st
    
    class TestPropertyBasedStyle:
        """Property-based tests using hypothesis."""
        
        @given(
            actor_index=st.integers(min_value=0, max_value=MAX_ACTORS-1),
            property_name=st.sampled_from(list(ACTOR_PROPERTIES.keys()))
        )
        def test_address_uniqueness(self, actor_index, property_name):
            """Every actor/property combination should have a unique address."""
            addr = get_actor_property_address(actor_index, property_name)
            
            # Address should be within valid range
            assert is_valid_actor_address(addr)
            
            # Reverse lookup should return the same actor/property
            result = get_actor_and_property_from_address(addr)
            assert result is not None
            assert result[0] == actor_index
            assert result[1] == property_name
        
        @given(
            actor1=st.integers(min_value=0, max_value=MAX_ACTORS-1),
            actor2=st.integers(min_value=0, max_value=MAX_ACTORS-1),
            property_name=st.sampled_from(list(ACTOR_PROPERTIES.keys()))
        )
        def test_actor_separation(self, actor1, actor2, property_name):
            """Properties of different actors should be separated by ACTOR_STRUCT_SIZE."""
            if actor1 != actor2:
                addr1 = get_actor_property_address(actor1, property_name)
                addr2 = get_actor_property_address(actor2, property_name)
                
                diff = abs(addr2 - addr1)
                assert diff % ACTOR_STRUCT_SIZE == 0

except ImportError:
    # Hypothesis not installed, skip these tests
    pass


# ==============================================================================
# Testing Style 5: Doctest-style inline examples
# ==============================================================================

def example_usage():
    """
    Example usage of the actor state API.
    
    >>> # Simple function API
    >>> addr = get_actor_property_address(5, "x")
    >>> hex(addr)
    '0x40001d98'
    
    >>> # Fluent API
    >>> am = ActorMemory()
    >>> addr = am.actor(0).prop("costume").address
    >>> hex(addr)
    '0x40001c52'
    
    >>> # Dictionary API
    >>> actors = ActorState()
    >>> addr, info = actors[10]["flags"]
    >>> hex(addr)
    '0x40001ef2'
    >>> info.size
    2
    
    >>> # Reverse lookup
    >>> actor, prop = get_actor_and_property_from_address(0x40001c58)
    >>> actor, prop
    (0, 'x')
    """
    pass


def test_generated_actor_struct_definition():
    """Test that the generated actor struct matches expected definition."""
    # Generate the struct
    generated = generate_actor_struct_definition()
    
    # Expected struct definition based on ActorProperty enum
    # This serves as a regression test to ensure the struct format doesn't change unexpectedly
    expected = """struct Actor {
    uint16_t id; // 0x00
    uint16_t costume; // 0x02
    uint32_t name_ptr; // 0x04
    uint16_t x; // 0x08
    uint16_t y; // 0x0A
    int16_t elevation; // 0x0C
    uint8_t room; // 0x0E
    uint8_t layer; // 0x0F
    uint16_t target_x; // 0x10
    uint16_t target_y; // 0x12
    uint16_t walk_speed_x; // 0x14
    uint16_t walk_speed_y; // 0x16
    uint8_t facing_direction; // 0x18
    uint8_t moving; // 0x19
    uint8_t walk_box; // 0x1A
    uint8_t ignore_boxes; // 0x1B
    uint8_t scale_x; // 0x1C
    uint8_t scale_y; // 0x1D
    uint8_t width; // 0x1E
    uint8_t palette; // 0x1F
    uint8_t talk_color; // 0x20
    uint8_t never_zclip; // 0x21
    uint16_t flags; // 0x22
    uint16_t anim_counter; // 0x24
    uint8_t current_anim; // 0x26
    uint8_t walk_frame; // 0x27
    uint8_t stand_frame; // 0x28
    uint8_t talk_frame; // 0x29
    uint8_t anim_speed; // 0x2A
    uint8_t loop_flag; // 0x2B
    int16_t talk_pos_x; // 0x2C
    int16_t talk_pos_y; // 0x2E
    uint8_t _pad1[16];
}"""
    
    # Compare the full multi-line string
    assert generated == expected, f"Generated struct does not match expected.\n\nExpected:\n{expected}\n\nGenerated:\n{generated}"


if __name__ == "__main__":
    # Run doctests
    import doctest
    doctest.testmod()
    
    # Run pytest
    pytest.main([__file__, "-v"])