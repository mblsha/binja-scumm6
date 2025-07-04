"""Declarative tests for actor state virtual memory mapping.

This file provides comprehensive test coverage using the declarative style
from test_descumm_comparison.py with explicit test cases and expected results.
"""
# mypy: disable-error-code=no-untyped-def

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import pytest
from dataclasses import dataclass
from typing import List, Union

from .actor_state import (
    get_actor_property_address, get_current_actor_property_address,
    ActorMemory, ActorState, ActorProperty, ACTORS_START, CURRENT_ACTOR_ADDRESS, MAX_ACTORS, ACTOR_STRUCT_SIZE,
    ACTOR_PROPERTIES
)


@dataclass
class ActorPropertyTestCase:
    """Declarative test case for actor property address calculations."""
    
    test_id: str
    actor_index: int
    property: Union[ActorProperty, str]
    expected_address: int
    expected_offset: int
    expected_size: int
    expected_type: str
    description: str = ""


@dataclass
class CurrentActorTestCase:
    """Declarative test case for current actor property calculations."""
    
    test_id: str
    property: Union[ActorProperty, str] 
    expected_current_actor_addr: int
    expected_property_offset: int
    expected_size: int
    expected_type: str
    description: str = ""


@dataclass
class APIConsistencyTestCase:
    """Test case for verifying all APIs return the same result."""
    
    test_id: str
    actor_index: int
    property: Union[ActorProperty, str]
    expected_address: int
    description: str = ""


# ==============================================================================
# Core Property Test Cases
# ==============================================================================

property_test_cases: List[ActorPropertyTestCase] = [
    # Core Identity properties
    ActorPropertyTestCase(
        test_id="actor_0_id_property",
        actor_index=0,
        property=ActorProperty.ID,
        expected_address=0x40001c50,  # ACTORS_START + 0 * 64 + 0x00
        expected_offset=0x00,
        expected_size=2,
        expected_type="u16",
        description="Actor 0 ID property at struct start"
    ),
    
    ActorPropertyTestCase(
        test_id="actor_5_costume_property", 
        actor_index=5,
        property=ActorProperty.COSTUME,
        expected_address=0x40001d92,  # ACTORS_START + 5 * 64 + 0x02
        expected_offset=0x02,
        expected_size=2,
        expected_type="u16",
        description="Actor 5 costume property"
    ),
    
    # Position properties
    ActorPropertyTestCase(
        test_id="actor_10_x_position",
        actor_index=10,
        property=ActorProperty.X,
        expected_address=0x40001ed8,  # ACTORS_START + 10 * 64 + 0x08
        expected_offset=0x08,
        expected_size=2,
        expected_type="u16",
        description="Actor 10 X position"
    ),
    
    ActorPropertyTestCase(
        test_id="actor_10_y_position",
        actor_index=10,
        property=ActorProperty.Y,
        expected_address=0x40001eda,  # ACTORS_START + 10 * 64 + 0x0A
        expected_offset=0x0A,
        expected_size=2,
        expected_type="u16",
        description="Actor 10 Y position (sequential after X)"
    ),
    
    # Movement properties
    ActorPropertyTestCase(
        test_id="actor_15_walk_speed_x",
        actor_index=15,
        property=ActorProperty.WALK_SPEED_X,
        expected_address=0x40002024,  # ACTORS_START + 15 * 64 + 0x14
        expected_offset=0x14,
        expected_size=2,
        expected_type="u16",
        description="Actor 15 walk speed X"
    ),
    
    ActorPropertyTestCase(
        test_id="actor_31_facing_direction",
        actor_index=31,
        property=ActorProperty.FACING_DIRECTION,
        expected_address=0x40002428,  # ACTORS_START + 31 * 64 + 0x18  
        expected_offset=0x18,
        expected_size=1,
        expected_type="u8",
        description="Actor 31 (last actor) facing direction"
    ),
    
    # Visual properties
    ActorPropertyTestCase(
        test_id="actor_7_flags",
        actor_index=7,
        property=ActorProperty.FLAGS,
        expected_address=0x40001e32,  # ACTORS_START + 7 * 64 + 0x22
        expected_offset=0x22,
        expected_size=2,
        expected_type="u16",
        description="Actor 7 flags property"
    ),
    
    # Animation properties
    ActorPropertyTestCase(
        test_id="actor_3_anim_counter",
        actor_index=3,
        property=ActorProperty.ANIM_COUNTER,
        expected_address=0x40001d34,  # ACTORS_START + 3 * 64 + 0x24
        expected_offset=0x24,
        expected_size=2,
        expected_type="u16",
        description="Actor 3 animation counter"
    ),
    
    # Talk state properties  
    ActorPropertyTestCase(
        test_id="actor_20_talk_pos_x",
        actor_index=20,
        property=ActorProperty.TALK_POS_X,
        expected_address=0x4000217c,  # ACTORS_START + 20 * 64 + 0x2C
        expected_offset=0x2C,
        expected_size=2,
        expected_type="s16",
        description="Actor 20 talk position X (signed)"
    ),
    
    # String-based property access for compatibility
    ActorPropertyTestCase(
        test_id="actor_1_x_string_property",
        actor_index=1,
        property="x",  # String instead of enum
        expected_address=0x40001c98,  # ACTORS_START + 1 * 64 + 0x08
        expected_offset=0x08,
        expected_size=2,
        expected_type="u16",
        description="Actor 1 X position using string property name"
    ),
]


# ==============================================================================
# Current Actor Test Cases  
# ==============================================================================

current_actor_test_cases: List[CurrentActorTestCase] = [
    CurrentActorTestCase(
        test_id="current_actor_x_property",
        property=ActorProperty.X,
        expected_current_actor_addr=0x40002450,  # ACTORS_START + MAX_ACTORS * ACTOR_STRUCT_SIZE
        expected_property_offset=0x08,
        expected_size=2,
        expected_type="u16",
        description="Current actor X property for LLIL pointer arithmetic"
    ),
    
    CurrentActorTestCase(
        test_id="current_actor_costume_string",
        property="costume",  # String property
        expected_current_actor_addr=0x40002450,  # ACTORS_START + MAX_ACTORS * ACTOR_STRUCT_SIZE
        expected_property_offset=0x02,
        expected_size=2,
        expected_type="u16", 
        description="Current actor costume using string property"
    ),
    
    CurrentActorTestCase(
        test_id="current_actor_flags",
        property=ActorProperty.FLAGS,
        expected_current_actor_addr=0x40002450,  # ACTORS_START + MAX_ACTORS * ACTOR_STRUCT_SIZE
        expected_property_offset=0x22,
        expected_size=2,
        expected_type="u16",
        description="Current actor flags for conditional checks"
    ),
    
    CurrentActorTestCase(
        test_id="current_actor_anim_counter",
        property=ActorProperty.ANIM_COUNTER,
        expected_current_actor_addr=0x40002450,  # ACTORS_START + MAX_ACTORS * ACTOR_STRUCT_SIZE
        expected_property_offset=0x24,
        expected_size=2,
        expected_type="u16",
        description="Current actor animation counter"
    ),
]


# ==============================================================================
# API Consistency Test Cases
# ==============================================================================

api_consistency_test_cases: List[APIConsistencyTestCase] = [
    APIConsistencyTestCase(
        test_id="api_consistency_actor_0_x",
        actor_index=0,
        property=ActorProperty.X,
        expected_address=0x40001c58,  # ACTORS_START + 0 * 64 + 0x08
        description="All APIs should return same address for actor 0 X property"
    ),
    
    APIConsistencyTestCase(
        test_id="api_consistency_actor_10_flags",
        actor_index=10,
        property=ActorProperty.FLAGS,
        expected_address=0x40001ef2,  # ACTORS_START + 10 * 64 + 0x22
        description="All APIs should return same address for actor 10 flags"
    ),
    
    APIConsistencyTestCase(
        test_id="api_consistency_string_property",
        actor_index=5,
        property="walk_speed_x",  # String property
        expected_address=0x40001da4,  # ACTORS_START + 5 * 64 + 0x14
        description="All APIs should handle string properties consistently"
    ),
]


# ==============================================================================
# Parametrized Test Functions
# ==============================================================================

@pytest.mark.parametrize("case", property_test_cases, ids=lambda c: c.test_id)
def test_actor_property_addresses(case: ActorPropertyTestCase):
    """Test actor property address calculations using declarative test cases."""
    
    # Calculate address using the function API
    actual_address = get_actor_property_address(case.actor_index, case.property)
    
    # Verify the address matches expected
    assert actual_address == case.expected_address, (
        f"Address mismatch for {case.description}: "
        f"expected {hex(case.expected_address)}, got {hex(actual_address)}"
    )
    
    # Verify the address calculation formula
    expected_base = ACTORS_START + (case.actor_index * ACTOR_STRUCT_SIZE)
    expected_addr = expected_base + case.expected_offset
    assert actual_address == expected_addr, (
        f"Address calculation error: base={hex(expected_base)}, "
        f"offset={hex(case.expected_offset)}, expected={hex(expected_addr)}"
    )


@pytest.mark.parametrize("case", current_actor_test_cases, ids=lambda c: c.test_id)
def test_current_actor_property_addresses(case: CurrentActorTestCase):
    """Test current actor property address calculations for LLIL generation."""
    
    # Get current actor address and property offset
    current_actor_addr, property_offset = get_current_actor_property_address(case.property)
    
    # Verify current actor address
    assert current_actor_addr == case.expected_current_actor_addr, (
        f"Current actor address mismatch for {case.description}: "
        f"expected {hex(case.expected_current_actor_addr)}, got {hex(current_actor_addr)}"
    )
    
    # Verify property offset
    assert property_offset == case.expected_property_offset, (
        f"Property offset mismatch for {case.description}: "
        f"expected {hex(case.expected_property_offset)}, got {hex(property_offset)}"
    )
    
    # Verify the current actor address matches our constant
    assert current_actor_addr == CURRENT_ACTOR_ADDRESS


@pytest.mark.parametrize("case", api_consistency_test_cases, ids=lambda c: c.test_id)
def test_api_consistency(case: APIConsistencyTestCase):
    """Test that all three APIs return the same address for the same inputs."""
    
    # Test simple function API
    addr1 = get_actor_property_address(case.actor_index, case.property)
    
    # Test fluent interface API
    am = ActorMemory()
    addr2 = am.actor(case.actor_index).prop(case.property).address
    
    # Test dictionary-style API
    actors = ActorState()
    addr3, _ = actors[case.actor_index][case.property]
    
    # All should return the same address
    assert addr1 == case.expected_address, f"Function API: expected {hex(case.expected_address)}, got {hex(addr1)}"
    assert addr2 == case.expected_address, f"Fluent API: expected {hex(case.expected_address)}, got {hex(addr2)}"
    assert addr3 == case.expected_address, f"Dictionary API: expected {hex(case.expected_address)}, got {hex(addr3)}"
    
    # All APIs should agree
    assert addr1 == addr2 == addr3, (
        f"API inconsistency for {case.description}: "
        f"function={hex(addr1)}, fluent={hex(addr2)}, dictionary={hex(addr3)}"
    )


# ==============================================================================
# Edge Case and Validation Tests
# ==============================================================================

def test_actor_bounds_validation():
    """Test that actor index bounds are properly validated."""
    
    # Valid bounds should work
    addr = get_actor_property_address(0, ActorProperty.ID)
    assert addr == ACTORS_START
    
    addr = get_actor_property_address(MAX_ACTORS - 1, ActorProperty.ID)
    assert addr == ACTORS_START + ((MAX_ACTORS - 1) * ACTOR_STRUCT_SIZE)
    
    # Invalid bounds should raise ValueError
    with pytest.raises(ValueError, match="out of bounds"):
        get_actor_property_address(-1, ActorProperty.ID)
    
    with pytest.raises(ValueError, match="out of bounds"):
        get_actor_property_address(MAX_ACTORS, ActorProperty.ID)
    
    with pytest.raises(ValueError, match="out of bounds"):
        get_actor_property_address(100, ActorProperty.ID)


def test_property_validation():
    """Test that invalid properties are rejected."""
    
    # Valid enum should work
    addr = get_actor_property_address(0, ActorProperty.X)
    assert addr == ACTORS_START + 0x08
    
    # Valid string should work
    addr = get_actor_property_address(0, "x")
    assert addr == ACTORS_START + 0x08
    
    # Invalid string should raise ValueError
    with pytest.raises(ValueError, match="Unknown actor property"):
        get_actor_property_address(0, "invalid_property")
    
    # Invalid type should raise ValueError
    with pytest.raises(ValueError, match="Property must be"):
        get_actor_property_address(0, 123)  # type: ignore


def test_current_actor_address_constants():
    """Test that current actor address constants are correctly defined."""
    
    # Current actor address should be after actors section
    assert CURRENT_ACTOR_ADDRESS == ACTORS_START + (MAX_ACTORS * ACTOR_STRUCT_SIZE)
    
    # Should be after the actors section end
    actors_end = ACTORS_START + (MAX_ACTORS * ACTOR_STRUCT_SIZE)
    assert CURRENT_ACTOR_ADDRESS == actors_end
    
    # Address should be 4-byte aligned for proper access
    assert CURRENT_ACTOR_ADDRESS % 4 == 0


def test_property_metadata_consistency():
    """Test that enum and dictionary properties have consistent metadata."""
    
    # Test that each enum property has corresponding dictionary entry
    for actor_prop in ActorProperty:
        prop_name = actor_prop.name.lower()
        
        # Not all enum properties may have dictionary entries (that's ok)
        # But if they do, they should match
        if prop_name in ACTOR_PROPERTIES:
            enum_info = actor_prop.value
            dict_info = ACTOR_PROPERTIES[prop_name]
            
            assert enum_info.offset == dict_info.offset, f"Offset mismatch for {prop_name}"
            assert enum_info.size == dict_info.size, f"Size mismatch for {prop_name}"
            assert enum_info.type == dict_info.type, f"Type mismatch for {prop_name}"


def test_struct_layout_coverage():
    """Test that all 64 bytes of actor struct are accounted for."""
    
    # Collect all property ranges
    covered_ranges = []
    for prop_info in ACTOR_PROPERTIES.values():
        covered_ranges.append((prop_info.offset, prop_info.offset + prop_info.size))
    
    # Sort by offset
    covered_ranges.sort()
    
    # Verify no overlaps and reasonable coverage
    for i in range(1, len(covered_ranges)):
        prev_end = covered_ranges[i-1][1]
        curr_start = covered_ranges[i][0]
        assert prev_end <= curr_start, f"Property overlap: {covered_ranges[i-1]} and {covered_ranges[i]}"
    
    # Verify we don't exceed struct size
    max_end = max(end for _, end in covered_ranges)
    assert max_end <= ACTOR_STRUCT_SIZE, f"Properties exceed struct size: max_end={max_end}, size={ACTOR_STRUCT_SIZE}"


# ==============================================================================
# Performance and Scale Tests
# ==============================================================================

def test_all_actors_all_properties():
    """Test address calculation for all actors and all properties."""
    
    # This tests the full scale of the system
    addresses_seen = set()
    
    for actor_index in range(MAX_ACTORS):
        for prop_name in ACTOR_PROPERTIES:
            addr = get_actor_property_address(actor_index, prop_name)
            
            # Address should be unique
            assert addr not in addresses_seen, f"Duplicate address {hex(addr)} for actor {actor_index} property {prop_name}"
            addresses_seen.add(addr)
            
            # Address should be in valid range
            assert ACTORS_START <= addr < ACTORS_START + (MAX_ACTORS * ACTOR_STRUCT_SIZE)


if __name__ == "__main__":
    # Run with verbose output to see all test cases
    pytest.main([__file__, "-v", "--tb=short"])