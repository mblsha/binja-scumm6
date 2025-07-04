"""Actor state virtual memory mapping helper.

This module provides utilities to calculate addresses for actor properties
in a virtual memory segment used for tracking actor state modifications.
"""

from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from .vars import MAX_ACTORS, ACTOR_STRUCT_SIZE, ACTORS_START

# Property offsets within Actor struct (based on Option 3)
@dataclass(frozen=True)
class PropertyInfo:
    """Information about an actor property."""
    offset: int
    size: int
    type: str  # 'u8', 'u16', 'u32', 's16', etc.


ACTOR_PROPERTIES: Dict[str, PropertyInfo] = {
    # Core Identity (8 bytes)
    "id": PropertyInfo(0x00, 2, "u16"),
    "costume": PropertyInfo(0x02, 2, "u16"),
    "name_ptr": PropertyInfo(0x04, 4, "u32"),
    
    # Position (8 bytes)
    "x": PropertyInfo(0x08, 2, "u16"),
    "y": PropertyInfo(0x0A, 2, "u16"),
    "elevation": PropertyInfo(0x0C, 2, "s16"),
    "room": PropertyInfo(0x0E, 1, "u8"),
    "layer": PropertyInfo(0x0F, 1, "u8"),
    
    # Movement (12 bytes)
    "target_x": PropertyInfo(0x10, 2, "u16"),
    "target_y": PropertyInfo(0x12, 2, "u16"),
    "walk_speed_x": PropertyInfo(0x14, 2, "u16"),
    "walk_speed_y": PropertyInfo(0x16, 2, "u16"),
    "facing_direction": PropertyInfo(0x18, 1, "u8"),
    "moving": PropertyInfo(0x19, 1, "u8"),
    "walk_box": PropertyInfo(0x1A, 1, "u8"),
    # _pad1 at 0x1B
    
    # Visual (8 bytes)
    "scale_x": PropertyInfo(0x1C, 1, "u8"),
    "scale_y": PropertyInfo(0x1D, 1, "u8"),
    "width": PropertyInfo(0x1E, 1, "u8"),
    "palette": PropertyInfo(0x1F, 1, "u8"),
    "talk_color": PropertyInfo(0x20, 1, "u8"),
    # _pad2 at 0x21
    "flags": PropertyInfo(0x22, 2, "u16"),
    
    # Animation (8 bytes)
    "anim_counter": PropertyInfo(0x24, 2, "u16"),
    "current_anim": PropertyInfo(0x26, 1, "u8"),
    "walk_frame": PropertyInfo(0x27, 1, "u8"),
    "stand_frame": PropertyInfo(0x28, 1, "u8"),
    "talk_frame": PropertyInfo(0x29, 1, "u8"),
    "anim_speed": PropertyInfo(0x2A, 1, "u8"),
    "loop_flag": PropertyInfo(0x2B, 1, "u8"),
    
    # Talk State (8 bytes)
    "talk_pos_x": PropertyInfo(0x2C, 2, "s16"),
    "talk_pos_y": PropertyInfo(0x2E, 2, "s16"),
    # _reserved at 0x30
}


# ==============================================================================
# API Option 1: Simple function-based approach
# ==============================================================================

def get_actor_property_address(actor_index: int, property_name: str) -> int:
    """Calculate the address for an actor property.
    
    Args:
        actor_index: The actor index (0-31)
        property_name: Name of the property (e.g., 'x', 'costume', 'flags')
        
    Returns:
        The calculated memory address
        
    Raises:
        ValueError: If actor_index is out of bounds or property_name is invalid
    """
    if not (0 <= actor_index < MAX_ACTORS):
        raise ValueError(f"Actor index {actor_index} out of bounds (0-{MAX_ACTORS-1})")
    
    if property_name not in ACTOR_PROPERTIES:
        raise ValueError(f"Unknown actor property: {property_name}")
    
    prop = ACTOR_PROPERTIES[property_name]
    return ACTORS_START + (actor_index * ACTOR_STRUCT_SIZE) + prop.offset


# ==============================================================================
# API Option 2: Class-based approach with fluent interface
# ==============================================================================

class ActorMemory:
    """Fluent interface for actor memory calculations."""
    
    def __init__(self, actor_index: Optional[int] = None):
        self._actor_index = actor_index
        self._property_name: Optional[str] = None
    
    def actor(self, index: int) -> 'ActorMemory':
        """Select an actor by index."""
        if not (0 <= index < MAX_ACTORS):
            raise ValueError(f"Actor index {index} out of bounds (0-{MAX_ACTORS-1})")
        return ActorMemory(index)
    
    def prop(self, name: str) -> 'ActorMemory':
        """Select a property by name."""
        if name not in ACTOR_PROPERTIES:
            raise ValueError(f"Unknown actor property: {name}")
        new = ActorMemory(self._actor_index)
        new._property_name = name
        return new
    
    @property
    def address(self) -> int:
        """Get the calculated address."""
        if self._actor_index is None:
            raise ValueError("Actor index not set")
        if self._property_name is None:
            # Return base address of actor struct
            return ACTORS_START + (self._actor_index * ACTOR_STRUCT_SIZE)
        
        prop = ACTOR_PROPERTIES[self._property_name]
        return ACTORS_START + (self._actor_index * ACTOR_STRUCT_SIZE) + prop.offset
    
    def info(self) -> PropertyInfo:
        """Get property information."""
        if self._property_name is None:
            raise ValueError("Property not set")
        return ACTOR_PROPERTIES[self._property_name]


# ==============================================================================
# API Option 3: Dictionary-style access
# ==============================================================================

class ActorState:
    """Dictionary-style access to actor properties."""
    
    def __init__(self):
        self._actors: Dict[int, 'ActorProxy'] = {}
    
    def __getitem__(self, actor_index: int) -> 'ActorProxy':
        """Get an actor proxy by index."""
        if not (0 <= actor_index < MAX_ACTORS):
            raise ValueError(f"Actor index {actor_index} out of bounds (0-{MAX_ACTORS-1})")
        
        if actor_index not in self._actors:
            self._actors[actor_index] = ActorProxy(actor_index)
        
        return self._actors[actor_index]


class ActorProxy:
    """Proxy for accessing actor properties."""
    
    def __init__(self, actor_index: int):
        self._actor_index = actor_index
    
    def __getitem__(self, property_name: str) -> Tuple[int, PropertyInfo]:
        """Get address and info for a property."""
        if property_name not in ACTOR_PROPERTIES:
            raise ValueError(f"Unknown actor property: {property_name}")
        
        prop = ACTOR_PROPERTIES[property_name]
        address = ACTORS_START + (self._actor_index * ACTOR_STRUCT_SIZE) + prop.offset
        return address, prop
    
    @property
    def base_address(self) -> int:
        """Get the base address of this actor's struct."""
        return ACTORS_START + (self._actor_index * ACTOR_STRUCT_SIZE)


# ==============================================================================
# Helper functions
# ==============================================================================

def get_actor_base_address(actor_index: int) -> int:
    """Get the base address for an actor struct.
    
    Args:
        actor_index: The actor index (0-31)
        
    Returns:
        The base address of the actor struct
    """
    if not (0 <= actor_index < MAX_ACTORS):
        raise ValueError(f"Actor index {actor_index} out of bounds (0-{MAX_ACTORS-1})")
    
    return ACTORS_START + (actor_index * ACTOR_STRUCT_SIZE)


def get_property_info(property_name: str) -> PropertyInfo:
    """Get information about a property.
    
    Args:
        property_name: Name of the property
        
    Returns:
        PropertyInfo with offset, size, and type
    """
    if property_name not in ACTOR_PROPERTIES:
        raise ValueError(f"Unknown actor property: {property_name}")
    
    return ACTOR_PROPERTIES[property_name]


def is_valid_actor_address(address: int) -> bool:
    """Check if an address falls within the actor state section.
    
    Args:
        address: Memory address to check
        
    Returns:
        True if the address is within the actor state section
    """
    return ACTORS_START <= address < (ACTORS_START + MAX_ACTORS * ACTOR_STRUCT_SIZE)


def get_actor_and_property_from_address(address: int) -> Optional[Tuple[int, str]]:
    """Reverse lookup: get actor index and property name from address.
    
    Args:
        address: Memory address
        
    Returns:
        Tuple of (actor_index, property_name) or None if not found
    """
    if not is_valid_actor_address(address):
        return None
    
    offset_from_start = address - ACTORS_START
    actor_index = offset_from_start // ACTOR_STRUCT_SIZE
    property_offset = offset_from_start % ACTOR_STRUCT_SIZE
    
    # Find matching property
    for prop_name, prop_info in ACTOR_PROPERTIES.items():
        if prop_info.offset <= property_offset < (prop_info.offset + prop_info.size):
            return actor_index, prop_name
    
    return actor_index, "unknown"