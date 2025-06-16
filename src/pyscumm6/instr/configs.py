"""Metadata-driven instruction configurations."""

from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class IntrinsicConfig:
    """Configuration for intrinsic operations."""
    pop_count: int = 0
    push_count: int = 0
    doc: str = ""
    special_lift: Optional[str] = None  # Name of special lift method

@dataclass  
class VariableConfig:
    """Configuration for variable operations."""
    var_type: str  # "byte" or "word"
    operation: str  # "inc", "dec", "read", "write"
    doc: str = ""

@dataclass
class ArrayConfig:
    """Configuration for array operations."""
    element_type: str  # "byte" or "word"
    operation: str     # "read", "write", "inc", "dec"
    indexed: bool = False
    doc: str = ""

@dataclass
class ComplexConfig:
    """Configuration for complex operations with sub-commands."""
    body_type_name: str  # e.g., "ActorOps", "VerbOps"
    doc: str = ""

@dataclass
class StackConfig:
    """Configuration for stack operations."""
    il_op_name: str
    display_name: Optional[str] = None
    is_comparison: bool = False
    is_unary: bool = False
    doc: str = ""

# ============================================================================
# INSTRUCTION METADATA - Replaces 100+ class definitions
# ============================================================================

# Intrinsic Operations (100+ classes -> single config table)
INTRINSIC_CONFIGS: Dict[str, IntrinsicConfig] = {
    # Drawing Operations
    "draw_object": IntrinsicConfig(pop_count=2, doc="Draw object with ID and state"),
    "draw_object_at": IntrinsicConfig(pop_count=3, doc="Draw object at position"),
    "draw_blast_object": IntrinsicConfig(doc="Draw blast object"),
    "set_blast_object_window": IntrinsicConfig(doc="Set blast object window"),
    
    # Audio Operations  
    "start_sound": IntrinsicConfig(pop_count=1, doc="Start sound"),
    "stop_sound": IntrinsicConfig(pop_count=1, doc="Stop sound"),
    "start_music": IntrinsicConfig(pop_count=1, doc="Start music"),
    "stop_music": IntrinsicConfig(doc="Stop music"),
    "is_sound_running": IntrinsicConfig(pop_count=1, push_count=1, doc="Check if sound running"),
    "sound_kludge": IntrinsicConfig(pop_count=1, doc="Sound system kludge"),
    
    # Actor Query Operations
    "get_actor_moving": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor moving state"),
    "get_actor_room": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor room"),
    "get_actor_costume": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor costume"),
    "get_actor_walk_box": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor walk box"),
    "get_actor_elevation": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor elevation"),
    "get_actor_width": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor width"),
    "get_actor_scale_x": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor scale X"),
    "get_actor_anim_counter": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor anim counter"),
    "get_actor_from_xy": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor from coordinates"),
    "get_actor_layer": IntrinsicConfig(pop_count=1, push_count=1, doc="Get actor layer"),
    
    # Actor Movement Operations
    "face_actor": IntrinsicConfig(pop_count=1, doc="Face actor"),
    "animate_actor": IntrinsicConfig(pop_count=1, doc="Animate actor"),
    "walk_actor_to_obj": IntrinsicConfig(pop_count=3, doc="Walk actor to object"),
    "walk_actor_to": IntrinsicConfig(pop_count=3, doc="Walk actor to position"),
    "put_actor_at_xy": IntrinsicConfig(pop_count=4, doc="Put actor at coordinates"),
    "put_actor_at_object": IntrinsicConfig(pop_count=3, doc="Put actor at object"),
    
    # Object Operations
    "get_object_x": IntrinsicConfig(pop_count=1, push_count=1, doc="Get object X position"),
    "get_object_y": IntrinsicConfig(pop_count=1, push_count=1, doc="Get object Y position"),
    "get_object_old_dir": IntrinsicConfig(pop_count=1, push_count=1, doc="Get object old direction"),
    "get_object_new_dir": IntrinsicConfig(pop_count=1, push_count=1, doc="Get object new direction"),
    "pickup_object": IntrinsicConfig(pop_count=1, doc="Pick up object"),
    "find_object": IntrinsicConfig(pop_count=2, push_count=1, doc="Find object"),
    "find_all_objects": IntrinsicConfig(push_count=1, doc="Find all objects"),
    "stamp_object": IntrinsicConfig(doc="Stamp object"),
    
    # System & State Operations
    "end_cutscene": IntrinsicConfig(doc="End cutscene"),
    "get_state": IntrinsicConfig(pop_count=1, push_count=1, doc="Get state"),
    "set_state": IntrinsicConfig(pop_count=2, doc="Set state"),
    "set_owner": IntrinsicConfig(pop_count=2, doc="Set owner"),
    "get_owner": IntrinsicConfig(pop_count=1, push_count=1, doc="Get owner"),
    "freeze_unfreeze": IntrinsicConfig(pop_count=1, doc="Freeze/unfreeze"),
    "begin_override": IntrinsicConfig(doc="Begin override"),
    "end_override": IntrinsicConfig(doc="End override"),
    "set_object_name": IntrinsicConfig(pop_count=2, doc="Set object name"),
    "set_box_flags": IntrinsicConfig(pop_count=2, doc="Set box flags"),
    "create_box_matrix": IntrinsicConfig(doc="Create box matrix"),
    
    # Camera Operations
    "pan_camera_to": IntrinsicConfig(pop_count=1, doc="Pan camera to position"),
    "actor_follow_camera": IntrinsicConfig(pop_count=1, doc="Actor follow camera"),
    "set_camera_at": IntrinsicConfig(pop_count=1, doc="Set camera at position"),
    
    # Room Operations
    "load_room": IntrinsicConfig(pop_count=1, doc="Load room"),
    "load_room_with_ego": IntrinsicConfig(pop_count=1, doc="Load room with ego"),
    "pseudo_room": IntrinsicConfig(pop_count=1, doc="Pseudo room operation"),
    
    # Script Operations
    "is_script_running": IntrinsicConfig(pop_count=1, push_count=1, doc="Check if script running"),
    "stop_script": IntrinsicConfig(pop_count=1, doc="Stop script"),
    "is_room_script_running": IntrinsicConfig(pop_count=1, push_count=1, doc="Check if room script running"),
    "jump_to_script": IntrinsicConfig(doc="Jump to script"),
    
    # Object Script Operations
    "start_object": IntrinsicConfig(doc="Start object"),
    "start_object_quick": IntrinsicConfig(doc="Start object quick"),
    "stop_object_script": IntrinsicConfig(pop_count=1, doc="Stop object script"),
    
    # Inventory Operations
    "find_inventory": IntrinsicConfig(pop_count=1, push_count=1, doc="Find inventory item"),
    "get_inventory_count": IntrinsicConfig(pop_count=1, push_count=1, doc="Get inventory count"),
    
    # Verb Operations
    "do_sentence": IntrinsicConfig(pop_count=2, doc="Do sentence"),
    "get_verb_from_xy": IntrinsicConfig(pop_count=1, push_count=1, doc="Get verb from coordinates"),
    "get_verb_entrypoint": IntrinsicConfig(pop_count=2, push_count=1, doc="Get verb entrypoint"),
    
    # Timing Operations
    "wait": IntrinsicConfig(pop_count=1, doc="Wait for actor"),
    "delay": IntrinsicConfig(pop_count=1, doc="Delay"),
    "delay_seconds": IntrinsicConfig(pop_count=1, doc="Delay seconds"),
    "delay_minutes": IntrinsicConfig(pop_count=1, doc="Delay minutes"),
    "delay_frames": IntrinsicConfig(pop_count=1, doc="Delay frames"),
    
    # Distance/Geometry Operations
    "dist_object_object": IntrinsicConfig(pop_count=2, push_count=1, doc="Distance between objects"),
    "dist_object_pt": IntrinsicConfig(pop_count=3, push_count=1, doc="Distance object to point"),
    "dist_pt_pt": IntrinsicConfig(pop_count=4, push_count=1, doc="Distance between points"),
    "get_pixel": IntrinsicConfig(pop_count=2, push_count=1, doc="Get pixel color"),
    
    # Utility Operations
    "get_date_time": IntrinsicConfig(push_count=1, doc="Get date/time"),
    "get_animate_variable": IntrinsicConfig(pop_count=1, push_count=1, doc="Get animate variable"),
    "pick_var_random": IntrinsicConfig(pop_count=1, push_count=1, doc="Pick variable random"),
    "cursor_command": IntrinsicConfig(pop_count=1, doc="Cursor command"),
    "if_class_of_is": IntrinsicConfig(pop_count=2, push_count=1, doc="Check object class"),
    "set_class": IntrinsicConfig(pop_count=2, doc="Set class"),
    "draw_box": IntrinsicConfig(doc="Draw box"),
    "is_any_of": IntrinsicConfig(push_count=1, doc="Check if value is any of set"),
    "set_box_set": IntrinsicConfig(pop_count=1, doc="Set box set"),
    "is_actor_in_box": IntrinsicConfig(pop_count=2, push_count=1, doc="Check if actor in box"),
    
    # Array Management
    "dim_array": IntrinsicConfig(doc="Dimension array"),
    "dim2dim_array": IntrinsicConfig(doc="2D dimension array"),
    
    # Kernel Operations
    "kernel_get_functions": IntrinsicConfig(doc="Kernel get functions"),
    "kernel_set_functions": IntrinsicConfig(doc="Kernel set functions"),
    "save_restore_verbs": IntrinsicConfig(doc="Save/restore verbs"),
    
    # Dialog and Text Operations
    "print_line": IntrinsicConfig(doc="Print line"),
    "print_text": IntrinsicConfig(doc="Print text"),
    "print_debug": IntrinsicConfig(doc="Print debug"),
    "print_system": IntrinsicConfig(doc="Print system message"),
    "print_actor": IntrinsicConfig(doc="Print actor dialog"),
    "print_ego": IntrinsicConfig(doc="Print ego dialog"),
    "talk_actor": IntrinsicConfig(doc="Talk actor"),
    "talk_ego": IntrinsicConfig(doc="Talk ego"),
    "stop_sentence": IntrinsicConfig(doc="Stop sentence"),
    "stop_talking": IntrinsicConfig(doc="Stop talking"),
    
    # Special Instructions with Custom Lift Logic
    "stop_object_code1": IntrinsicConfig(doc="Stop object code 1", special_lift="no_ret_lift"),
    "stop_object_code2": IntrinsicConfig(doc="Stop object code 2", special_lift="no_ret_lift"),
    "cutscene": IntrinsicConfig(doc="Start cutscene", special_lift="cutscene_lift"),
}

# Variable Operations (4 classes -> config table)
VARIABLE_CONFIGS: Dict[str, VariableConfig] = {
    "byte_var_inc": VariableConfig("byte", "inc", "Increment byte variable"),
    "word_var_inc": VariableConfig("word", "inc", "Increment word variable"),
    "byte_var_dec": VariableConfig("byte", "dec", "Decrement byte variable"), 
    "word_var_dec": VariableConfig("word", "dec", "Decrement word variable"),
}

# Array Operations (12 classes -> config table)
ARRAY_CONFIGS: Dict[str, ArrayConfig] = {
    "byte_array_read": ArrayConfig("byte", "read", doc="Read from byte array"),
    "word_array_read": ArrayConfig("word", "read", doc="Read from word array"),
    "byte_array_indexed_read": ArrayConfig("byte", "read", indexed=True, doc="Indexed byte array read"),
    "word_array_indexed_read": ArrayConfig("word", "read", indexed=True, doc="Indexed word array read"),
    "byte_array_write": ArrayConfig("byte", "write", doc="Write to byte array"),
    "word_array_write": ArrayConfig("word", "write", doc="Write to word array"),
    "byte_array_indexed_write": ArrayConfig("byte", "write", indexed=True, doc="Indexed byte array write"),
    "word_array_indexed_write": ArrayConfig("word", "write", indexed=True, doc="Indexed word array write"),
    "byte_array_inc": ArrayConfig("byte", "inc", doc="Increment byte array element"),
    "word_array_inc": ArrayConfig("word", "inc", doc="Increment word array element"),
    "byte_array_dec": ArrayConfig("byte", "dec", doc="Decrement byte array element"),
    "word_array_dec": ArrayConfig("word", "dec", doc="Decrement word array element"),
}

# Complex Operations (6 classes -> config table)
COMPLEX_CONFIGS: Dict[str, ComplexConfig] = {
    "actor_ops": ComplexConfig("ActorOps", "Actor operations with sub-commands"),
    "verb_ops": ComplexConfig("VerbOps", "Verb operations with sub-commands"),
    "array_ops": ComplexConfig("ArrayOps", "Array operations with sub-commands"),
    "room_ops": ComplexConfig("RoomOps", "Room operations with sub-commands"),
    "system_ops": ComplexConfig("SystemOps", "System operations with sub-commands"),
    "resource_routines": ComplexConfig("ResourceRoutines", "Resource management operations"),
}

# Stack Operations
STACK_CONFIGS: Dict[str, StackConfig] = {
    "add": StackConfig("add", doc="Addition"),
    "sub": StackConfig("sub", doc="Subtraction"),
    "mul": StackConfig("mult", "mul", doc="Multiplication"),
    "div": StackConfig("div_signed", "div", doc="Division"),
    "land": StackConfig("and_expr", "land", doc="Logical AND"),
    "lor": StackConfig("or_expr", "lor", doc="Logical OR"),
    "nott": StackConfig("nott", is_unary=True, doc="Logical NOT"),
    "eq": StackConfig("compare_equal", "eq", is_comparison=True, doc="Equal"),
    "neq": StackConfig("compare_not_equal", "neq", is_comparison=True, doc="Not equal"),
    "gt": StackConfig("compare_signed_greater_than", "gt", is_comparison=True, doc="Greater than"),
    "lt": StackConfig("compare_signed_less_than", "lt", is_comparison=True, doc="Less than"),
    "le": StackConfig("compare_signed_less_equal", "le", is_comparison=True, doc="Less than or equal"),
    "ge": StackConfig("compare_signed_greater_equal", "ge", is_comparison=True, doc="Greater than or equal"),
}