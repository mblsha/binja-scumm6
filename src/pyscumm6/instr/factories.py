"""Smart factory functions for generating instruction classes."""

from typing import Type, Dict, List, Union
from binja_helpers.tokens import Token

from .opcodes import Instruction
from .smart_bases import (SmartIntrinsicOp, SmartVariableOp, SmartArrayOp, SmartComplexOp, 
                         SmartBinaryOp, SmartUnaryOp, SmartComparisonOp, SmartSemanticIntrinsicOp,
                         SmartFusibleIntrinsic)
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig, INTRINSIC_CONFIGS, VARIABLE_CONFIGS, ARRAY_CONFIGS, 
                     COMPLEX_CONFIGS, STACK_CONFIGS, SEMANTIC_CONFIGS)

def create_intrinsic_instruction(name: str, config: IntrinsicConfig) -> Type[Instruction]:
    """Create an intrinsic instruction class from configuration."""
    
    # List of instructions that should support fusion
    FUSIBLE_INSTRUCTIONS = {
        # Drawing operations
        "draw_object",      # 2 params: object_id, state
        "draw_object_at",   # 3 params: object_id, x, y
        # Actor operations
        "walk_actor_to",    # 3 params: actor_id, x, y
        "walk_actor_to_obj",# 3 params: actor_id, object_id, ?
        "put_actor_at_xy",  # 4 params: actor_id, x, y, ?
        "put_actor_at_object", # 3 params: actor_id, object_id, ?
        "face_actor",       # 1 param: direction
        "animate_actor",    # 1 param: animation
        "is_actor_in_box",  # 2 params: actor_id, box_id
        # Script operations
        "start_script",     # Variable params
        "start_script_quick",# Variable params
        "start_object",     # 2+ params
        "is_script_running", # 1 param: script_id
        # Sound operations
        "start_sound",      # 1 param: sound_id
        "start_music",      # 1 param: music_id
        "stop_sound",       # 1 param: sound_id
        # Object query operations
        "get_object_x",     # 1 param: object_id -> x position
        "get_object_y",     # 1 param: object_id -> y position
        "get_object_old_dir", # 1 param: object_id -> old direction
        "get_object_new_dir", # 1 param: object_id -> new direction
        "get_state",        # 1 param: object_id -> state
        # Actor query operations
        "get_actor_scale_x", # 1 param: actor_id -> scale X
        "get_actor_room",   # 1 param: actor_id -> room number
        # Random number operations
        "get_random_number", # 1 param: max_value -> random result
        "get_random_number_range", # 2 params: min, max -> random result
        # Object operations
        "set_state",        # 2 params: object, state
        "set_owner",        # 2 params: object, owner
        "set_class",        # 2 params: object, class
        "pickup_object",    # 2 params: object, room
        # Room operations
        "load_room",        # 1 param: room_id
        "pan_camera_to",    # 1 param: x_position
        "set_camera_at",    # 1 param: x_position
        "actor_follow_camera", # 1 param: actor_id
        # Other operations with parameters
        "pickup_object",    # 2 params: object, room
        "do_sentence",      # 4 params: verb, obj1, obj2, ?
        "stop_script",      # 1 param: script_id
        "stop_object_script", # 1 param: object_id
        "freeze_unfreeze",  # 1 param: freeze flag
        # Timing operations
        "delay",            # 1 param: delay amount
        "delay_seconds",    # 1 param: seconds
        "delay_minutes",    # 1 param: minutes
        "delay_frames",     # 1 param: frames
        # UI operations
        "cursor_command",   # Variable params for cursor operations
        # Print operations
        "print_actor",      # Complex print operations
        "print_ego",        # Complex print operations
        # Verb operations
        "save_restore_verbs", # 3 params: slot1, slot2, slot3
        # Utility operations with variable arguments
        "is_any_of",        # Variable params: value, [array], count
    }
    
    # Choose base class based on whether instruction should support fusion
    if name in FUSIBLE_INSTRUCTIONS:
        base_class: Type[Union[SmartFusibleIntrinsic, SmartIntrinsicOp]] = SmartFusibleIntrinsic
    else:
        base_class = SmartIntrinsicOp
    
    class GeneratedIntrinsicOp(base_class):  # type: ignore[misc,valid-type]
        _name = name
        _config = config
        __doc__ = config.doc
        
        def render(self, as_operand: bool = False) -> List[Token]:
            return super().render()  # type: ignore[no-any-return]
    
    GeneratedIntrinsicOp.__name__ = name.title().replace("_", "")
    GeneratedIntrinsicOp.__qualname__ = name.title().replace("_", "")
    return GeneratedIntrinsicOp

def create_variable_instruction(name: str, config: VariableConfig) -> Type[Instruction]:
    """Create a variable operation instruction class from configuration."""
    
    class GeneratedVariableOp(SmartVariableOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedVariableOp.__name__ = name.title().replace("_", "")
    GeneratedVariableOp.__qualname__ = name.title().replace("_", "")
    return GeneratedVariableOp

def create_array_instruction(name: str, config: ArrayConfig) -> Type[Instruction]:
    """Create an array operation instruction class from configuration."""
    
    class GeneratedArrayOp(SmartArrayOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedArrayOp.__name__ = name.title().replace("_", "")
    GeneratedArrayOp.__qualname__ = name.title().replace("_", "")
    return GeneratedArrayOp

def create_complex_instruction(name: str, config: ComplexConfig) -> Type[Instruction]:
    """Create a complex operation instruction class from configuration."""
    
    class GeneratedComplexOp(SmartComplexOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedComplexOp.__name__ = name.title().replace("_", "")
    GeneratedComplexOp.__qualname__ = name.title().replace("_", "")
    return GeneratedComplexOp

def create_stack_instruction(name: str, config: StackConfig) -> Type[Instruction]:
    """Create a stack operation instruction class from configuration."""
    
    if config.is_comparison:
        class GeneratedComparisonOp(SmartComparisonOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedComparisonOp.__name__ = name.title().replace("_", "")
        GeneratedComparisonOp.__qualname__ = name.title().replace("_", "")
        return GeneratedComparisonOp
    elif config.is_unary:
        class GeneratedUnaryOp(SmartUnaryOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedUnaryOp.__name__ = name.title().replace("_", "")
        GeneratedUnaryOp.__qualname__ = name.title().replace("_", "")
        return GeneratedUnaryOp
    else:
        class GeneratedBinaryOp(SmartBinaryOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedBinaryOp.__name__ = name.title().replace("_", "")
        GeneratedBinaryOp.__qualname__ = name.title().replace("_", "")
        return GeneratedBinaryOp

def create_semantic_intrinsic_instruction(name: str, config: SemanticIntrinsicConfig) -> Type[Instruction]:
    """Create a semantic intrinsic instruction class following descumm philosophy."""
    
    class GeneratedSemanticIntrinsicOp(SmartSemanticIntrinsicOp):
        _name = name
        _config = config
        __doc__ = config.doc
        
        def render(self, as_operand: bool = False) -> List[Token]:
            return super().render()
    
    GeneratedSemanticIntrinsicOp.__name__ = name.title().replace("_", "")
    GeneratedSemanticIntrinsicOp.__qualname__ = name.title().replace("_", "")
    return GeneratedSemanticIntrinsicOp

def generate_all_instructions() -> Dict[str, Type[Instruction]]:
    """Generate all instruction classes from configurations."""
    registry: Dict[str, Type[Instruction]] = {}
    
    # Generate intrinsic instructions
    for name, config in INTRINSIC_CONFIGS.items():
        registry[name] = create_intrinsic_instruction(name, config)
    
    # Generate variable instructions  
    for name, var_config in VARIABLE_CONFIGS.items():
        registry[name] = create_variable_instruction(name, var_config)
    
    # Generate array instructions
    for name, array_config in ARRAY_CONFIGS.items():
        registry[name] = create_array_instruction(name, array_config)
    
    # Generate complex instructions
    for name, complex_config in COMPLEX_CONFIGS.items():
        registry[name] = create_complex_instruction(name, complex_config)
    
    # Generate stack instructions
    for name, stack_config in STACK_CONFIGS.items():
        registry[name] = create_stack_instruction(name, stack_config)
    
    # Generate semantic intrinsic instructions (following descumm philosophy)
    for name, semantic_config in SEMANTIC_CONFIGS.items():
        registry[name] = create_semantic_intrinsic_instruction(name, semantic_config)
    
    # Add custom instruction implementations
    from . import instructions
    registry["print_debug"] = instructions.PrintDebug
    registry["talk_actor"] = instructions.TalkActor
    
    # Override start_script_quick with custom implementation
    from . import script_ops
    # Set the config from the generated class
    script_ops.StartScriptQuick._config = SEMANTIC_CONFIGS["start_script_quick"]
    registry["start_script_quick"] = script_ops.StartScriptQuick
    
    # Override start_script with custom implementation
    script_ops.StartScript._config = SEMANTIC_CONFIGS["start_script"]
    registry["start_script"] = script_ops.StartScript
    
    # Override sound_kludge with custom implementation
    script_ops.SoundKludge._config = INTRINSIC_CONFIGS["sound_kludge"]
    registry["sound_kludge"] = script_ops.SoundKludge
    
    # Override start_object with custom implementation
    # start_object is defined as a semantic_op which returns SemanticIntrinsicConfig
    # It's stored in INTRINSIC_CONFIGS but is actually a SemanticIntrinsicConfig
    if "start_object" in INTRINSIC_CONFIGS:
        # Cast is safe because start_object is defined with semantic_op()
        script_ops.StartObject._config = INTRINSIC_CONFIGS["start_object"]  # type: ignore[assignment]
    elif "start_object" in SEMANTIC_CONFIGS:
        script_ops.StartObject._config = SEMANTIC_CONFIGS["start_object"]
    registry["start_object"] = script_ops.StartObject
    
    # Override cutscene with custom implementation
    script_ops.Cutscene._config = INTRINSIC_CONFIGS["cutscene"]
    registry["cutscene"] = script_ops.Cutscene
    
    # Override is_any_of with custom implementation
    script_ops.IsAnyOf._config = INTRINSIC_CONFIGS["is_any_of"]
    registry["is_any_of"] = script_ops.IsAnyOf
    
    return registry
