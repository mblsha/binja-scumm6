"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes  # type: ignore[attr-defined]
from .opcodes import Instruction
from . import instructions
from .generic import make_push_constant_instruction, make_intrinsic_instruction
from .registry import INSTRUCTION_REGISTRY

# This map is the core of the new dispatcher.
# The key is the enum value from the Kaitai-generated parser.
# The value is the Python class that handles that instruction.
OPCODE_MAP: Dict[Scumm6Opcodes.OpType, Type[Instruction]] = {
    # --- Using Factories ---
    Scumm6Opcodes.OpType.push_byte: make_push_constant_instruction(
        "push_byte", Scumm6Opcodes.ByteData, 4
    ),
    Scumm6Opcodes.OpType.push_word: make_push_constant_instruction(
        "push_word", Scumm6Opcodes.WordData, 4
    ),
    Scumm6Opcodes.OpType.abs: make_intrinsic_instruction(
        "abs", Scumm6Opcodes.CallFuncPop1Push, pop_count=1, push_count=1
    ),
    Scumm6Opcodes.OpType.break_here: make_intrinsic_instruction(
        "break_here", Scumm6Opcodes.NoData, pop_count=0, push_count=0
    ),
    Scumm6Opcodes.OpType.pop1: make_intrinsic_instruction(
        "pop1", Scumm6Opcodes.CallFuncPop1, pop_count=1, push_count=0
    ),
    # pop2 also has a CallFuncPop1 body
    Scumm6Opcodes.OpType.pop2: make_intrinsic_instruction(
        "pop2", Scumm6Opcodes.CallFuncPop1, pop_count=1, push_count=0
    ),
    Scumm6Opcodes.OpType.get_random_number: make_intrinsic_instruction(
        "get_random_number", Scumm6Opcodes.CallFuncPop1Push, pop_count=1, push_count=1
    ),
    Scumm6Opcodes.OpType.get_random_number_range: make_intrinsic_instruction(
        "get_random_number_range", Scumm6Opcodes.CallFuncPop2Push, pop_count=2, push_count=1
    ),

    # --- Auto-Generated Stack Operations ---
    Scumm6Opcodes.OpType.add: INSTRUCTION_REGISTRY["add"],
    Scumm6Opcodes.OpType.sub: INSTRUCTION_REGISTRY["sub"],
    Scumm6Opcodes.OpType.mul: INSTRUCTION_REGISTRY["mul"],
    Scumm6Opcodes.OpType.div: INSTRUCTION_REGISTRY["div"],
    Scumm6Opcodes.OpType.land: INSTRUCTION_REGISTRY["land"],
    Scumm6Opcodes.OpType.lor: INSTRUCTION_REGISTRY["lor"],
    Scumm6Opcodes.OpType.nott: INSTRUCTION_REGISTRY["nott"],
    Scumm6Opcodes.OpType.eq: INSTRUCTION_REGISTRY["eq"],
    Scumm6Opcodes.OpType.neq: INSTRUCTION_REGISTRY["neq"],
    Scumm6Opcodes.OpType.gt: INSTRUCTION_REGISTRY["gt"],
    Scumm6Opcodes.OpType.lt: INSTRUCTION_REGISTRY["lt"],
    Scumm6Opcodes.OpType.le: INSTRUCTION_REGISTRY["le"],
    Scumm6Opcodes.OpType.ge: INSTRUCTION_REGISTRY["ge"],

    # --- Keeping Full Implementations for Complex Cases ---
    Scumm6Opcodes.OpType.push_byte_var: instructions.PushByteVar,
    Scumm6Opcodes.OpType.push_word_var: instructions.PushWordVar,
    Scumm6Opcodes.OpType.dup: instructions.Dup,
    Scumm6Opcodes.OpType.band: instructions.Band,
    Scumm6Opcodes.OpType.bor: instructions.Bor,
    # --- Auto-Generated Variable Operations ---
    Scumm6Opcodes.OpType.byte_var_inc: INSTRUCTION_REGISTRY["byte_var_inc"],
    Scumm6Opcodes.OpType.word_var_inc: INSTRUCTION_REGISTRY["word_var_inc"],
    Scumm6Opcodes.OpType.byte_var_dec: INSTRUCTION_REGISTRY["byte_var_dec"],
    Scumm6Opcodes.OpType.word_var_dec: INSTRUCTION_REGISTRY["word_var_dec"],
    Scumm6Opcodes.OpType.dummy: instructions.Dummy,
    Scumm6Opcodes.OpType.pick_one_of: instructions.PickOneOf,
    Scumm6Opcodes.OpType.pick_one_of_default: instructions.PickOneOfDefault,
    Scumm6Opcodes.OpType.shuffle: instructions.Shuffle,
    # --- Auto-Generated Array Operations ---
    Scumm6Opcodes.OpType.byte_array_read: INSTRUCTION_REGISTRY["byte_array_read"],
    Scumm6Opcodes.OpType.word_array_read: INSTRUCTION_REGISTRY["word_array_read"],
    Scumm6Opcodes.OpType.byte_array_indexed_read: INSTRUCTION_REGISTRY["byte_array_indexed_read"],
    Scumm6Opcodes.OpType.word_array_indexed_read: INSTRUCTION_REGISTRY["word_array_indexed_read"],
    Scumm6Opcodes.OpType.byte_array_write: INSTRUCTION_REGISTRY["byte_array_write"],
    Scumm6Opcodes.OpType.word_array_write: INSTRUCTION_REGISTRY["word_array_write"],
    Scumm6Opcodes.OpType.byte_array_indexed_write: INSTRUCTION_REGISTRY["byte_array_indexed_write"],
    Scumm6Opcodes.OpType.word_array_indexed_write: INSTRUCTION_REGISTRY["word_array_indexed_write"],
    Scumm6Opcodes.OpType.byte_array_inc: INSTRUCTION_REGISTRY["byte_array_inc"],
    Scumm6Opcodes.OpType.word_array_inc: INSTRUCTION_REGISTRY["word_array_inc"],
    Scumm6Opcodes.OpType.byte_array_dec: INSTRUCTION_REGISTRY["byte_array_dec"],
    Scumm6Opcodes.OpType.word_array_dec: INSTRUCTION_REGISTRY["word_array_dec"],
    Scumm6Opcodes.OpType.iff: instructions.SmartIff,
    Scumm6Opcodes.OpType.if_not: instructions.SmartIfNot,
    Scumm6Opcodes.OpType.jump: instructions.Jump,
    Scumm6Opcodes.OpType.write_byte_var: instructions.WriteByteVar,
    Scumm6Opcodes.OpType.write_word_var: instructions.WriteWordVar,
    # --- Auto-Generated Intrinsic Operations ---
    Scumm6Opcodes.OpType.draw_object: INSTRUCTION_REGISTRY["draw_object"],
    Scumm6Opcodes.OpType.draw_object_at: INSTRUCTION_REGISTRY["draw_object_at"],
    Scumm6Opcodes.OpType.draw_blast_object: INSTRUCTION_REGISTRY["draw_blast_object"],
    Scumm6Opcodes.OpType.cutscene: INSTRUCTION_REGISTRY["cutscene"],
    Scumm6Opcodes.OpType.end_cutscene: INSTRUCTION_REGISTRY["end_cutscene"],
    Scumm6Opcodes.OpType.stop_music: INSTRUCTION_REGISTRY["stop_music"],
    Scumm6Opcodes.OpType.freeze_unfreeze: INSTRUCTION_REGISTRY["freeze_unfreeze"],
    Scumm6Opcodes.OpType.stop_object_code1: INSTRUCTION_REGISTRY["stop_object_code1"],
    Scumm6Opcodes.OpType.stop_object_code2: INSTRUCTION_REGISTRY["stop_object_code2"],
    Scumm6Opcodes.OpType.stop_object_script: INSTRUCTION_REGISTRY["stop_object_script"],
    Scumm6Opcodes.OpType.start_sound: INSTRUCTION_REGISTRY["start_sound"],
    Scumm6Opcodes.OpType.stop_sound: INSTRUCTION_REGISTRY["stop_sound"],
    Scumm6Opcodes.OpType.pan_camera_to: INSTRUCTION_REGISTRY["pan_camera_to"],
    Scumm6Opcodes.OpType.actor_follow_camera: INSTRUCTION_REGISTRY["actor_follow_camera"],
    Scumm6Opcodes.OpType.set_camera_at: INSTRUCTION_REGISTRY["set_camera_at"],
    Scumm6Opcodes.OpType.load_room: INSTRUCTION_REGISTRY["load_room"],
    Scumm6Opcodes.OpType.get_state: INSTRUCTION_REGISTRY["get_state"],
    Scumm6Opcodes.OpType.set_state: INSTRUCTION_REGISTRY["set_state"],
    Scumm6Opcodes.OpType.set_owner: INSTRUCTION_REGISTRY["set_owner"],
    Scumm6Opcodes.OpType.get_owner: INSTRUCTION_REGISTRY["get_owner"],
    # --- Auto-Generated Actor and Object Query Operations ---
    Scumm6Opcodes.OpType.is_script_running: INSTRUCTION_REGISTRY["is_script_running"],
    Scumm6Opcodes.OpType.is_sound_running: INSTRUCTION_REGISTRY["is_sound_running"],
    Scumm6Opcodes.OpType.get_actor_moving: INSTRUCTION_REGISTRY["get_actor_moving"],
    Scumm6Opcodes.OpType.get_actor_room: INSTRUCTION_REGISTRY["get_actor_room"],
    Scumm6Opcodes.OpType.get_actor_costume: INSTRUCTION_REGISTRY["get_actor_costume"],
    Scumm6Opcodes.OpType.get_actor_walk_box: INSTRUCTION_REGISTRY["get_actor_walk_box"],
    Scumm6Opcodes.OpType.get_inventory_count: INSTRUCTION_REGISTRY["get_inventory_count"],
    Scumm6Opcodes.OpType.find_inventory: INSTRUCTION_REGISTRY["find_inventory"],
    Scumm6Opcodes.OpType.get_object_x: INSTRUCTION_REGISTRY["get_object_x"],
    Scumm6Opcodes.OpType.get_object_y: INSTRUCTION_REGISTRY["get_object_y"],
    Scumm6Opcodes.OpType.get_object_old_dir: INSTRUCTION_REGISTRY["get_object_old_dir"],
    Scumm6Opcodes.OpType.animate_actor: INSTRUCTION_REGISTRY["animate_actor"],
    Scumm6Opcodes.OpType.face_actor: INSTRUCTION_REGISTRY["face_actor"],
    Scumm6Opcodes.OpType.pickup_object: INSTRUCTION_REGISTRY["pickup_object"],
    Scumm6Opcodes.OpType.set_box_flags: INSTRUCTION_REGISTRY["set_box_flags"],
    Scumm6Opcodes.OpType.set_object_name: INSTRUCTION_REGISTRY["set_object_name"],
    Scumm6Opcodes.OpType.do_sentence: INSTRUCTION_REGISTRY["do_sentence"],
    Scumm6Opcodes.OpType.get_actor_elevation: INSTRUCTION_REGISTRY["get_actor_elevation"],
    Scumm6Opcodes.OpType.get_actor_width: INSTRUCTION_REGISTRY["get_actor_width"],
    Scumm6Opcodes.OpType.get_actor_scale_x: INSTRUCTION_REGISTRY["get_actor_scale_x"],
    Scumm6Opcodes.OpType.get_actor_anim_counter: INSTRUCTION_REGISTRY["get_actor_anim_counter"],
    Scumm6Opcodes.OpType.get_verb_from_xy: INSTRUCTION_REGISTRY["get_verb_from_xy"],
    Scumm6Opcodes.OpType.get_actor_from_xy: INSTRUCTION_REGISTRY["get_actor_from_xy"],
    Scumm6Opcodes.OpType.begin_override: INSTRUCTION_REGISTRY["begin_override"],
    Scumm6Opcodes.OpType.end_override: INSTRUCTION_REGISTRY["end_override"],
    Scumm6Opcodes.OpType.create_box_matrix: INSTRUCTION_REGISTRY["create_box_matrix"],
    Scumm6Opcodes.OpType.stop_talking: INSTRUCTION_REGISTRY["stop_talking"],
    Scumm6Opcodes.OpType.stop_sentence: INSTRUCTION_REGISTRY["stop_sentence"],
    # --- Auto-Generated Timing Operations ---
    Scumm6Opcodes.OpType.wait: INSTRUCTION_REGISTRY["wait"],
    Scumm6Opcodes.OpType.delay: INSTRUCTION_REGISTRY["delay"],
    Scumm6Opcodes.OpType.delay_seconds: INSTRUCTION_REGISTRY["delay_seconds"],
    Scumm6Opcodes.OpType.delay_minutes: INSTRUCTION_REGISTRY["delay_minutes"],
    Scumm6Opcodes.OpType.delay_frames: INSTRUCTION_REGISTRY["delay_frames"],
    # --- Auto-Generated Script/Control Operations ---
    Scumm6Opcodes.OpType.start_music: INSTRUCTION_REGISTRY["start_music"],
    Scumm6Opcodes.OpType.stop_script: INSTRUCTION_REGISTRY["stop_script"],
    Scumm6Opcodes.OpType.is_room_script_running: INSTRUCTION_REGISTRY["is_room_script_running"],
    Scumm6Opcodes.OpType.get_object_new_dir: INSTRUCTION_REGISTRY["get_object_new_dir"],
    # --- Auto-Generated Distance/Geometry Operations ---
    Scumm6Opcodes.OpType.dist_object_object: INSTRUCTION_REGISTRY["dist_object_object"],
    Scumm6Opcodes.OpType.dist_object_pt: INSTRUCTION_REGISTRY["dist_object_pt"],
    Scumm6Opcodes.OpType.dist_pt_pt: INSTRUCTION_REGISTRY["dist_pt_pt"],
    Scumm6Opcodes.OpType.get_pixel: INSTRUCTION_REGISTRY["get_pixel"],
    # --- Auto-Generated Query Operations ---
    Scumm6Opcodes.OpType.find_object: INSTRUCTION_REGISTRY["find_object"],
    Scumm6Opcodes.OpType.get_verb_entrypoint: INSTRUCTION_REGISTRY["get_verb_entrypoint"],
    Scumm6Opcodes.OpType.is_actor_in_box: INSTRUCTION_REGISTRY["is_actor_in_box"],
    # --- Auto-Generated Actor Movement Operations ---
    Scumm6Opcodes.OpType.walk_actor_to_obj: INSTRUCTION_REGISTRY["walk_actor_to_obj"],
    Scumm6Opcodes.OpType.walk_actor_to: INSTRUCTION_REGISTRY["walk_actor_to"],
    Scumm6Opcodes.OpType.put_actor_at_xy: INSTRUCTION_REGISTRY["put_actor_at_xy"],
    Scumm6Opcodes.OpType.put_actor_at_object: INSTRUCTION_REGISTRY["put_actor_at_object"],
    # --- Auto-Generated Utility Operations ---
    Scumm6Opcodes.OpType.get_date_time: INSTRUCTION_REGISTRY["get_date_time"],
    Scumm6Opcodes.OpType.get_animate_variable: INSTRUCTION_REGISTRY["get_animate_variable"],
    Scumm6Opcodes.OpType.pick_var_random: INSTRUCTION_REGISTRY["pick_var_random"],
    Scumm6Opcodes.OpType.get_actor_layer: INSTRUCTION_REGISTRY["get_actor_layer"],
    Scumm6Opcodes.OpType.cursor_command: instructions.CursorCommand,
    Scumm6Opcodes.OpType.sound_kludge: INSTRUCTION_REGISTRY["sound_kludge"],
    Scumm6Opcodes.OpType.if_class_of_is: instructions.IfClassOfIs,
    Scumm6Opcodes.OpType.set_class: INSTRUCTION_REGISTRY["set_class"],
    Scumm6Opcodes.OpType.draw_box: INSTRUCTION_REGISTRY["draw_box"],
    Scumm6Opcodes.OpType.is_any_of: INSTRUCTION_REGISTRY["is_any_of"],
    Scumm6Opcodes.OpType.load_room_with_ego: INSTRUCTION_REGISTRY["load_room_with_ego"],
    Scumm6Opcodes.OpType.set_box_set: INSTRUCTION_REGISTRY["set_box_set"],
    Scumm6Opcodes.OpType.stamp_object: INSTRUCTION_REGISTRY["stamp_object"],
    Scumm6Opcodes.OpType.set_blast_object_window: INSTRUCTION_REGISTRY["set_blast_object_window"],
    Scumm6Opcodes.OpType.pseudo_room: INSTRUCTION_REGISTRY["pseudo_room"],
    Scumm6Opcodes.OpType.find_all_objects: INSTRUCTION_REGISTRY["find_all_objects"],
    # --- Auto-Generated Script and Object Operations ---
    Scumm6Opcodes.OpType.jump_to_script: INSTRUCTION_REGISTRY["jump_to_script"],
    Scumm6Opcodes.OpType.start_script: INSTRUCTION_REGISTRY["start_script"],
    Scumm6Opcodes.OpType.start_script_quick: INSTRUCTION_REGISTRY["start_script_quick"],
    Scumm6Opcodes.OpType.start_object: INSTRUCTION_REGISTRY["start_object"],
    Scumm6Opcodes.OpType.start_object_quick: INSTRUCTION_REGISTRY["start_object_quick"],
    # --- Auto-Generated Array Management Operations ---
    Scumm6Opcodes.OpType.dim_array: INSTRUCTION_REGISTRY["dim_array"],
    Scumm6Opcodes.OpType.dim2dim_array: INSTRUCTION_REGISTRY["dim2dim_array"],
    # --- Auto-Generated Kernel Operations ---
    Scumm6Opcodes.OpType.kernel_get_functions: INSTRUCTION_REGISTRY["kernel_get_functions"],
    Scumm6Opcodes.OpType.kernel_set_functions: INSTRUCTION_REGISTRY["kernel_set_functions"],
    # --- Auto-Generated Utility Operations ---
    Scumm6Opcodes.OpType.save_restore_verbs: instructions.SaveRestoreVerbs,
    # --- Auto-Generated Dialog and Text Operations ---
    Scumm6Opcodes.OpType.print_line: INSTRUCTION_REGISTRY["print_line"],
    Scumm6Opcodes.OpType.print_text: INSTRUCTION_REGISTRY["print_text"],
    Scumm6Opcodes.OpType.print_debug: INSTRUCTION_REGISTRY["print_debug"],
    Scumm6Opcodes.OpType.print_system: INSTRUCTION_REGISTRY["print_system"],
    Scumm6Opcodes.OpType.print_actor: instructions.PrintActor,
    Scumm6Opcodes.OpType.print_ego: instructions.PrintEgo,
    Scumm6Opcodes.OpType.talk_actor: INSTRUCTION_REGISTRY["talk_actor"],
    Scumm6Opcodes.OpType.talk_ego: INSTRUCTION_REGISTRY["talk_ego"],
    # --- Auto-Generated Complex Operations ---
    Scumm6Opcodes.OpType.actor_ops: instructions.ActorOps,
    Scumm6Opcodes.OpType.verb_ops: INSTRUCTION_REGISTRY["verb_ops"],
    Scumm6Opcodes.OpType.array_ops: INSTRUCTION_REGISTRY["array_ops"],
    Scumm6Opcodes.OpType.room_ops: INSTRUCTION_REGISTRY["room_ops"],
    Scumm6Opcodes.OpType.system_ops: INSTRUCTION_REGISTRY["system_ops"],
    Scumm6Opcodes.OpType.resource_routines: INSTRUCTION_REGISTRY["resource_routines"],
}
