"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes
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
    Scumm6Opcodes.OpType.lt: instructions.Lt,
    Scumm6Opcodes.OpType.le: instructions.Le,
    Scumm6Opcodes.OpType.ge: instructions.Ge,

    # --- Keeping Full Implementations for Complex Cases ---
    Scumm6Opcodes.OpType.push_byte_var: instructions.PushByteVar,
    Scumm6Opcodes.OpType.push_word_var: instructions.PushWordVar,
    Scumm6Opcodes.OpType.dup: instructions.Dup,
    Scumm6Opcodes.OpType.band: instructions.Band,
    Scumm6Opcodes.OpType.bor: instructions.Bor,
    Scumm6Opcodes.OpType.byte_var_inc: instructions.ByteVarInc,
    Scumm6Opcodes.OpType.word_var_inc: instructions.WordVarInc,
    Scumm6Opcodes.OpType.byte_var_dec: instructions.ByteVarDec,
    Scumm6Opcodes.OpType.word_var_dec: instructions.WordVarDec,
    Scumm6Opcodes.OpType.dummy: instructions.Dummy,
    Scumm6Opcodes.OpType.pick_one_of: instructions.PickOneOf,
    Scumm6Opcodes.OpType.pick_one_of_default: instructions.PickOneOfDefault,
    Scumm6Opcodes.OpType.shuffle: instructions.Shuffle,
    Scumm6Opcodes.OpType.byte_array_read: instructions.ByteArrayRead,
    Scumm6Opcodes.OpType.word_array_read: instructions.WordArrayRead,
    Scumm6Opcodes.OpType.byte_array_indexed_read: instructions.ByteArrayIndexedRead,
    Scumm6Opcodes.OpType.word_array_indexed_read: instructions.WordArrayIndexedRead,
    Scumm6Opcodes.OpType.byte_array_write: instructions.ByteArrayWrite,
    Scumm6Opcodes.OpType.word_array_write: instructions.WordArrayWrite,
    Scumm6Opcodes.OpType.byte_array_indexed_write: instructions.ByteArrayIndexedWrite,
    Scumm6Opcodes.OpType.word_array_indexed_write: instructions.WordArrayIndexedWrite,
    Scumm6Opcodes.OpType.byte_array_inc: instructions.ByteArrayInc,
    Scumm6Opcodes.OpType.word_array_inc: instructions.WordArrayInc,
    Scumm6Opcodes.OpType.byte_array_dec: instructions.ByteArrayDec,
    Scumm6Opcodes.OpType.word_array_dec: instructions.WordArrayDec,
    Scumm6Opcodes.OpType.iff: instructions.Iff,
    Scumm6Opcodes.OpType.if_not: instructions.IfNot,
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
    # Additional Actor and Object Query Operations
    Scumm6Opcodes.OpType.is_script_running: instructions.IsScriptRunning,
    Scumm6Opcodes.OpType.is_sound_running: instructions.IsSoundRunning,
    Scumm6Opcodes.OpType.get_actor_moving: instructions.GetActorMoving,
    Scumm6Opcodes.OpType.get_actor_room: instructions.GetActorRoom,
    Scumm6Opcodes.OpType.get_actor_costume: instructions.GetActorCostume,
    Scumm6Opcodes.OpType.get_actor_walk_box: instructions.GetActorWalkBox,
    Scumm6Opcodes.OpType.get_inventory_count: instructions.GetInventoryCount,
    Scumm6Opcodes.OpType.find_inventory: instructions.FindInventory,
    Scumm6Opcodes.OpType.get_object_x: instructions.GetObjectX,
    Scumm6Opcodes.OpType.get_object_y: instructions.GetObjectY,
    Scumm6Opcodes.OpType.get_object_old_dir: instructions.GetObjectOldDir,
    Scumm6Opcodes.OpType.animate_actor: instructions.AnimateActor,
    Scumm6Opcodes.OpType.face_actor: instructions.FaceActor,
    Scumm6Opcodes.OpType.pickup_object: instructions.PickupObject,
    Scumm6Opcodes.OpType.set_box_flags: instructions.SetBoxFlags,
    Scumm6Opcodes.OpType.set_object_name: instructions.SetObjectName,
    Scumm6Opcodes.OpType.do_sentence: instructions.DoSentence,
    Scumm6Opcodes.OpType.get_actor_elevation: instructions.GetActorElevation,
    Scumm6Opcodes.OpType.get_actor_width: instructions.GetActorWidth,
    Scumm6Opcodes.OpType.get_actor_scale_x: instructions.GetActorScaleX,
    Scumm6Opcodes.OpType.get_actor_anim_counter: instructions.GetActorAnimCounter,
    Scumm6Opcodes.OpType.get_verb_from_xy: instructions.GetVerbFromXy,
    Scumm6Opcodes.OpType.get_actor_from_xy: instructions.GetActorFromXy,
    Scumm6Opcodes.OpType.begin_override: instructions.BeginOverride,
    Scumm6Opcodes.OpType.end_override: instructions.EndOverride,
    Scumm6Opcodes.OpType.create_box_matrix: instructions.CreateBoxMatrix,
    Scumm6Opcodes.OpType.stop_talking: instructions.StopTalking,
    Scumm6Opcodes.OpType.stop_sentence: instructions.StopSentence,
    # Timing Operations
    Scumm6Opcodes.OpType.wait: instructions.Wait,
    Scumm6Opcodes.OpType.delay: instructions.Delay,
    Scumm6Opcodes.OpType.delay_seconds: instructions.DelaySeconds,
    Scumm6Opcodes.OpType.delay_minutes: instructions.DelayMinutes,
    Scumm6Opcodes.OpType.delay_frames: instructions.DelayFrames,
    # Simple Script/Control Operations
    Scumm6Opcodes.OpType.start_music: instructions.StartMusic,
    Scumm6Opcodes.OpType.stop_script: instructions.StopScript,
    Scumm6Opcodes.OpType.is_room_script_running: instructions.IsRoomScriptRunning,
    Scumm6Opcodes.OpType.get_object_new_dir: instructions.GetObjectNewDir,
    # Distance/Geometry Operations
    Scumm6Opcodes.OpType.dist_object_object: instructions.DistObjectObject,
    Scumm6Opcodes.OpType.dist_object_pt: instructions.DistObjectPt,
    Scumm6Opcodes.OpType.dist_pt_pt: instructions.DistPtPt,
    Scumm6Opcodes.OpType.get_pixel: instructions.GetPixel,
    # Simple Query Operations
    Scumm6Opcodes.OpType.find_object: instructions.FindObject,
    Scumm6Opcodes.OpType.get_verb_entrypoint: instructions.GetVerbEntrypoint,
    Scumm6Opcodes.OpType.is_actor_in_box: instructions.IsActorInBox,
    # Simple Actor Movement Operations
    Scumm6Opcodes.OpType.walk_actor_to_obj: instructions.WalkActorToObj,
    Scumm6Opcodes.OpType.walk_actor_to: instructions.WalkActorTo,
    Scumm6Opcodes.OpType.put_actor_at_xy: instructions.PutActorAtXy,
    Scumm6Opcodes.OpType.put_actor_at_object: instructions.PutActorAtObject,
    # Additional Simple Operations
    Scumm6Opcodes.OpType.get_date_time: instructions.GetDatetime,
    Scumm6Opcodes.OpType.get_animate_variable: instructions.GetAnimateVariable,
    Scumm6Opcodes.OpType.pick_var_random: instructions.PickVarRandom,
    Scumm6Opcodes.OpType.get_actor_layer: instructions.GetActorLayer,
    # Final Simple Utility Operations
    Scumm6Opcodes.OpType.cursor_command: instructions.CursorCommand,
    Scumm6Opcodes.OpType.sound_kludge: instructions.SoundKludge,
    Scumm6Opcodes.OpType.if_class_of_is: instructions.IfClassOfIs,
    Scumm6Opcodes.OpType.set_class: instructions.SetClass,
    Scumm6Opcodes.OpType.draw_box: instructions.DrawBox,
    Scumm6Opcodes.OpType.is_any_of: instructions.IsAnyOf,
    Scumm6Opcodes.OpType.load_room_with_ego: instructions.LoadRoomWithEgo,
    Scumm6Opcodes.OpType.set_box_set: instructions.SetBoxSet,
    Scumm6Opcodes.OpType.stamp_object: instructions.StampObject,
    Scumm6Opcodes.OpType.set_blast_object_window: instructions.SetBlastObjectWindow,
    Scumm6Opcodes.OpType.pseudo_room: instructions.PseudoRoom,
    Scumm6Opcodes.OpType.find_all_objects: instructions.FindAllObjects,
    # Simple Script and Object Operations
    Scumm6Opcodes.OpType.jump_to_script: instructions.JumpToScript,
    Scumm6Opcodes.OpType.start_object: instructions.StartObject,
    Scumm6Opcodes.OpType.start_object_quick: instructions.StartObjectQuick,
    # Array Management Operations
    Scumm6Opcodes.OpType.dim_array: instructions.DimArray,
    Scumm6Opcodes.OpType.dim2dim_array: instructions.Dim2dimArray,
    # Kernel Operations
    Scumm6Opcodes.OpType.kernel_get_functions: instructions.KernelGetFunctions,
    Scumm6Opcodes.OpType.kernel_set_functions: instructions.KernelSetFunctions,
    # Additional Utility Operations
    Scumm6Opcodes.OpType.save_restore_verbs: instructions.SaveRestoreVerbs,
    # Dialog and Text Operations
    Scumm6Opcodes.OpType.print_line: instructions.PrintLine,
    Scumm6Opcodes.OpType.print_text: instructions.PrintText,
    Scumm6Opcodes.OpType.print_debug: instructions.PrintDebug,
    Scumm6Opcodes.OpType.print_system: instructions.PrintSystem,
    Scumm6Opcodes.OpType.print_actor: instructions.PrintActor,
    Scumm6Opcodes.OpType.print_ego: instructions.PrintEgo,
    Scumm6Opcodes.OpType.talk_actor: instructions.TalkActor,
    Scumm6Opcodes.OpType.talk_ego: instructions.TalkEgo,
    # --- Auto-Generated Complex Operations ---
    Scumm6Opcodes.OpType.actor_ops: INSTRUCTION_REGISTRY["actor_ops"],
    Scumm6Opcodes.OpType.verb_ops: INSTRUCTION_REGISTRY["verb_ops"],
    Scumm6Opcodes.OpType.array_ops: INSTRUCTION_REGISTRY["array_ops"],
    Scumm6Opcodes.OpType.room_ops: INSTRUCTION_REGISTRY["room_ops"],
    Scumm6Opcodes.OpType.system_ops: INSTRUCTION_REGISTRY["system_ops"],
    Scumm6Opcodes.OpType.resource_routines: INSTRUCTION_REGISTRY["resource_routines"],
}
