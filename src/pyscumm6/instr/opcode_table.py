"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes
from .opcodes import Instruction
from . import instructions
from .generic import make_push_constant_instruction, make_intrinsic_instruction

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

    # --- Using Base Classes ---
    Scumm6Opcodes.OpType.add: instructions.Add,
    Scumm6Opcodes.OpType.sub: instructions.Sub,
    Scumm6Opcodes.OpType.mul: instructions.Mul,
    Scumm6Opcodes.OpType.div: instructions.Div,
    Scumm6Opcodes.OpType.land: instructions.Land,
    Scumm6Opcodes.OpType.lor: instructions.Lor,
    Scumm6Opcodes.OpType.nott: instructions.Nott,
    Scumm6Opcodes.OpType.eq: instructions.Eq,
    Scumm6Opcodes.OpType.neq: instructions.Neq,
    Scumm6Opcodes.OpType.gt: instructions.Gt,
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
    # Group 3: Complex Engine Intrinsics
    Scumm6Opcodes.OpType.draw_object: instructions.DrawObject,
    Scumm6Opcodes.OpType.draw_object_at: instructions.DrawObjectAt,
    Scumm6Opcodes.OpType.draw_blast_object: instructions.DrawBlastObject,
    Scumm6Opcodes.OpType.cutscene: instructions.Cutscene,
    Scumm6Opcodes.OpType.end_cutscene: instructions.EndCutscene,
    Scumm6Opcodes.OpType.stop_music: instructions.StopMusic,
    Scumm6Opcodes.OpType.freeze_unfreeze: instructions.FreezeUnfreeze,
    Scumm6Opcodes.OpType.stop_object_code1: instructions.StopObjectCode1,
    Scumm6Opcodes.OpType.stop_object_code2: instructions.StopObjectCode2,
    Scumm6Opcodes.OpType.stop_object_script: instructions.StopObjectScript,
    Scumm6Opcodes.OpType.start_sound: instructions.StartSound,
    Scumm6Opcodes.OpType.stop_sound: instructions.StopSound,
    Scumm6Opcodes.OpType.pan_camera_to: instructions.PanCameraTo,
    Scumm6Opcodes.OpType.actor_follow_camera: instructions.ActorFollowCamera,
    Scumm6Opcodes.OpType.set_camera_at: instructions.SetCameraAt,
    Scumm6Opcodes.OpType.load_room: instructions.LoadRoom,
    Scumm6Opcodes.OpType.get_state: instructions.GetState,
    Scumm6Opcodes.OpType.set_state: instructions.SetState,
    Scumm6Opcodes.OpType.set_owner: instructions.SetOwner,
    Scumm6Opcodes.OpType.get_owner: instructions.GetOwner,
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
}
