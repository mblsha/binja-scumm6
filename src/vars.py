from binja_helpers import binja_api  # noqa: F401
from binaryninja import RegisterName, lowlevelil

from .scumm6_opcodes import Scumm6Opcodes  # type: ignore[attr-defined]
from functools import lru_cache

from typing import Dict, NamedTuple, Optional, Any

VarType = Scumm6Opcodes.VarType


# ScummEngine::setupScummVars()
# https://github.com/scummvm/scummvm/blob/master/engines/scumm/vars.cpp
@lru_cache(maxsize=None)
def raw_scumm_vars(game_version: int = 6) -> Dict[str, int]:
    r: Dict[str, int] = {}

    r["VAR_KEYPRESS"] = 0
    r["VAR_EGO"] = 1
    r["VAR_CAMERA_POS_X"] = 2
    r["VAR_HAVE_MSG"] = 3
    r["VAR_ROOM"] = 4
    r["VAR_OVERRIDE"] = 5
    r["VAR_MACHINE_SPEED"] = 6
    r["VAR_ME"] = 7
    r["VAR_NUM_ACTOR"] = 8
    r["VAR_CURRENTDRIVE"] = 10
    r["VAR_TMR_1"] = 11
    r["VAR_TMR_2"] = 12
    r["VAR_TMR_3"] = 13
    r["VAR_MUSIC_TIMER"] = 14
    r["VAR_ACTOR_RANGE_MIN"] = 15
    r["VAR_ACTOR_RANGE_MAX"] = 16
    r["VAR_CAMERA_MIN_X"] = 17
    r["VAR_CAMERA_MAX_X"] = 18
    r["VAR_TIMER_NEXT"] = 19
    r["VAR_VIRT_MOUSE_X"] = 20
    r["VAR_VIRT_MOUSE_Y"] = 21
    r["VAR_ROOM_RESOURCE"] = 22
    r["VAR_LAST_SOUND"] = 23
    r["VAR_CUTSCENEEXIT_KEY"] = 24
    r["VAR_TALK_ACTOR"] = 25
    r["VAR_CAMERA_FAST_X"] = 26
    r["VAR_ENTRY_SCRIPT"] = 28
    r["VAR_ENTRY_SCRIPT2"] = 29
    r["VAR_EXIT_SCRIPT"] = 30
    r["VAR_EXIT_SCRIPT2"] = 31
    r["VAR_VERB_SCRIPT"] = 32
    r["VAR_SENTENCE_SCRIPT"] = 33
    r["VAR_INVENTORY_SCRIPT"] = 34
    r["VAR_CUTSCENE_START_SCRIPT"] = 35
    r["VAR_CUTSCENE_END_SCRIPT"] = 36
    r["VAR_CHARINC"] = 37
    r["VAR_WALKTO_OBJ"] = 38
    r["VAR_HEAPSPACE"] = 40
    r["VAR_RESTART_KEY"] = 42
    r["VAR_PAUSE_KEY"] = 43
    r["VAR_MOUSE_X"] = 44
    r["VAR_MOUSE_Y"] = 45
    r["VAR_TIMER"] = 46
    r["VAR_TIMER_TOTAL"] = 47
    r["VAR_SOUNDCARD"] = 48
    r["VAR_VIDEOMODE"] = 49

    # if (_game.id == GID_LOOM && _game.platform == Common::kPlatformPCEngine):
    #     r["VAR_MAINMENU_KEY"] = 50

    if game_version >= 4:
        r["VAR_SCROLL_SCRIPT"] = 27
        r["VAR_DEBUGMODE"] = 39
        r["VAR_MAINMENU_KEY"] = 50
        r["VAR_FIXEDDISK"] = 51
        r["VAR_CURSORSTATE"] = 52
        r["VAR_USERPUT"] = 53

    if game_version >= 5:
        r["VAR_SOUNDRESULT"] = 56
        r["VAR_TALKSTOP_KEY"] = 57
        r["VAR_FADE_DELAY"] = 59
        r["VAR_SOUNDPARAM"] = 64
        r["VAR_SOUNDPARAM2"] = 65
        r["VAR_SOUNDPARAM3"] = 66
        r["VAR_INPUTMODE"] = 67  # 1 is keyboard, 2 is joystick, 3 is mouse
        r["VAR_MEMORY_PERFORMANCE"] = 68
        r["VAR_VIDEO_PERFORMANCE"] = 69
        r["VAR_ROOM_FLAG"] = 70
        r["VAR_GAME_LOADED"] = 71
        r["VAR_NEW_ROOM"] = 72

    # ScummEngine_v6::setupScummVars()
    r["VAR_ROOM_WIDTH"] = 41
    r["VAR_ROOM_HEIGHT"] = 54

    # if (_game.heversion >= 60) {
    #     VAR_NOSUBTITLES = 60
    # } else {
    if True:
        r["VAR_VOICE_MODE"] = 60  # 0 is voice, 1 is voice+text, 2 is text only
        r["VAR_PRE_SAVELOAD_SCRIPT"] = 61
        r["VAR_POST_SAVELOAD_SCRIPT"] = 62

    r["VAR_LEFTBTN_HOLD"] = 74
    r["VAR_RIGHTBTN_HOLD"] = 75

    r["VAR_V6_EMSSPACE"] = 76
    r["VAR_RANDOM_NR"] = 118

    r["VAR_TIMEDATE_YEAR"] = 119
    r["VAR_TIMEDATE_MONTH"] = 129
    r["VAR_TIMEDATE_DAY"] = 128
    r["VAR_TIMEDATE_HOUR"] = 125
    r["VAR_TIMEDATE_MINUTE"] = 126

    # Sam & Max specific
    # if (_game.id == GID_SAMNMAX) {
    #     VAR_V6_SOUNDMODE = 9
    #     VAR_CHARSET_MASK = 123
    # }

    return r


@lru_cache(maxsize=None)
def scumm_vars_inverse() -> Dict[int, str]:
    return {v: k for k, v in raw_scumm_vars().items()}


# ScummEngine::readVar() handles reading vars
# need to read MAXS first

# _scummVar: _numVariables at ScummEngine::allocateArrays()
# vm.localvar: local: NUM_SCRIPT_LOCAL = 25 at scumm/script.h
# _bitVars: _numBitVariables at ScummEngine::allocateArrays()

# local for each script, are set when calling scripts
NUM_SCRIPT_LOCAL = 25

# scumm_vars, hold system state
NUM_SCUMM_VARS = 800  # DOTTDEMO.000 / defined in MAXS section
VAR_ITEM_SIZE = 4

SCUMM_VARS_START = 0x40000000
SCUMM_VARS_SIZE = NUM_SCUMM_VARS * VAR_ITEM_SIZE

# we only need to allocate a single bit, but it's easier to mark
# the whole byte as used in binja
NUM_BITVARS = 2048  # DOTTDEMO.000 / defined in MAXS section
BITVAR_ITEM_SIZE = 1

BITVARS_START = SCUMM_VARS_START + SCUMM_VARS_SIZE
BITVARS_SIZE = NUM_BITVARS * BITVAR_ITEM_SIZE

NUM_ARRAY_VARS = 50  # DOTTDEMO.000 / defined in MAXS section
VAR_ARRAY_ITEM_SIZE = 4
VAR_ARRAY_NUM_ITEMS = 10
ARRAYS_START = BITVARS_START + BITVARS_SIZE
ARRAYS_SIZE = NUM_ARRAY_VARS * VAR_ARRAY_ITEM_SIZE * VAR_ARRAY_NUM_ITEMS


# returns name for a given var number
class ScummVar(NamedTuple):
    name: Optional[str]
    address: int


def get_scumm_var(num: int) -> ScummVar:
    address = SCUMM_VARS_START + num * VAR_ITEM_SIZE

    if num in scumm_vars_inverse():
        return ScummVar(name=scumm_vars_inverse()[num], address=address)

    return ScummVar(name=None, address=address)


def get_bit_var(num: int) -> int:
    return BITVARS_START + num * BITVAR_ITEM_SIZE


def reg_name(block: Any) -> str:
    if block.type == VarType.local:
        return f"L{block.data}"
    else:
        raise Exception(f"reg_name: unsupported var type '{block.type}'")


def il_get_var(il: lowlevelil.LowLevelILFunction, block: Any) -> Any:
    # Handle ByteData that doesn't have type attribute (for push_byte_var compatibility)
    if not hasattr(block, 'type'):
        # Default to scumm_var for ByteData without type
        return il.load(
            VAR_ITEM_SIZE,
            il.const_pointer(4, get_scumm_var(block.data).address),
        )
    
    if block.type == VarType.scumm_var:
        return il.load(
            VAR_ITEM_SIZE,
            il.const_pointer(4, get_scumm_var(block.data).address),
        )
    elif block.type == VarType.bitvar:
        return il.load(BITVAR_ITEM_SIZE, il.const_pointer(4, get_bit_var(block.data)))

    return il.reg(4, RegisterName(reg_name(block)))


def il_set_var(il: lowlevelil.LowLevelILFunction, block: Any, value: Any) -> Any:
    if block.type == VarType.scumm_var:
        return il.store(
            VAR_ITEM_SIZE,
            il.const_pointer(4, get_scumm_var(block.data).address),
            value,
        )
    elif block.type == VarType.bitvar:
        return il.store(
            BITVAR_ITEM_SIZE,
            il.const_pointer(4, get_bit_var(block.data)),
            value,
        )

    return il.set_reg(4, RegisterName(reg_name(block)), value)


# Memory layout:
# field types
#   kStringArray: 1-byte
#   kIntArray: 2-byte
# dim1: uint16_t
# dim2: uint16_t
# data: void*
#
# Example: defineArray(array, kStringArray, 0, len + 1);

# https://github.com/scummvm/scummvm/blob/master/engines/scumm/script_v6.cpp
# ScummEngine_v6::defineArray(int array, int type, int dim2, int dim1)

def il_array_item_addr(
    il: lowlevelil.LowLevelILFunction, array: int, index: Any
) -> Any:
    array_size = VAR_ARRAY_ITEM_SIZE * VAR_ARRAY_NUM_ITEMS
    array_start = il.const_pointer(4, ARRAYS_START + array * array_size)
    return il.add(
        4, array_start, il.mult(4, il.const(4, index), il.const(4, VAR_ARRAY_ITEM_SIZE))
    )


def il_get_array(
    il: lowlevelil.LowLevelILFunction, array: int, index: int, base: int
) -> Any:
    return il.load(
        VAR_ARRAY_ITEM_SIZE,
        il_array_item_addr(il, array, index),
    )


def il_set_array(
    il: lowlevelil.LowLevelILFunction, array: int, index: Any, base: Any, value: Any
) -> Any:
    return il.store(
        VAR_ARRAY_ITEM_SIZE,
        il_array_item_addr(il, array, index),
        value,
    )
