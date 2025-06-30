from binja_helpers import binja_api  # noqa: F401

from typing import List, Optional, Tuple, Dict

import threading
import logging
from collections import defaultdict

from binaryninja.architecture import Architecture
from binaryninja import (
    IntrinsicInfo,
    RegisterName,
    FlagWriteTypeName,
)
from binaryninja import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.enums import (
    Endianness,
    InstructionTextTokenType,
    FlagRole,
    ImplicitRegisterExtend,
)
from binaryninja import lowlevelil

from .scumm6_opcodes import Scumm6Opcodes

from .sorted_list import SortedList

from . import vars

# Import new decoder
from .pyscumm6.disasm import decode as new_decode, decode_with_fusion

OpType = Scumm6Opcodes.OpType
VarType = Scumm6Opcodes.VarType
SubopType = Scumm6Opcodes.SubopType


# called by Scumm6View
logger = logging.getLogger(__name__)


class LastBV:
    _last_bv: Optional[BinaryView] = None
    _lock = threading.Lock()

    @staticmethod
    def set(bv: BinaryView) -> None:
        with LastBV._lock:
            logger.debug("set_last_bv %s %s", bv, threading.current_thread().name)
            LastBV._last_bv = bv

    @staticmethod
    def get() -> Optional[BinaryView]:
        with LastBV._lock:
            result = LastBV._last_bv
            if not result:
                logger.debug(
                    "get_last_bv: no last_bv %s",
                    threading.current_thread().name,
                )
            return result


# FIXME: create a fake memory segment for all the function names,
# so that cross-references will work
class Scumm6(Architecture):  # type: ignore[misc]
    name = "SCUMM6"
    address_size = 4
    default_int_size = 4
    max_instr_length = 256
    endianness = Endianness.LittleEndian
    
    # Fusion settings - can be overridden by subclasses or modified at runtime
    enable_fusion_in_disassembly = False
    enable_fusion_in_llil = False
    
    regs = {
        RegisterName("sp"): RegisterInfo(
            RegisterName("sp"), 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth
        ),
    } | {
        # local variables (L0-L24)
        RegisterName(f"L{i}"): RegisterInfo(RegisterName(f"L{i}"), 4)
        for i in range(vars.NUM_SCRIPT_LOCAL)
    } | {
        # global SCUMM variables (var_0 to var_799)
        RegisterName(f"var_{i}"): RegisterInfo(RegisterName(f"var_{i}"), 4)
        for i in range(vars.NUM_SCUMM_VARS)
    }

    stack_pointer = "sp"
    flags = ["n", "z", "v", "c"]
    flag_write_types = [FlagWriteTypeName("*")]
    flags_written_by_flag_write_type = {
        "*": ["n", "z", "v", "c"],
    }
    flag_roles = {
        "n": FlagRole.NegativeSignFlagRole,
        "z": FlagRole.ZeroFlagRole,
        "v": FlagRole.OverflowFlagRole,
        "c": FlagRole.CarryFlagRole,
    }

    intrinsics = (
        {op.name: IntrinsicInfo(inputs=[], outputs=[]) for op in OpType}
        | {"abs": IntrinsicInfo(inputs=[], outputs=[])}
        | {
            f"dim_array.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"system_ops.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"array_ops.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"resource_routines.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"cursor_command.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"room_ops.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"actor_ops.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"verb_ops.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"wait.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_line.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_text.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_debug.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_system.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_actor.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
        | {
            f"print_ego.{subop.name}": IntrinsicInfo(inputs=[], outputs=[])
            for subop in SubopType
        }
    )

    # FIXME: attach this state to the view?
    # need to make sure it's a BinaryView subclass
    op_addrs: Dict[str, SortedList] = defaultdict(SortedList)

    def __init__(self) -> None:
        Architecture.__init__(self)

    def get_view(
        self, data: bytes, addr: int
    ) -> Tuple[Optional[BinaryView], Optional[str]]:
        last_bv = LastBV.get()
        if last_bv:
            # check that the data matches in case last_bv is not the right view
            data2 = last_bv.read(addr, len(data))
            if data == data2:
                return (last_bv, last_bv.file.filename)
            else:
                # FIXME: could be because of the .synthetic_builtins section
                logger.warning(
                    "get_view(%s) data mismatch:\nwant: %r,\n got: %r",
                    hex(addr),
                    data,
                    data2,
                )
        assert last_bv
        return (None, None)



    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        # Use new decoder for proper InstructionInfo population
        new_instr = new_decode(data, addr)
        if new_instr is None:
            return None

        result = InstructionInfo()

        # Always call analyze - base class sets length, subclasses add CFG info
        new_instr.analyze(result, addr)

        return result

    def get_instruction_text(
        self, data: bytes, addr: int
    ) -> Optional[Tuple[List[InstructionTextToken], int]]:
        # Use decoder with or without fusion based on setting
        if self.enable_fusion_in_disassembly:
            new_instr = decode_with_fusion(data, addr)
        else:
            new_instr = new_decode(data, addr)
            
        if new_instr is None:
            return None

        # Get tokens from new instruction rendering
        tokens = new_instr.render()

        # Convert to Binary Ninja tokens
        binja_tokens = []
        for token in tokens:
            # Our tokens have a to_binja() method
            if hasattr(token, 'to_binja'):
                binja_tokens.append(token.to_binja())
            else:
                # Fallback for any other token types
                binja_tokens.append(InstructionTextToken(
                    InstructionTextTokenType.TextToken, str(token)
                ))

        return binja_tokens, new_instr._length

    def get_instruction_low_level_il(
        self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction
    ) -> Optional[int]:
        # Use decoder with or without fusion based on setting
        if self.enable_fusion_in_llil:
            new_instr = decode_with_fusion(data, addr)
        else:
            new_instr = new_decode(data, addr)
            
        if new_instr is None:
            return None

        # Generate LLIL using new instruction's lift method
        new_instr.lift(il, addr)

        # Return the instruction length
        return new_instr._length
