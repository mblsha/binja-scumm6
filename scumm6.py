import binaryninja

from typing import List, Optional, Tuple

import struct
import traceback
import os
from enum import Enum
import threading
from functools import partial

from binaryninja.architecture import Architecture, IntrinsicIndex, IntrinsicName, IntrinsicType, IntrinsicInfo
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP, LowLevelILFunction, ExpressionIndex
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import AddressField, ChoiceField, get_form_input
from binaryninja.types import Symbol, Type
from binaryninja.enums import (Endianness, BranchType, InstructionTextTokenType,
        LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag,
        ImplicitRegisterExtend, SymbolType)
from binaryninja import BinaryViewType, lowlevelil
from binaryninjaui import UIContext

from .disasm import Scumm6Disasm
from .scumm6_opcodes import Scumm6Opcodes
OpType = Scumm6Opcodes.OpType

class Scumm6(Architecture):
    name = "SCUMM6"
    address_size = 4
    default_int_size = 4
    max_instr_length = 256
    endianness = Endianness.LittleEndian
    regs = {
       'r':  RegisterInfo('r', 4),
       'sp': RegisterInfo('sp', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
    }

    stack_pointer = 'sp'
    flags = ['n', 'z', 'v', 'c']
    flag_write_types = ['*']
    flags_written_by_flag_write_type = {
        '*': ['n', 'z', 'v', 'c'],
    }
    flag_roles = {
        'n': FlagRole.NegativeSignFlagRole,
        'z': FlagRole.ZeroFlagRole,
        'v': FlagRole.OverflowFlagRole,
        'c': FlagRole.CarryFlagRole,
    }

    def __init__(self):
        Architecture.__init__(self)
        self.disasm = Scumm6Disasm()

    def decode_instruction(self, data: bytes, addr: int):
        dis = self.disasm.decode_instruction(data, addr)
        return dis

    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        result = InstructionInfo()
        result.length = dis[2]

        op = dis[0]
        body = getattr(op, 'body', None)
        # print(op, body, op.id)
        if body:
            if getattr(body, 'jump_offset', None) != None:
                result.add_branch(BranchType.TrueBranch, addr+body.jump_offset)
                result.add_branch(BranchType.FalseBranch, addr+result.length)
                # raise Exception('Unhandled jump_offset for op %s' % op.id)

        return result

    def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List['function.InstructionTextToken'], int]]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        def tokenize_params(*params):
            r = [InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "(")]
            need_comma = False
            for x in params:
                if need_comma:
                    r += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", ")]
                r += [InstructionTextToken(InstructionTextTokenType.IntegerToken, str(x))]
                need_comma = True
            r += [InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ")")]
            return r

        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, dis[1])]
        op = dis[0]
        body = getattr(op, 'body', None)
        if body:
            tokens += tokenize_params(*[getattr(body, x) for x in dir(body) if isinstance(getattr(body, x), int)])

        return tokens, dis[2]

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        il.append(il.unimplemented())
        return dis[2]

