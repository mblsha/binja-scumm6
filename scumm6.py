import binaryninja

from typing import List, Optional, Tuple

import struct
import traceback
import os
from enum import Enum
import threading
from functools import partial
import bisect
from collections import defaultdict

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
SubopType = Scumm6Opcodes.SubopType

last_bv = None
def set_last_bv(bv):
    global last_bv
    last_bv = bv
    print('set_last_bv', bv)

class SortedList:
    def __init__(self):
        self._list = []

    def insert_sorted(self, value):
        if self.find_element(value):
            return
        bisect.insort(self._list, value)

    def find_element(self, value):
        pos = bisect.bisect_left(self._list, value)
        return pos != len(self._list) and self._list[pos] == value

    def closest_left_match(self, value):
        pos = bisect.bisect_left(self._list, value)
        if pos == 0:
            return None
        else:
            return self._list[pos - 1]

class Scumm6(Architecture):
    name = "SCUMM6"
    address_size = 4
    default_int_size = 4
    max_instr_length = 256
    endianness = Endianness.LittleEndian
    regs = {
       'p0':  RegisterInfo('r', 4),
       'p1':  RegisterInfo('r', 4),
       'p2':  RegisterInfo('r', 4),
       'p3':  RegisterInfo('r', 4),
       'p4':  RegisterInfo('r', 4),
       'p5':  RegisterInfo('r', 4),
       'p6':  RegisterInfo('r', 4),
       'p7':  RegisterInfo('r', 4),
       'p8':  RegisterInfo('r', 4),
       'p9':  RegisterInfo('r', 4),

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

    intrinsics = {
        op.name:IntrinsicInfo(inputs=[], outputs=[]) for op in OpType
    } | {
        f'cursor_command.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'room_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'actor_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'wait.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_debug.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    }


    op_addrs = defaultdict(SortedList)

    def __init__(self):
        Architecture.__init__(self)
        self.disasm = Scumm6Disasm()

    def get_view(self, data: bytes, addr: int):
        ctx = UIContext.activeContext()
        if not ctx:
            return (None, None)
        for view, filename in ctx.getAvailableBinaryViews():
            if str(view.arch) != self.name:
                continue
            data2 = view.read(addr, len(data))
            if data != data2:
                continue
            return (view, view.file.filename)

        global last_bv
        if last_bv:
            data2 = last_bv.read(addr, len(data))
            if data == data2:
                return (last_bv, last_bv.file.filename)
        print('last_bv not set, view not initialized?')
        return (None, None)

    def prev_instruction(self, data: bytes, addr: int):
        view, filename = self.get_view(data, addr)
        if not view:
            raise Exception(f'prev_instruction: no view at {addr:x}')
        prev_addr = self.op_addrs[filename].closest_left_match(addr)
        print(f'prev_instruction: addr:{addr:x} -> prev:{prev_addr:x}')
        data2 = view.read(prev_addr, 256)
        dis = self.decode_instruction(data2, len(data2))
        if not dis:
            raise Exception(f'prev_instruction: no disasm at {prev_addr:x} len{len(data)}')
        return dis

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
                result.add_branch(BranchType.TrueBranch, addr+result.length+body.jump_offset)
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

        op = dis[0]
        body = getattr(op, 'body', None)

        intrinsic_name = dis[1]
        subop = getattr(body, 'subop', None)
        if body and subop:
            intrinsic_name += f'.{body.subop.name}'
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, intrinsic_name)]

        if op.id == OpType.talk_actor:
            args = []
            for tcmd in body.cmds:
                if getattr(tcmd, 'data', None):
                    args.append(chr(tcmd.magic) + tcmd.data)
                else:
                    args.append(tcmd.cmd.name)
            tokens += tokenize_params(*args)

        elif body:
            args  = [getattr(body, x)  for x in dir(body)  if isinstance(getattr(body, x), int)]
            args += [getattr(subop, x) for x in dir(subop) if isinstance(getattr(subop, x), int)]
            tokens += tokenize_params(*args)

        return tokens, dis[2]

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        # FIXME: support switching based on var type
        # use registers for local vars, and split to read/write funcs?
        def var_addr(var_index):
            start = il.const_pointer(4, 0x100000)
            offs = il.mult(4, il.const(4, 4), il.const(4, var_index))
            return il.add(4, start, offs)

        def add_intrinsic(name, block):
            pop_count = getattr(block, 'pop_count', 0)
            push_count = getattr(block, 'push_count', 0)
            pop_list = getattr(block, 'pop_list', False)

            args = []
            args += [il.pop(4) for _ in range(pop_count)]
            if pop_list:
                # binja doesn't support popping dynamic num of args from stack,
                # so try to figure out how many do we need to pop.
                dis2 = self.prev_instruction(data, addr)
                if not dis2:
                    raise Exception(f'no op_prev for {dis[1]} at {hex(addr)}')
                op_prev = dis2[0]
                if op_prev.id not in [OpType.push_byte, OpType.push_word]:
                    raise Exception(f'unsupported op_prev {dis2[1]} at {hex(addr)}')

                # num_regs need to be popped separately
                il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # a
                args += [il.pop(4) for _ in range(op_prev.body.data + 0)]

            results = []
            if push_count:
                assert(push_count == 1)
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], name, args))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], name, args))


        implemented = True
        op = dis[0]
        body = getattr(op, 'body', None)
        if op.id in [OpType.push_byte, OpType.push_word]:
            il.append(il.push(4, il.const(4, body.data)))
        elif op.id in [OpType.write_byte_var, OpType.write_word_var]:
            il.append(il.store(4, var_addr(body.data), il.pop(4)))
        elif op.id in [OpType.push_byte_var, OpType.push_word_var]:
            il.append(il.push(4, il.load(4, var_addr(body.data))))
        elif op.id in [OpType.byte_var_dec, OpType.word_var_dec]:
            il.append(il.set_reg(4, LLIL_TEMP(0), var_addr(body.data)))
            il.append(il.store(4, il.reg(4, LLIL_TEMP(0)),
                                  il.sub(4,
                                         il.load(4, il.reg(4, LLIL_TEMP(0))),
                                         il.const(4, 1))))
        # elif op.id in [OpType.byte_array_read, OpType.word_array_read]:
        #     il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # base
        #     il.append(il.set_reg(4, LLIL_TEMP(1), body.data)) # ?
        #     int base = pop();
        #     # int ScummEngine_v6::readArray(int array, int idx, int base)
        #     push(readArray(fetchScriptByte(), 0, base));
        #     pass
        elif op.id in [OpType.eq, OpType.neq,
                       OpType.gt, OpType.lt, OpType.le, OpType.ge]:
            comp = {
                OpType.eq: il.compare_equal,
                OpType.neq: il.compare_not_equal,
                OpType.gt: il.compare_signed_greater_than,
                OpType.lt: il.compare_signed_less_than,
                OpType.le: il.compare_signed_less_equal,
                OpType.ge: il.compare_signed_greater_equal,
            }
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4))) # b
            comp_res = comp[op.id](4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
            il.append(il.push(4, comp_res))
        elif op.id in [OpType.add, OpType.sub, OpType.mul, OpType.div]:
            subopt = {
                OpType.add: il.add,
                OpType.sub: il.sub,
                OpType.mul: il.mult,
                OpType.div: il.div_signed,
            }
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4))) # b
            il.append(il.push(4,
                              subopt[op.id](4,
                                            il.reg(4, LLIL_TEMP(1)),
                                            il.reg(4, LLIL_TEMP(0)))))
        elif op.id in [OpType.dup]:
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        elif op.id in [OpType.nott]:
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
            comp = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
            il.append(il.push(4, comp))
        elif op.id in [OpType.iff, OpType.if_not]:
            comp = {
                OpType.iff: il.compare_not_equal,
                OpType.if_not: il.compare_equal,
            }
            t = LowLevelILLabel()
            f = LowLevelILLabel()
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # a
            il.append(il.if_expr(
                comp[op.id](4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0)),
                t, f))
            il.mark_label(t)
            il.append(il.jump(il.const(4, addr+dis[2]+body.jump_offset)))
            il.mark_label(f)
        elif op.id in [OpType.jump]:
            il.append(il.jump(il.const(4, addr+dis[2]+body.jump_offset)))
        elif op.id in [OpType.stop_object_code1, OpType.stop_object_code2]:
            add_intrinsic(op.id.name, body)
            il.append(il.no_ret())
        elif op.id == OpType.stop_script:
            add_intrinsic(op.id.name, body)
            dis2 = self.prev_instruction(data, addr)
            op_prev = dis2[0]
            if op_prev.id not in [OpType.push_byte, OpType.push_word]:
                raise Exception(f'unsupported op_prev {dis2[1]} at {hex(addr)}')
                args += [il.pop(4) for _ in range(op_prev.body.data + 0)]
            if op_prev.body.data == 0:
                # stopObjectCode
                il.append(il.no_ret())
        elif not getattr(body, 'call_func', True):
            add_intrinsic(op.id.name, body)
        elif getattr(body, 'subop', None):
            if type(body.body) == Scumm6Opcodes.UnknownOp:
                print(f'unknown_op {dis[1]} at {hex(addr)}: {getattr(body, "subop", None)}')
                implemented = False
                il.append(il.unimplemented())
            else:
                add_intrinsic(f'{op.id.name}.{body.subop.name}', body.body)
        elif op.id in [OpType.break_here]:
            il.append(il.intrinsic([], op.id.name, []))
        else:
            print(f'not implemented {dis[1]} at {hex(addr)}: {getattr(body, "subop", None)}')
            implemented = False
            il.append(il.unimplemented())

        if body and type(body) == Scumm6Opcodes.UnknownOp:
            print(f'unknown_op {dis[1]} at {hex(addr)}: {getattr(body, "subop", None)}')
            implemented = False
            il.append(il.unimplemented())

        if implemented:
            view, filename = self.get_view(data, addr)
            if not view:
                raise Exception(f"No view for data at {hex(addr)}")
            self.op_addrs[filename].insert_sorted(addr)
            # print(self.op_addrs[filename]._list)

        return dis[2]

