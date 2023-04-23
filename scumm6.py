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

from .disasm import Scumm6Disasm, Instruction
from .scumm6_opcodes import Scumm6Opcodes
OpType = Scumm6Opcodes.OpType
VarType = Scumm6Opcodes.VarType
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
        'sp': RegisterInfo('sp', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
    } | { # normal
        f'N{i}': RegisterInfo(f'N{i}', 4) for i in range(1024)
    } | { # local
        f'L{i}': RegisterInfo(f'L{i}', 4) for i in range(1024)
    } | { # room
        f'R{i}': RegisterInfo(f'R{i}', 4) for i in range(1024)
    } | { # global
        f'G{i}': RegisterInfo(f'G{i}', 4) for i in range(1024)
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
        f'dim_array.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'system_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'array_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'resource_routines.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'cursor_command.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'room_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'actor_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'verb_ops.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'wait.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_line.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_text.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_debug.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_system.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_actor.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
    } | {
        f'print_ego.{subop.name}':IntrinsicInfo(inputs=[], outputs=[]) for subop in SubopType
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

    def prev_instruction(self, instr):
        view, filename = self.get_view(instr.data, instr.addr)
        if not view:
            raise Exception(f'prev_instruction: no view at {hex(instr.addr)}')
        prev_addr = self.op_addrs[filename].closest_left_match(instr.addr)
        # print(f'prev_instruction: addr:{instr.addr:x} -> prev:{prev_addr:x}')
        data2 = view.read(prev_addr, 256)
        dis = self.decode_instruction(data2, prev_addr)
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
        result.length = dis.length

        op = dis.op
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

        op = dis.op
        body = getattr(op, 'body', None)

        intrinsic_name = dis.id
        subop = getattr(body, 'subop', None)
        if body and subop:
            intrinsic_name += f'.{body.subop.name}'
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, intrinsic_name)]

        def can_tokenize(param):
            if isinstance(param, int):
                return True
            if isinstance(param, str):
                return not param.startswith('scumm6')
            return False

        if op.id == OpType.talk_actor:
            args = []
            for tcmd in body.cmds:
                if getattr(tcmd, 'data', None):
                    args.append(chr(tcmd.magic) + tcmd.data)
                else:
                    args.append(tcmd.cmd.name)
            tokens += tokenize_params(*args)
        elif body:
            args  = [getattr(body, x)  for x in dir(body) if can_tokenize(getattr(body, x))]
            if getattr(body, 'body', None):
                args += [getattr(body.body, x) for x in dir(body.body) if
                         can_tokenize(getattr(body.body, x))]
            tokens += tokenize_params(*args)

        return tokens, dis.length

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        # # FIXME: support switching based on var type
        # # use registers for local vars, and split to read/write funcs?
        # def var_addr(var_index):
        #     start = il.const_pointer(4, 0x100000)
        #     offs = il.mult(4, il.const(4, 4), il.const(4, var_index))
        #     return il.add(4, start, offs)
        def reg_name(block):
            if block.type == VarType.normal:
                return f'N{block.data}'
            elif block.type == VarType.local:
                return f'L{block.data}'
            elif block.type == VarType.room:
                return f'R{block.data}'
            elif block.type == VarType.globall:
                return f'G{block.data}'
            else:
                raise Exception(f"reg_name: unsupported var type '{block.type}'")

        def get_prev_dis(instr):
            prev = self.prev_instruction(instr)
            if not prev:
                raise Exception(f"get_prev_dis: no prev for '{instr.id}' at {hex(instr.addr)}")
            return prev

        def get_dis_value(instr):
            op = instr.op
            if op.id not in [OpType.push_byte, OpType.push_word]:
                raise Exception(f"get_dis_value: unsupported op '{instr.id}' at {hex(instr.addr)}")
            return op.body.data

        def get_prev_value(instr):
            prev = get_prev_dis(instr)
            return get_dis_value(prev)

        def do_pop_list(instr):
            # binja doesn't support popping dynamic num of args from stack,
            # so try to figure out how many do we need to pop.
            num_args = get_prev_value(instr)
            # num_regs need to be popped separately
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # a
            args = [il.pop(4) for _ in range(num_args)]
            return args

        def add_intrinsic(name, block):
            pop_count = getattr(block, 'pop_count', 0)
            push_count = getattr(block, 'push_count', 0)
            pop_list = getattr(block, 'pop_list', False)

            args = []
            if pop_list:
                assert(getattr(block, 'pop_list_first', False))
                args += do_pop_list(dis)

            args += [il.pop(4) for _ in range(pop_count)]

            results = []
            if push_count:
                assert(push_count == 1)
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], name, args))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], name, args))


        implemented = True
        op = dis.op
        body = getattr(op, 'body', None)
        if op.id in [OpType.push_byte, OpType.push_word]:
            il.append(il.push(4, il.const(4, body.data)))
        elif op.id in [OpType.write_byte_var, OpType.write_word_var]:
            # il.append(il.store(4, var_addr(body.data), il.pop(4)))
            il.append(il.set_reg(4, reg_name(body), il.pop(4)))
        elif op.id in [OpType.push_byte_var, OpType.push_word_var]:
            # il.append(il.push(4, il.load(4, var_addr(body.data))))
            il.append(il.push(4, il.reg(4, reg_name(body))))
        elif op.id in [OpType.byte_var_inc, OpType.word_var_inc,
                       OpType.byte_var_dec, OpType.word_var_dec]:
            inc = {
                OpType.byte_var_inc: il.add,
                OpType.word_var_inc: il.add,
                OpType.byte_var_dec: il.sub,
                OpType.word_var_dec: il.sub,
            }
            # il.append(il.set_reg(4, LLIL_TEMP(0), var_addr(body.data)))
            # il.append(il.store(4, il.reg(4, LLIL_TEMP(0)),
            #                       inc[op.id](4,
            #                              il.load(4, il.reg(4, LLIL_TEMP(0))),
            #                              il.const(4, 1))))
            il.append(il.set_reg(4, reg_name(body),
                                  inc[op.id](4,
                                         il.reg(4, reg_name(body)),
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
            il.append(il.jump(il.const(4, addr+dis.length+body.jump_offset)))
            il.mark_label(f)
        elif op.id in [OpType.jump]:
            il.append(il.jump(il.const(4, addr+dis.length+body.jump_offset)))
        elif op.id in [OpType.stop_object_code1, OpType.stop_object_code2]:
            add_intrinsic(op.id.name, body)
            il.append(il.no_ret())
        elif op.id in [OpType.start_script, OpType.start_script_quick]:
            # print(f'>> {op.id.name} at {hex(dis.addr)}')
            args = do_pop_list(dis)
            func_num = dis
            args = [il.pop(4) for _ in args]
            for _ in range(len(args) + 2):
                func_num = self.prev_instruction(func_num)

            if op.id == OpType.start_script:
                flags = get_prev_value(func_num)
                print(f'>>> {hex(addr)} calling function #{get_dis_value(func_num)} with {len(args)} args and flags {flags}')
                il.append(il.intrinsic([], op.id.name, [il.pop(4), il.pop(4)] + args))
            else:
                print(f'>>> {hex(addr)} calling function #{get_dis_value(func_num)} with {len(args)} args')
                il.append(il.intrinsic([], op.id.name, [il.pop(4)] + args))
        elif op.id == OpType.stop_script:
            prev_value = get_prev_value(dis)
            il.append(il.intrinsic([], op.id.name, [il.pop(4)]))
            if prev_value == 0:
                # stopObjectCode
                il.append(il.no_ret())
        elif not getattr(body, 'call_func', True):
            add_intrinsic(op.id.name, body)
        elif getattr(body, 'subop', None):
            if type(body.body) == Scumm6Opcodes.UnknownOp:
                print(f'unknown_op {dis.id} at {hex(addr)}: {getattr(body, "subop", None)}')
                implemented = False
                il.append(il.unimplemented())
            else:
                add_intrinsic(f'{op.id.name}.{body.subop.name}', body.body)
        elif op.id in [OpType.break_here]:
            il.append(il.intrinsic([], op.id.name, []))
        else:
            print(f'not implemented {dis.id} at {hex(addr)}: {getattr(body, "subop", None)}')
            implemented = False
            il.append(il.unimplemented())

        if body and type(body) == Scumm6Opcodes.UnknownOp:
            print(f'unknown_op {dis.id} at {hex(addr)}: {getattr(body, "subop", None)}')
            implemented = False
            il.append(il.unimplemented())

        if implemented:
            view, filename = self.get_view(data, addr)
            if not view:
                raise Exception(f"Can't save current addr: No view for data at {hex(addr)}")
            self.op_addrs[filename].insert_sorted(addr)
            # print(self.op_addrs[filename]._list)

        return dis.length

