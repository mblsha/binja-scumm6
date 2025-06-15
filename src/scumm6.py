from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_analysis import MockAnalysisInfo

from typing import Any, List, Optional, Tuple, Dict

import threading
from collections import defaultdict

from binaryninja import core_ui_enabled  # type: ignore[attr-defined]
from binaryninja.architecture import Architecture, IntrinsicInfo  # type: ignore[attr-defined]
from binaryninja.lowlevelil import (
    LowLevelILLabel,
    LLIL_TEMP,
)
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.enums import (  # type: ignore[attr-defined]
    Endianness,
    BranchType,
    InstructionTextTokenType,
    FlagRole,
    ImplicitRegisterExtend,
)
from binaryninja import lowlevelil

if core_ui_enabled():
    from binaryninjaui import UIContext

from .disasm import Scumm6Disasm, Instruction, State
from .scumm6_opcodes import Scumm6Opcodes
from .message import parse_message

from .sorted_list import SortedList

from . import vars

OpType = Scumm6Opcodes.OpType
VarType = Scumm6Opcodes.VarType
SubopType = Scumm6Opcodes.SubopType


# called by Scumm6View
class LastBV:
    _last_bv: Optional[BinaryView] = None
    _lock = threading.Lock()

    @staticmethod
    def set(bv: BinaryView) -> None:
        with LastBV._lock:
            print("set_last_bv", bv, threading.current_thread().name)
            LastBV._last_bv = bv

    @staticmethod
    def get() -> Optional[BinaryView]:
        with LastBV._lock:
            result = LastBV._last_bv
            if not result:
                print("get_last_bv: no last_bv", threading.current_thread().name)
            return result


# FIXME: create a fake memory segment for all the function names,
# so that cross-references will work
class Scumm6(Architecture):
    name = "SCUMM6"
    address_size = 4
    default_int_size = 4
    max_instr_length = 256
    endianness = Endianness.LittleEndian
    regs = {
        "sp": RegisterInfo(
            "sp", 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth
        ),
    } | {
        # local
        f"L{i}": RegisterInfo(f"L{i}", 4)
        for i in range(vars.NUM_SCRIPT_LOCAL)
    }

    stack_pointer = "sp"
    flags = ["n", "z", "v", "c"]
    flag_write_types = ["*"]
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
        self.disasm = Scumm6Disasm()

    def get_view(
        self, data: bytes, addr: int
    ) -> Tuple[Optional[BinaryView], Optional[str]]:
        if not core_ui_enabled():
            return (None, None)

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

        last_bv = LastBV.get()
        if last_bv:
            # check that the data matches in case last_bv is not the right view
            data2 = last_bv.read(addr, len(data))  # type: ignore[attr-defined]
            if data == data2:
                return (last_bv, last_bv.file.filename)  # type: ignore[attr-defined]
            else:
                # FIXME: could be because of the .synthetic_builtins section
                print(
                    f"get_view({hex(addr)}) data mismatch:\nwant: {data!r},\n got: {data2!r}"
                )
        assert last_bv
        return (None, None)

    def get_state(self, instr: Instruction) -> State:
        # FIXME: this won't work correctly if we open several files
        view = LastBV.get()
        return view.state  # type: ignore

    def prev_instruction(self, instr: Instruction) -> Instruction:
        view, filename = self.get_view(instr.data, instr.addr)
        if not view:
            raise Exception(f"prev_instruction: no view at {hex(instr.addr)}")
        assert filename
        prev_addr = self.op_addrs[filename].closest_left_match(instr.addr)
        assert prev_addr
        # print(f'prev_instruction: addr:{instr.addr:x} -> prev:{prev_addr:x}')
        data2 = view.read(prev_addr, 256)  # type: ignore[attr-defined]
        dis = self.decode_instruction(data2, prev_addr)
        if not dis:
            raise Exception(
                f"prev_instruction: no disasm at {prev_addr:x} len{len(data2)}"
            )
        return dis

    def decode_instruction(self, data: bytes, addr: int) -> Optional[Instruction]:
        dis = self.disasm.decode_instruction(data, addr)
        if dis and not core_ui_enabled():
            try:
                info = MockAnalysisInfo()
                info.length = dis.length
                op = dis.op
                body = getattr(op, "body", None)
                if body and getattr(body, "jump_offset", None) is not None:
                    info.add_branch(
                        BranchType.TrueBranch,
                        addr + info.length + body.jump_offset,
                    )
                    info.add_branch(BranchType.FalseBranch, addr + info.length)
                dis = dis._replace(analysis_info=info)
            except Exception:
                pass
        return dis

    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        result = InstructionInfo()
        result.length = dis.length

        op = dis.op
        body = getattr(op, "body", None)
        # print(op, body, op.id)
        if body:
            if getattr(body, "jump_offset", None) is not None:
                result.add_branch(
                    BranchType.TrueBranch, addr + result.length + body.jump_offset
                )
                result.add_branch(BranchType.FalseBranch, addr + result.length)
                # raise Exception('Unhandled jump_offset for op %s' % op.id)

        return result

    def get_instruction_text(
        self, data: bytes, addr: int
    ) -> Optional[Tuple[List[InstructionTextToken], int]]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        def tokenize_params(*params: Any) -> List[InstructionTextToken]:
            r = [
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, "("
                )
            ]
            need_comma = False
            for x in params:
                if need_comma:
                    r += [
                        InstructionTextToken(
                            InstructionTextTokenType.OperandSeparatorToken, ", "
                        )
                    ]
                r += [
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, str(x))
                ]
                need_comma = True
            r += [
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, ")"
                )
            ]
            return r

        op = dis.op
        body = getattr(op, "body", None)

        intrinsic_name = dis.id
        subop = getattr(body, "subop", None)
        if body and subop:
            intrinsic_name += f".{body.subop.name}"
        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, intrinsic_name)
        ]

        def can_tokenize(param: Any) -> bool:
            if isinstance(param, int):
                return True
            if isinstance(param, str):
                return not param.startswith("scumm6")
            return False

        def tokenize_talk_actor(
            body: Scumm6Opcodes.Message, tokens: List[InstructionTextToken]
        ) -> None:
            message = parse_message(body)
            args = []
            for i in message:
                if isinstance(i, str):
                    args.append(i)
                else:
                    type_str = str(i.part_type).replace("PartType.", "")
                    args.append(type_str)
            tokens += tokenize_params(*args)

        if isinstance(body, Scumm6Opcodes.Message):
            assert body
            tokenize_talk_actor(body, tokens)
        elif (
            body
            and hasattr(body, "body")
            and isinstance(body.body, Scumm6Opcodes.Message)
        ):
            tokenize_talk_actor(body.body, tokens)
        elif body:
            args = [
                getattr(body, x) for x in dir(body) if can_tokenize(getattr(body, x))
            ]
            if getattr(body, "body", None):
                args += [
                    getattr(body.body, x)
                    for x in dir(body.body)
                    if can_tokenize(getattr(body.body, x))
                ]
            tokens += tokenize_params(*args)

        return tokens, dis.length

    def get_instruction_low_level_il(
        self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction
    ) -> Optional[int]:
        dis = self.decode_instruction(data, addr)
        if not dis:
            return None

        def get_prev_dis(instr: Instruction) -> Instruction:
            prev = self.prev_instruction(instr)
            if not prev:
                raise Exception(
                    f"get_prev_dis: no prev for '{instr.id}' at {hex(instr.addr)}"
                )
            return prev

        def get_dis_value(instr: Instruction) -> int:
            op = instr.op
            if op.id not in [OpType.push_byte, OpType.push_word]:
                raise Exception(
                    f"get_dis_value: unsupported op '{instr.id}' at {hex(instr.addr)}"
                )
            assert isinstance(op.body.data, int)
            return op.body.data

        def get_prev_value(instr: Instruction) -> int:
            prev = get_prev_dis(instr)
            return get_dis_value(prev)

        def do_pop_list(instr: Instruction) -> List[Any]:
            # binja doesn't support popping dynamic num of args from stack,
            # so try to figure out how many do we need to pop.
            num_args = get_prev_value(instr)
            # num_args need to be popped separately
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            args = [il.pop(4) for _ in range(num_args)]
            return args

        def add_intrinsic(name: str, block: Any) -> None:
            pop_count = getattr(block, "pop_count", 0)
            push_count = getattr(block, "push_count", 0)
            pop_list = getattr(block, "pop_list", False)

            args = []
            if pop_list and block.pop_list_first:
                args += do_pop_list(dis)

            args += [il.pop(4) for _ in range(pop_count)]

            if pop_list and not block.pop_list_first:
                args += do_pop_list(dis)

            if push_count:
                assert push_count == 1
                il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], name, args))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                il.append(il.intrinsic([], name, args))

        implemented = True
        op = dis.op
        body = getattr(op, "body", None)
        if op.id in [OpType.push_byte, OpType.push_word]:
            assert body
            il.append(il.push(4, il.const(4, body.data)))
        elif op.id in [OpType.write_byte_var, OpType.write_word_var]:
            il.append(vars.il_set_var(il, body, il.pop(4)))
        elif op.id in [OpType.push_byte_var, OpType.push_word_var]:
            il.append(il.push(4, vars.il_get_var(il, body)))
        elif op.id in [
            OpType.byte_var_inc,
            OpType.word_var_inc,
            OpType.byte_var_dec,
            OpType.word_var_dec,
        ]:
            inc = {
                OpType.byte_var_inc: il.add,
                OpType.word_var_inc: il.add,
                OpType.byte_var_dec: il.sub,
                OpType.word_var_dec: il.sub,
            }
            il.append(
                vars.il_set_var(
                    il, body, inc[op.id](4, vars.il_get_var(il, body), il.const(4, 1))
                )
            )
        # elif (
        #     op.id in [OpType.array_ops]
        #     and body
        #     and body.subop == SubopType.assign_string
        # ):
        #     prefix_len = 1 + 2
        #     string_start_ptr = dis.addr + prefix_len
        #     string_len = dis.length - prefix_len
        #     # ScummEngine_v6::o6_arrayOps()
        #     # https://github.com/scummvm/scummvm/blob/master/engines/scumm/script_v6.cpp#L2330
        #     pass
        # elif op.id in [OpType.byte_array_read, OpType.word_array_read]:
        #     il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4))) # base
        #     il.append(il.set_reg(4, LLIL_TEMP(1), body.data)) # ?
        #     int base = pop();
        #     # int ScummEngine_v6::readArray(int array, int idx, int base)
        #     push(readArray(fetchScriptByte(), 0, base));
        #     pass
        elif op.id in [
            OpType.eq,
            OpType.neq,
            OpType.gt,
            OpType.lt,
            OpType.le,
            OpType.ge,
        ]:
            comp = {
                OpType.eq: il.compare_equal,
                OpType.neq: il.compare_not_equal,
                OpType.gt: il.compare_signed_greater_than,
                OpType.lt: il.compare_signed_less_than,
                OpType.le: il.compare_signed_less_equal,
                OpType.ge: il.compare_signed_greater_equal,
            }
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
            comp_res = comp[op.id](4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0)))
            il.append(il.push(4, comp_res))
        elif op.id in [
            OpType.add,
            OpType.sub,
            OpType.mul,
            OpType.div,
            OpType.land,
            OpType.lor,
        ]:
            subopt = {
                OpType.add: il.add,
                OpType.sub: il.sub,
                OpType.mul: il.mult,
                OpType.div: il.div_signed,
                OpType.land: il.and_expr,
                OpType.lor: il.or_expr,
            }
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
            il.append(
                il.push(
                    4,
                    subopt[op.id](4, il.reg(4, LLIL_TEMP(1)), il.reg(4, LLIL_TEMP(0))),
                )
            )
        elif op.id in [OpType.dup]:
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        elif op.id in [OpType.nott]:
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
            comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
            il.append(il.push(4, comp_res))
        elif op.id in [OpType.iff, OpType.if_not]:
            comp = {
                OpType.iff: il.compare_not_equal,
                OpType.if_not: il.compare_equal,
            }
            t = LowLevelILLabel()
            f = LowLevelILLabel()
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(
                il.if_expr(
                    comp[op.id](4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0)), t, f
                )
            )
            il.mark_label(t)
            assert body
            il.append(il.jump(il.const(4, addr + dis.length + body.jump_offset)))
            il.mark_label(f)
        elif op.id in [OpType.jump]:
            assert body
            il.append(il.jump(il.const(4, addr + dis.length + body.jump_offset)))
        elif op.id in [OpType.stop_object_code1, OpType.stop_object_code2]:
            add_intrinsic(op.id.name, body)
            il.append(il.no_ret())
        elif op.id in [OpType.start_script, OpType.start_script_quick]:
            # o6_startScript
            # https://github.com/scummvm/scummvm/blob/master/engines/scumm/script_v6.cpp#L871

            # args are last in stack
            args = do_pop_list(dis)  # implicitly pops num_args

            # need to somehow preserve the local state
            SAVE_ARGS_REG_START = 10
            for index, a in enumerate(args):
                il.append(il.set_reg(4, LLIL_TEMP(SAVE_ARGS_REG_START + index), a))

            # go back enough to get the function number,
            # it's pushed before the args
            func_num = dis
            for _ in range(len(args) + 2):
                func_num = self.prev_instruction(func_num)

            func_num_value = get_dis_value(func_num)
            try:
                func_ptr = Scumm6Disasm.get_script_ptr(
                    self.get_state(dis), func_num_value, dis.addr
                )
            except:  # noqa: E722
                print(f"get_script_ptr failed: {func_num_value} at {hex(dis.addr)}")
                raise

            # fake pus to "read the func num"
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))

            if op.id == OpType.start_script:
                flags = get_prev_value(func_num)
                # fake push to "read the flags"
                il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))
                # ScummEngine::runScript()
                # https://github.com/scummvm/scummvm/blob/master/engines/scumm/script.cpp#L59
                # freeze_resistant = (flags & 1) != 0
                recursive = (flags & 2) != 0

                if not recursive:
                    il.append(
                        il.intrinsic([], "stop_script", [il.const_pointer(4, func_ptr)])
                    )

            for index, a in enumerate(args):
                il.append(il.push(4, il.reg(4, LLIL_TEMP(SAVE_ARGS_REG_START + index))))

            # expect binja to use pushed args as function args
            il.append(il.call(il.const_pointer(4, func_ptr)))
        elif op.id == OpType.stop_script:
            prev_value = get_prev_value(dis)
            il.append(il.intrinsic([], op.id.name, [il.pop(4)]))
            if prev_value == 0:
                # stopObjectCode
                il.append(il.no_ret())
        elif not getattr(body, "call_func", True):
            add_intrinsic(op.id.name, body)
        elif isinstance(body, Scumm6Opcodes.Message):
            message = parse_message(body)
            state = self.get_state(dis)
            args = []
            for i in message:
                if isinstance(i, str):
                    str_addr = state.bstr[i]
                    args.append(il.const_pointer(4, str_addr))
            il.append(il.intrinsic([], op.id.name, args))
        elif (
            body
            and hasattr(body, "body")
            and isinstance(body.body, Scumm6Opcodes.Message)
        ):
            message = parse_message(body.body)
            state = self.get_state(dis)
            args = []
            for i in message:
                if isinstance(i, str):
                    str_addr = state.bstr[i]
                    args.append(il.const_pointer(4, str_addr))
            name = f"{op.id.name}.{body.subop.name}"
            il.append(il.intrinsic([], name, args))
        elif getattr(body, "subop", None):
            assert body
            add_intrinsic(f"{op.id.name}.{body.subop.name}", body.body)
        elif op.id in [OpType.break_here]:
            il.append(il.intrinsic([], op.id.name, []))
        else:
            implemented = False
            il.append(il.unimplemented())

        if body and isinstance(body, Scumm6Opcodes.UnknownOp):
            print(f'unknown_op {dis.id} at {hex(addr)}: {getattr(body, "subop", None)}')
            implemented = False
            il.append(il.unimplemented())

        if implemented:
            view, filename = self.get_view(data, addr)
            if not view:
                raise Exception(
                    f"Can't save current addr: No view for data at {hex(addr)}"
                )
            assert filename
            self.op_addrs[filename].insert_sorted(addr)
            # print(self.op_addrs[filename]._list)

        return dis.length
