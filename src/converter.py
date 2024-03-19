from . import disasm
from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container

from typing import Any, NamedTuple, List

OpType = Scumm6Opcodes.OpType
SubopType = Scumm6Opcodes.SubopType


class StringInfo(NamedTuple):
    op_addr: str
    script_name: str
    string: List[str]


def visit_strings(data: bytes, start: int, end: int, script_name: str) -> List[StringInfo]:
    r: List[StringInfo] = []
    if script_name != 'room76_scrp3':
        return r
    print(script_name, hex(start), hex(end))

    portion = data[start:end]
    with open('portion.bin', 'wb') as f:
        # f.write(b'SCRP')
        # f.write((end - start + 8).to_bytes(4, 'big'))
        f.write(portion)

    def tokenize_talk_actor(body: Any) -> List[str]:
        args = []
        for tcmd in body.cmds:
            if tcmd.has_str:
                a = [chr(i) for i in tcmd.string_data]
                args.append(chr(tcmd.magic) + "".join(a))
            # elif getattr(tcmd, 'cmd', None):
            #     args.append(tcmd.cmd.name)
            # else:
            #     args.append("UNKNOWN")
        return args

    def can_tokenize(param: Any) -> bool:
        # if isinstance(param, int):
        #     return True
        if isinstance(param, str):
            return not param.startswith("scumm6")
        return False

    pos = start
    while pos < end:
        data_view = data[pos:pos+256]
        dis = disasm.Scumm6Disasm().decode_instruction(data_view, pos)
        if not dis:
            break
        pos += dis.length

        # print(hex(pos), dis.id)

        op = dis.op
        body = getattr(op, "body", None)
        if op.id in [OpType.talk_actor, OpType.set_object_name]:
            strs = tokenize_talk_actor(body)
            r.append(StringInfo(op_addr=hex(dis.addr), script_name=script_name, string=strs))
        elif (
            op.id
            in [
                OpType.print_line,
                OpType.print_text,
                OpType.print_debug,
                OpType.print_system,
                OpType.print_actor,
                OpType.print_ego,
            ]
            and body
            and body.subop == SubopType.textstring
        ):
            strs = tokenize_talk_actor(body.body)
            r.append(StringInfo(op_addr=hex(dis.addr), script_name=script_name, string=strs))
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
            for a in args:
                r.append(StringInfo(op_addr=hex(dis.addr),
                                    script_name=script_name, string=[a]))

    return sorted(r, key=lambda x: x.op_addr)

def read_resources(lecf_filename: str) -> Any:
    dscr = disasm.read_dscr(lecf_filename)

    with open(lecf_filename, "rb") as f:
        data = f.read()
    ks = KaitaiStream(BytesIO(data))
    r = Scumm6Container(ks)

    state = disasm.State()
    state.dscr = dscr

    scripts = disasm.get_script_addrs(r.blocks[0], state, 0)
    strings = []
    for s in scripts:
        strings.extend(visit_strings(data, s.start, s.end, s.name))

    # deduplicate strings
    # string -> id
    # write strings in id order
    # write lookup table, op to string id

    # write table: script id -> addr

    return strings
