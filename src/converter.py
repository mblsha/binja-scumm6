from . import disasm
from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container
from .message import parse_message

import os

from typing import Any, NamedTuple, List

OpType = Scumm6Opcodes.OpType
SubopType = Scumm6Opcodes.SubopType


class StringInfo(NamedTuple):
    op_addr: str
    script_name: str
    string: str


def extract_strings(
    data: bytes, start: int, end: int, script_name: str
) -> List[StringInfo]:
    r: List[StringInfo] = []
    # if script_name != 'room76_scrp3':
    #     return r
    # print(script_name, hex(start), hex(end))

    # portion = data[start:end]
    # with open('portion.bin', 'wb') as f:
    #     # f.write(b'SCRP')
    #     # f.write((end - start + 8).to_bytes(4, 'big'))
    #     f.write(portion)

    def add_message_strings(dis: Any, body: Scumm6Opcodes.Message) -> None:
        for i in parse_message(body):
            if isinstance(i, str):
                r.append(
                    StringInfo(op_addr=hex(dis.addr), script_name=script_name, string=i)
                )

    pos = start
    while pos < end:
        data_view = data[pos : pos + 256]  # noqa: E203
        dis = disasm.Scumm6Disasm().decode_instruction(data_view, pos)
        if not dis:
            break
        pos += dis.length

        op = dis.op
        body = getattr(op, "body", None)

        if isinstance(body, Scumm6Opcodes.Message):
            add_message_strings(dis, body)
        elif (
            body
            and hasattr(body, "body")
            and isinstance(body.body, Scumm6Opcodes.Message)
        ):
            add_message_strings(dis, body.body)

    return r


def read_resources(lecf_filename: str, rnam_filename: str) -> bytes:
    with open(lecf_filename, "rb") as f:
        lecf_data = f.read()
    with open(rnam_filename, "rb") as f:
        rnam_data = f.read()

    ks = KaitaiStream(BytesIO(rnam_data))
    r = Scumm6Container(ks)
    state = disasm.State()
    state.dscr = disasm.decode_rnam_dscr(r)

    ks = KaitaiStream(BytesIO(lecf_data))
    r = Scumm6Container(ks)
    scripts = disasm.get_script_addrs(r.blocks[0], state, 0)
    strings: List[StringInfo] = []
    for script in scripts:
        strings.extend(extract_strings(lecf_data, script.start, script.end, script.name))

    dedup_strings = set()
    for s in strings:
        dedup_strings.add(s.string)

    string_dict_block = b""
    for s in sorted(dedup_strings):
        string_dict_block += s.encode("utf-8") + b"\0"
    string_dict_len = len(string_dict_block) + 8
    bstr = b"Bstr" + string_dict_len.to_bytes(4, "big") + string_dict_block

    bsc6 = lecf_data + bstr + rnam_data
    bsc6 = b"Bsc6" + bsc6[4:]

    print(sorted(dedup_strings))

    return bsc6
