from .disasm import Scumm6Disasm

from .scumm6_opcodes import Scumm6Opcodes
from .message import parse_message, Part, PartType


OpType = Scumm6Opcodes.OpType


def test_decode_talk_actor() -> None:
    disasm = Scumm6Disasm()

    # printLine.msg("LucasArts Entertainment Company" + newline() + "Presents" + keepText())
    data = (
        b"\xb4\x4b\x4c\x75\x63\x61\x73\x41\x72\x74\x73\x20\x45\x6e\x74\x65"
        + b"\x72\x74\x61\x69\x6e\x6d\x65\x6e\x74\x20\x43\x6f\x6d\x70\x61\x6e"
        + b"\x79\xff\x01\x50\x72\x65\x73\x65\x6e\x74\x73\xff\x02\x00"
    )

    dis = disasm.decode_instruction(data, 0x1234)
    assert dis is not None
    assert dis.length == len(data)
    assert dis.op.id == OpType.print_line
    assert dis.id == "print_line"
    assert dis.op.body.subop == Scumm6Opcodes.SubopType.textstring
    assert parse_message(dis.op.body.body) == [
        "LucasArts Entertainment Company",
        Part(PartType.NEWLINE),
        "Presents",
        Part(PartType.KEEP_TEXT),
    ]

    # printDebug.msg(sound(0x9DE5, 0xA) + " ")
    data = (
        b"\xb6\x4b\xff\x0a\xe5\x9d\xff\x0a\x00\x00\xff\x0a\x0a\x00\xff"
        + b"\x0a\x00\x00\x20\x00"
    )
    dis = disasm.decode_instruction(data, 0x1234)
    assert dis is not None
    assert dis.op.id == OpType.print_debug
    assert parse_message(dis.op.body.body) == [
        Part(PartType.SOUND, [40421, 10]),
        " ",
    ]
