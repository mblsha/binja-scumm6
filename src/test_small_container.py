import pytest

from .disasm import Scumm6Disasm

SMALL_BSC6 = (
    b"DSCR" + (15).to_bytes(4, "big")
    + (1).to_bytes(2, "little") + b"\x01" + (8).to_bytes(4, "little")
    + b"LOFF" + (14).to_bytes(4, "big") + b"\x01\x01" + (29).to_bytes(4, "little")
    + b"ROOM" + (17).to_bytes(4, "big")
    + b"SCRP" + (9).to_bytes(4, "big") + b"\x66"
)


def test_decode_small_container() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_container("<mem>", SMALL_BSC6)
    assert r is not None
    scripts, state = r

    assert len(scripts) == 1
    script = scripts[0]
    assert script.name == "room1_scrp1"
    assert script.start == disasm.get_script_ptr(state, 0, -1)
