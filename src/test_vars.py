from . import vars


def test_get_scumm_var() -> None:
    r = vars.get_scumm_var(126)
    assert r is not None
    assert r.name == "VAR_TIMEDATE_MINUTE"
    assert r.address == 0x400001F8
