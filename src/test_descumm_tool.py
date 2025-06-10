import subprocess
import tempfile
from pathlib import Path

import pytest

from .disasm import Scumm6Disasm

from scripts.ensure_descumm import build_descumm

EXPECTED_OUTPUT = """[0000] (AC) soundKludge([264,4,0,47,0])
[0013] (AC) soundKludge([270,4,3])
[0020] (AC) soundKludge([271,262,4,0])
[0030] (AC) soundKludge([271,-1])
[003A] (AC) soundKludge([-1])
[0041] (43) bitvar93 = 0
[0047] (9D) actorOps.setCurActor(7)
[004C] (9D) actorOps.init()
[004E] (9D) actorOps.setCostume(6)
[0053] (9D) actorOps.setTalkColor(13)
[0058] (9D) actorOps.setName("Purple Tentacle")
[006A] (9D) actorOps.setWalkSpeed(4,2)
[0072] (9D) actorOps.setWalkSpeed(4,1)
[007A] (9D) actorOps.setCurActor(6)
[007F] (9D) actorOps.init()
[0081] (9D) actorOps.setCostume(5)
[0086] (9D) actorOps.setTalkColor(10)
[008B] (9D) actorOps.setName("Green Tentacle")
[009C] (9D) actorOps.setWalkSpeed(4,2)
[00A4] (9D) actorOps.setWalkSpeed(4,1)
[00AC] (7F) putActorInXY(7,185,100,2)
[00B9] (7F) putActorInXY(6,288,83,2)
[00C6] (82) animateActor(7,248)
[00CD] (82) animateActor(6,248)
[00D4] (B0) delay(60)
[00D8] (BA) talkActor(sound(0x8, 0xE) + "I don't think you should drink that^",6)
[0111] (A9) wait.waitForMessage()
[0113] (6C) breakHere()
[0114] (5D) unless (bitvar327) jump 113
[011A] (82) animateActor(7,250)
[0121] (9D) actorOps.setCurActor(7)
[0126] (9D) actorOps.setCostume(7)
[012B] (82) animateActor(7,6)
[0132] (CA) delayFrames(7)
[0136] (82) animateActor(7,7)
[013D] (CA) delayFrames(4)
[0141] (82) animateActor(7,8)
[0148] (CA) delayFrames(7)
[014C] (CA) delayFrames(10)
[0150] (82) animateActor(7,9)
[0157] (CA) delayFrames(3)
[015B] (B6) printDebug.begin()
[015D] (B6) printDebug.msg(sound(0x78839, 0xA) + " ")
[0171] (CA) delayFrames(7)
[0175] (CA) delayFrames(5)
[0179] (82) animateActor(7,250)
[0180] (9D) actorOps.setCurActor(7)
[0185] (9D) actorOps.init()
[0187] (9D) actorOps.setCostume(6)
[018C] (9D) actorOps.setTalkColor(13)
[0191] (9D) actorOps.setName("Purple Tentacle")
[01A3] (9D) actorOps.setWalkSpeed(4,2)
[01AB] (BA) talkActor(sound(0x47DC, 0xE) + "Nonsense!",7)
[01C9] (A9) wait.waitForMessage()
[01CB] (BA) talkActor(sound(0x8517, 0x26) + "It makes me feel GREAT!" + wait() + "Smarter!  More aggressive!",7)
[0213] (A9) wait.waitForMessage()
[0215] (AC) soundKludge([272])
[021C] (AC) soundKludge([-1])
[0223] (AC) soundKludge([262,4,127])
[0230] (AC) soundKludge([256,4,7])
[023D] (AC) soundKludge([-1])
[0244] (43) localvar1 = (20 + (VAR_SOUNDRESULT - ((VAR_SOUNDRESULT / 4) * 4)))
[025A] (AC) soundKludge([256,4,8])
[0267] (AC) soundKludge([-1])
[026E] (43) localvar2 = VAR_SOUNDRESULT
[0274] (AC) soundKludge([263,4,2,0,0])
[0287] (AC) soundKludge([-1])
[028E] (AC) soundKludge([264,4,2,localvar1,localvar2])
[02A1] (AC) soundKludge([-1])
[02A8] (5E) startScript(2,69,[0,7,7,241,108])
[02C1] (CA) delayFrames(4)
[02C5] (82) animateActor(6,246)
[02CC] (6C) breakHere()
[02CD] (5D) unless ((array236[7] == 0)) jump 2cc
[02DA] (82) animateActor(7,245)
[02E1] (A9) wait.waitForMessage()
[02E3] (82) animateActor(7,246)
[02EA] (BA) talkActor(sound(0x136FC, 0x1E) + "I feel like I could^",7)
[0313] (A9) wait.waitForMessage()
[0315] (AC) soundKludge([269,4,40,5])
[0325] (AC) soundKludge([262,4,0])
[0332] (AC) soundKludge([269,4,127,5])
[0342] (AC) soundKludge([262,4,127])
[034F] (AC) soundKludge([-1])
[0356] (43) bitvar93 = 1
[035C] (66) stopObjectCodeB()
END
"""


def ensure_demo_bsc6() -> Path:
    bsc6 = Path("DOTTDEMO.bsc6")
    if bsc6.exists():
        return bsc6
    zip_path = Path("dott_demo_files/DOTTDEMO.ZIP")
    if not zip_path.exists():
        pytest.skip("DOTTDEMO sample not available", allow_module_level=True)
    with tempfile.TemporaryDirectory() as td:
        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extract("DOTTDEMO.000", td)
            zf.extract("DOTTDEMO.001", td)
        subprocess.check_call(
            [
                "python",
                "converter/cli.py",
                f"{td}/DOTTDEMO.000",
                f"{td}/DOTTDEMO.001",
                "-o",
                str(bsc6),
            ]
        )
    return bsc6


def test_descumm_runs() -> None:
    descumm = build_descumm()
    bsc6 = ensure_demo_bsc6()

    data = bsc6.read_bytes()
    result = Scumm6Disasm().decode_container(str(bsc6), data)
    assert result is not None
    scripts, _ = result
    script = next(s for s in scripts if s.name == "room2_scrp1")

    with tempfile.TemporaryDirectory() as td:
        script_file = Path(td) / "script.bin"
        script_file.write_bytes(data[script.start : script.end])

        proc = subprocess.run(
            [str(descumm), "-6", "-u", str(script_file)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == EXPECTED_OUTPUT.strip()
