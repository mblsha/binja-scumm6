import subprocess
import tempfile
from pathlib import Path

import pytest

from .disasm import Scumm6Disasm

from scripts.ensure_descumm import build_descumm

EXPECTED_OUTPUT = """[0000] (74) startSound(4)
[0004] (AC) soundKludge([264,4,0,47,0])
[0017] (AC) soundKludge([270,4,3])
[0024] (AC) soundKludge([271,262,4,0])
[0034] (AC) soundKludge([271,-1])
[003E] (AC) soundKludge([-1])
[0045] (43) bitvar93 = 0
[004B] (9D) actorOps.setCurActor(7)
[0050] (9D) actorOps.init()
[0052] (9D) actorOps.setCostume(6)
[0057] (9D) actorOps.setTalkColor(13)
[005C] (9D) actorOps.setName("Purple Tentacle")
[006E] (9D) actorOps.setWalkSpeed(4,2)
[0076] (9D) actorOps.setWalkSpeed(4,1)
[007E] (9D) actorOps.setCurActor(6)
[0083] (9D) actorOps.init()
[0085] (9D) actorOps.setCostume(5)
[008A] (9D) actorOps.setTalkColor(10)
[008F] (9D) actorOps.setName("Green Tentacle")
[00A0] (9D) actorOps.setWalkSpeed(4,2)
[00A8] (9D) actorOps.setWalkSpeed(4,1)
[00B0] (7F) putActorInXY(7,185,100,2)
[00BD] (7F) putActorInXY(6,288,83,2)
[00CA] (82) animateActor(7,248)
[00D1] (82) animateActor(6,248)
[00D8] (B0) delay(60)
[00DC] (BA) talkActor(sound(0x8, 0xE) + "I don't think you should drink that^",6)
[0115] (A9) wait.waitForMessage()
[0117] (6C) breakHere()
[0118] (5D) unless (bitvar327) jump 117
[011E] (82) animateActor(7,250)
[0125] (9D) actorOps.setCurActor(7)
[012A] (9D) actorOps.setCostume(7)
[012F] (82) animateActor(7,6)
[0136] (CA) delayFrames(7)
[013A] (82) animateActor(7,7)
[0141] (CA) delayFrames(4)
[0145] (82) animateActor(7,8)
[014C] (CA) delayFrames(7)
[0150] (CA) delayFrames(10)
[0154] (82) animateActor(7,9)
[015B] (CA) delayFrames(3)
[015F] (B6) printDebug.begin()
[0161] (B6) printDebug.msg(sound(0x78839, 0xA) + " ")
[0175] (CA) delayFrames(7)
[0179] (CA) delayFrames(5)
[017D] (82) animateActor(7,250)
[0184] (9D) actorOps.setCurActor(7)
[0189] (9D) actorOps.init()
[018B] (9D) actorOps.setCostume(6)
[0190] (9D) actorOps.setTalkColor(13)
[0195] (9D) actorOps.setName("Purple Tentacle")
[01A7] (9D) actorOps.setWalkSpeed(4,2)
[01AF] (BA) talkActor(sound(0x47DC, 0xE) + "Nonsense!",7)
[01CD] (A9) wait.waitForMessage()
[01CF] (BA) talkActor(sound(0x8517, 0x26) + "It makes me feel GREAT!" + wait() + "Smarter!  More aggressive!",7)
[0217] (A9) wait.waitForMessage()
[0219] (AC) soundKludge([272])
[0220] (AC) soundKludge([-1])
[0227] (AC) soundKludge([262,4,127])
[0234] (AC) soundKludge([256,4,7])
[0241] (AC) soundKludge([-1])
[0248] (43) localvar1 = (20 + (VAR_SOUNDRESULT - ((VAR_SOUNDRESULT / 4) * 4)))
[025E] (AC) soundKludge([256,4,8])
[026B] (AC) soundKludge([-1])
[0272] (43) localvar2 = VAR_SOUNDRESULT
[0278] (AC) soundKludge([263,4,2,0,0])
[028B] (AC) soundKludge([-1])
[0292] (AC) soundKludge([264,4,2,localvar1,localvar2])
[02A5] (AC) soundKludge([-1])
[02AC] (5E) startScript(2,69,[0,7,7,241,108])
[02C5] (CA) delayFrames(4)
[02C9] (82) animateActor(6,246)
[02D0] (6C) breakHere()
[02D1] (5D) unless ((array236[7] == 0)) jump 2d0
[02DE] (82) animateActor(7,245)
[02E5] (A9) wait.waitForMessage()
[02E7] (82) animateActor(7,246)
[02EE] (BA) talkActor(sound(0x136FC, 0x1E) + "I feel like I could^",7)
[0317] (A9) wait.waitForMessage()
[0319] (AC) soundKludge([269,4,40,5])
[0329] (AC) soundKludge([262,4,0])
[0336] (AC) soundKludge([269,4,127,5])
[0346] (AC) soundKludge([262,4,127])
[0353] (AC) soundKludge([-1])
[035A] (43) bitvar93 = 1
[0360] (66) stopObjectCodeB()
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
