import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "scummvm-tools"
DESCUMM = TOOLS_DIR / "descumm"


def build_descumm() -> Path:
    if DESCUMM.exists():
        return DESCUMM
    # Configure and build descumm
    subprocess.check_call(["./configure", "--disable-wxwidgets"], cwd=TOOLS_DIR)
    subprocess.check_call(["make", "descumm", f"-j{os.cpu_count() or 2}"], cwd=TOOLS_DIR)
    return DESCUMM


if __name__ == "__main__":
    path = build_descumm()
    print(path)
