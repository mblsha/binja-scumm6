from pathlib import Path
import tempfile
import subprocess

import pytest


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
