#!/usr/bin/env python

import argparse
from pathlib import Path
import importlib
import importlib.util
import sys
import os

# Add binja_helpers to path for standalone execution
if __package__ is None or __package__ == "":
    # Force use of mock
    os.environ["FORCE_BINJA_MOCK"] = "1"
    
    # Get repository root (go up one level from converter dir)
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    
    # Add binja_helpers to path FIRST
    helper_dir = repo_root / "binja_helpers_tmp"
    if helper_dir.is_dir():
        sys.path.insert(0, str(helper_dir))
    
    module_path = Path(__file__).resolve().parent / "converter.py"
    spec = importlib.util.spec_from_file_location("converter", module_path)
    assert spec and spec.loader
    converter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(converter)
else:
    from . import converter


def valid_file_type(filename: str) -> str:
    if not (filename.endswith(".000") or filename.endswith(".001")):
        raise argparse.ArgumentTypeError(
            f'File "{filename}" must have a .000 or .001 extension'
        )
    return filename


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert SCUMM6 for analysis")
    parser.add_argument(
        "input_file",
        type=valid_file_type,
        nargs=2,
        help="Input files with .000 or .001 extensions",
    )
    parser.add_argument("-o", "--output", required=True, help="Output file name")

    args = parser.parse_args()

    output_file = args.output
    lecf_data = None
    rnam_data = None
    for path in args.input_file:
        data = converter.read_xored_data(path)
        header = data[:4]
        if header == b"LECF":
            lecf_data = data
        elif header == b"RNAM":
            rnam_data = data
        else:
            raise argparse.ArgumentTypeError(f"{path} is not a valid SCUMM6 file")

    if lecf_data is None or rnam_data is None:
        raise argparse.ArgumentTypeError("Both .000 and .001 files are required")

    bsc6 = converter.read_resources(lecf_data, rnam_data)
    with open(output_file, "wb") as f:
        f.write(bsc6)


if __name__ == "__main__":
    main()
