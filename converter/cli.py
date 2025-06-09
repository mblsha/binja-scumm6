#!/usr/bin/env python

import argparse
from . import converter


def valid_file_type(filename):
    if not (filename.endswith(".000") or filename.endswith(".001")):
        raise argparse.ArgumentTypeError(
            f'File "{filename}" must have a .000 or .001 extension'
        )
    return filename


def main():
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
    files = sorted(args.input_file)
    lecf_path, rnamn_path = files
    if not lecf_path.endswith(".000"):
        raise argparse.ArgumentTypeError(f"{lecf_path} must have a .000 extension")
    if not rnamn_path.endswith(".001"):
        raise argparse.ArgumentTypeError(f"{rnamn_path} must have a .001 extension")

    lecf_data = converter.read_xored_data(lecf_path)
    rnam_data = converter.read_xored_data(rnamn_path)
    assert lecf_data[:4] == b"LECF"
    assert rnam_data[:4] == b"RNAM"

    bsc6 = converter.read_resources(lecf_data, rnam_data)
    with open(output_file, "wb") as f:
        f.write(bsc6)


if __name__ == "__main__":
    main()
