import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.container import State, decode_rnam_dscr, get_script_addrs
from kaitaistruct import KaitaiStream, BytesIO  # type: ignore[import-untyped]
from src.scumm6_opcodes import Scumm6Opcodes  # type: ignore[attr-defined]
from src.scumm6_container import Scumm6Container  # type: ignore[attr-defined]
from src.pyscumm6.disasm import decode

from typing import NamedTuple, List

OpType = Scumm6Opcodes.OpType
SubopType = Scumm6Opcodes.SubopType


def parse_message(message: Scumm6Opcodes.Message) -> List[str]:
    """Extract string parts from a SCUMM6 message."""
    current_string = []
    strings = []
    
    for part in message.parts:
        # Check if this is a regular character
        if hasattr(part, 'content') and hasattr(part.content, 'value'):
            # Regular character - add to current string
            current_string.append(chr(part.content.value))
        elif part.data == 0:
            # Terminator - save current string if any
            if current_string:
                strings.append(''.join(current_string))
                current_string = []
        elif part.data == 255:
            # Special sequence - handle special codes
            # For now, just break the string here
            if current_string:
                strings.append(''.join(current_string))
                current_string = []
    
    # Save any remaining string
    if current_string:
        strings.append(''.join(current_string))
    
    return strings


def read_xored_data(filename: str) -> bytes:
    result = b""
    with open(filename, "rb") as fr:
        while True:
            chunk = fr.read(1)
            if not chunk:
                break
            # https://wiki.scummvm.org/index.php/SCUMM/Technical_Reference/SCUMM_6_resource_files#1.2_Basics
            # says to use 0x69
            converted = (chunk[0] ^ 0x69).to_bytes(1, byteorder="big")
            result += converted
    return result


class StringInfo(NamedTuple):
    op_addr: str
    script_name: str
    string: str


def extract_strings(
    data: bytes, start: int, end: int, script_name: str, debug: bool = False
) -> List[StringInfo]:
    r: List[StringInfo] = []
    # if script_name != 'room76_scrp3':
    #     return r
    if debug:
        print(f"Extracting strings from {script_name} [{hex(start)}-{hex(end)}]")

    # portion = data[start:end]
    # with open('portion.bin', 'wb') as f:
    #     # f.write(b'SCRP')
    #     # f.write((end - start + 8).to_bytes(4, 'big'))
    #     f.write(portion)

    def add_message_strings(addr: int, body: Scumm6Opcodes.Message) -> None:
        for i in parse_message(body):
            if isinstance(i, str):
                if debug:
                    print(f"  Message string at {hex(addr)}: {repr(i)}")
                r.append(
                    StringInfo(op_addr=hex(addr), script_name=script_name, string=i)
                )

    def add_call_func_string(addr: int, body: Scumm6Opcodes.CallFuncString) -> None:
        if hasattr(body, 'data') and isinstance(body.data, str) and body.data:
            if debug:
                print(f"  CallFuncString at {hex(addr)}: {repr(body.data)}")
            r.append(
                StringInfo(op_addr=hex(addr), script_name=script_name, string=body.data)
            )

    pos = start
    while pos < end:
        # Use the new decoder, passing the rest of the data and the absolute address
        dis = decode(data[pos:], pos)
        if not dis:
            break
        
        # Use the new instruction object API
        op = dis.op_details
        body = getattr(op, "body", None)

        if isinstance(body, Scumm6Opcodes.Message):
            if debug:
                print(f"  Found Message in {op.id.name if hasattr(op.id, 'name') else op.id}")
            add_message_strings(pos, body)
        elif isinstance(body, Scumm6Opcodes.CallFuncString):
            if debug:
                print(f"  Found CallFuncString in {op.id.name if hasattr(op.id, 'name') else op.id}")
            add_call_func_string(pos, body)
        elif (
            body
            and hasattr(body, "body")
            and isinstance(body.body, Scumm6Opcodes.Message)
        ):
            if debug:
                print(f"  Found nested Message in {op.id.name if hasattr(op.id, 'name') else op.id}")
            add_message_strings(pos, body.body)
        elif (
            body
            and hasattr(body, "body")
            and isinstance(body.body, Scumm6Opcodes.CallFuncString)
        ):
            if debug:
                print(f"  Found nested CallFuncString in {op.id.name if hasattr(op.id, 'name') else op.id}")
            add_call_func_string(pos, body.body)
        
        pos += dis.length()

    return r


def read_resources(lecf_data: bytes, rnam_data: bytes, debug: bool = False) -> bytes:
    ks = KaitaiStream(BytesIO(rnam_data))
    r = Scumm6Container(ks)
    state = State()
    state.dscr = decode_rnam_dscr(r)

    ks = KaitaiStream(BytesIO(lecf_data))
    r = Scumm6Container(ks)
    scripts = get_script_addrs(r.blocks[0], state, 0)
    strings: List[StringInfo] = []
    for script in scripts:
        strings.extend(
            extract_strings(lecf_data, script.start, script.end, script.name, debug)
        )

    # for script in scripts:
    #     if not script.create_function:
    #         continue
    #     data = lecf_data[script.start : script.end]
    #     with open(f"{script.name}.bin", "wb") as f:
    #         f.write(data)

    dedup_strings = set()
    for si in strings:
        dedup_strings.add(si.string)

    if debug:
        print(f"\nFound {len(strings)} total string occurrences")
        print(f"Found {len(dedup_strings)} unique strings")
        
        # Show some examples
        print("\nExample strings found:")
        for i, s in enumerate(sorted(dedup_strings)[:10]):
            print(f"  {i+1}. {repr(s)}")
        if len(dedup_strings) > 10:
            print(f"  ... and {len(dedup_strings) - 10} more")

    string_dict_block = b""
    for s in sorted(dedup_strings):
        string_dict_block += s.encode("iso-8859-1") + b"\0"
    string_dict_len = len(string_dict_block) + 8
    bstr = b"Bstr" + string_dict_len.to_bytes(4, "big") + string_dict_block

    # replace LECF with Bsc6, so the signature matcher in view.py works
    # Note: order for bstr and rnam_data shouldn't matter.
    bsc6 = lecf_data + bstr + rnam_data
    bsc6 = b"Bsc6" + bsc6[4:]

    return bsc6


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <LECF file> <RNAM file> <output BSC6 file> [--debug]")
        sys.exit(1)
    
    lecf_file = sys.argv[1]
    rnam_file = sys.argv[2]
    output_file = sys.argv[3]
    debug = "--debug" in sys.argv
    
    # Read the xor-encrypted files
    lecf_data = read_xored_data(lecf_file)
    rnam_data = read_xored_data(rnam_file)
    
    # Process and create BSC6
    bsc6_data = read_resources(lecf_data, rnam_data, debug)
    
    # Write output
    with open(output_file, "wb") as f:
        f.write(bsc6_data)
    
    print(f"Created {output_file} with BSTR block containing extracted strings.")
