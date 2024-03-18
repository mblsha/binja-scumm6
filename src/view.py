from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SectionSemantics, Endianness
from .scumm6 import LastBV
from .disasm import Scumm6Disasm, ScriptAddr, State, read_dscr

from typing import List


class Scumm6View(BinaryView):  # type: ignore
    name = "SCUMM6 View"
    long_name = "SCUMM6 Resources"

    @classmethod
    def is_valid_for_data(self, data: BinaryView) -> bool:
        header = data.read(0, 0x4)
        result = header[0:4] in [b"LECF"]
        if result:
            _ = read_dscr(data.file.filename)
        return result

    def __init__(self, parent_view: BinaryView) -> None:
        # parent_view is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(
            self, parent_view=parent_view, file_metadata=parent_view.file
        )
        LastBV.set(self)

        self.disasm = Scumm6Disasm()
        data = parent_view.read(0, parent_view.end)
        container = self.disasm.decode_container(parent_view.file.filename, data)
        assert container
        self.scripts: List[ScriptAddr] = container[0]
        self.state: State = container[1]

        # ScummEngine::runBootscript()
        # global script #1 is normally the boot script
        boot_script = self.disasm.get_script_ptr(self.state, 1, -1)
        assert boot_script
        self.boot_script = boot_script

        self.script_nums = self.disasm.get_script_nums(self.state)

    def init(self) -> bool:
        arch = "SCUMM6"
        self.arch = Architecture[arch]
        self.platform = Architecture[arch].standalone_platform

        for start, end, name, room in self.scripts:
            # print("adding segment:", hex(start), hex(end), name)
            size = end - start

            self.add_auto_segment(
                start, size, start, size, SegmentFlag.SegmentContainsCode
            )

            self.add_user_section(
                name,
                start,
                size,
                SectionSemantics.ReadOnlyCodeSectionSemantics,
            )

            if not self.get_function_at(start):
                self.create_user_function(start)
                f = self.get_function_at(start)

                suffix = ""
                if start in self.script_nums:
                    suffix = f"_{self.script_nums[start]}"

                if start == self.boot_script:
                    f.name = "boot_script_main" + suffix
                else:
                    f.name = name + suffix

        return True

    def perform_get_address_size(self) -> int:
        return 4

    def perform_get_default_endianness(self) -> Endianness:
        return Endianness.LittleEndian

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return self.boot_script
