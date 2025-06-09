from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.types import Symbol
from binaryninja.enums import SymbolType, SegmentFlag, SectionSemantics, Endianness
from .scumm6 import LastBV
from .disasm import Scumm6Disasm, ScriptAddr, State

from typing import List

from . import vars


class Scumm6View(BinaryView):
    name = "SCUMM6 View"
    long_name = "SCUMM6 Resources"

    @classmethod
    def is_valid_for_data(self, data: BinaryView) -> bool:
        header = data.read(0, 0x4)  # type: ignore[attr-defined]
        result = header[0:4] in [b"Bsc6"]
        return result

    def __init__(self, parent_view: BinaryView) -> None:
        # parent_view is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(self, parent_view=parent_view, file_metadata=parent_view.file)  # type: ignore[call-arg,attr-defined]
        LastBV.set(self)

        self.disasm = Scumm6Disasm()
        data = parent_view.read(0, parent_view.end)  # type: ignore[attr-defined]
        container = self.disasm.decode_container(
            parent_view.file.filename,  # type: ignore[attr-defined]
            data,
        )
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
        self.arch = Architecture[arch]  # type: ignore[misc]
        self.platform = Architecture[arch].standalone_platform  # type: ignore[misc]

        # create specinal segments for vars
        self.add_auto_segment(  # type: ignore[attr-defined]
            vars.SCUMM_VARS_START,
            vars.SCUMM_VARS_SIZE,
            0,
            0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )
        self.add_user_section(  # type: ignore[attr-defined]
            "SCUMM VARs",
            vars.SCUMM_VARS_START,
            vars.SCUMM_VARS_SIZE,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )
        uint32_t = self.parse_type_string("uint32_t")[0]  # type: ignore[attr-defined]
        for i in range(vars.NUM_SCUMM_VARS):
            var = vars.get_scumm_var(i)
            if var.name is None:
                continue
            self.define_user_symbol(  # type: ignore[attr-defined]
                Symbol(SymbolType.DataSymbol, var.address, var.name)  # type: ignore[call-arg]
            )
            self.define_user_data_var(var.address, uint32_t)  # type: ignore[attr-defined]

        self.add_auto_segment(  # type: ignore[attr-defined]
            vars.BITVARS_START,
            vars.BITVARS_SIZE,
            0,
            0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )
        self.add_user_section(  # type: ignore[attr-defined]
            "Bit VARs",
            vars.BITVARS_START,
            vars.BITVARS_SIZE,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )

        for start, end, name, create_function, segment_flag, section_semantics in self.scripts:
            # print("adding segment:", hex(start), hex(end), name)
            size = end - start

            self.add_auto_segment(  # type: ignore[attr-defined]
                start, size, start, size, segment_flag
            )

            self.add_user_section(  # type: ignore[attr-defined]
                name,
                start,
                size,
                section_semantics,
            )

            if create_function and not self.get_function_at(start):  # type: ignore[attr-defined]
                self.create_user_function(start)  # type: ignore[attr-defined]
                f = self.get_function_at(start)  # type: ignore[attr-defined]

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
