from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.types import Symbol
from binaryninja.enums import SymbolType, SegmentFlag, SectionSemantics, Endianness
from .scumm6 import LastBV
from .container import ContainerParser as Scumm6Disasm, ScriptAddr, State

from typing import List, cast

from . import vars
from .actor_state import CURRENT_ACTOR_ADDRESS


class Scumm6View(BinaryView):  # type: ignore[misc]
    name = "SCUMM6 View"
    long_name = "SCUMM6 Resources"

    @classmethod
    def is_valid_for_data(self, data: BinaryView) -> bool:
        header = data.read(0, 0x4)
        result = header[0:4] in [b"Bsc6"]
        return result

    def __init__(self, parent_view: BinaryView) -> None:
        # parent_view is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(self, parent_view=parent_view, file_metadata=parent_view.file)
        LastBV.set(self)

        self.disasm = Scumm6Disasm()
        data = parent_view.read(0, parent_view.end)
        container = self.disasm.decode_container(
            parent_view.file.filename,
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
        arch = Architecture["SCUMM6"]  # type: ignore[type-arg,name-defined,unused-ignore]
        self.arch = arch
        self.platform = arch.standalone_platform

        # create specinal segments for vars
        self.add_auto_segment(            vars.SCUMM_VARS_START,
            vars.SCUMM_VARS_SIZE,
            0,
            0,
            cast(SegmentFlag, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable),
        )
        self.add_user_section(            "SCUMM VARs",
            vars.SCUMM_VARS_START,
            vars.SCUMM_VARS_SIZE,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )
        uint32_t = self.parse_type_string("uint32_t")[0]
        for i in range(vars.NUM_SCUMM_VARS):
            var = vars.get_scumm_var(i)
            if var.name is None:
                continue
            self.define_user_symbol(
                Symbol(SymbolType.DataSymbol, var.address, var.name)
            )
            self.define_user_data_var(var.address, uint32_t)
        self.add_auto_segment(
            vars.BITVARS_START,
            vars.BITVARS_SIZE,
            0,
            0,
            cast(SegmentFlag, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable),
        )
        self.add_user_section(
            "Bit VARs",
            vars.BITVARS_START,
            vars.BITVARS_SIZE,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )
        
        # Create segment for actors
        self.add_auto_segment(
            vars.ACTORS_START,
            vars.ACTORS_SIZE,
            0,
            0,
            cast(SegmentFlag, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable),
        )
        self.add_user_section(
            "Actors",
            vars.ACTORS_START,
            vars.ACTORS_SIZE,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )
        
        # Define symbols for each actor
        # Create actor struct type definition based on ActorProperty enum
        actor_struct_def = """struct Actor {
            uint16_t id;              // 0x00
            uint16_t costume;         // 0x02
            uint32_t name_ptr;        // 0x04
            uint16_t x;               // 0x08
            uint16_t y;               // 0x0A
            int16_t elevation;        // 0x0C
            uint8_t room;             // 0x0E
            uint8_t layer;            // 0x0F
            uint16_t target_x;        // 0x10
            uint16_t target_y;        // 0x12
            uint16_t walk_speed_x;    // 0x14
            uint16_t walk_speed_y;    // 0x16
            uint8_t facing_direction; // 0x18
            uint8_t moving;           // 0x19
            uint8_t walk_box;         // 0x1A
            uint8_t _pad1;            // 0x1B
            uint8_t scale_x;          // 0x1C
            uint8_t scale_y;          // 0x1D
            uint8_t width;            // 0x1E
            uint8_t palette;          // 0x1F
            uint8_t talk_color;       // 0x20
            uint8_t _pad2;            // 0x21
            uint16_t flags;           // 0x22
            uint16_t anim_counter;    // 0x24
            uint8_t current_anim;     // 0x26
            uint8_t walk_frame;       // 0x27
            uint8_t stand_frame;      // 0x28
            uint8_t _pad3[3];         // 0x29-0x2B
            uint8_t _reserved[20];    // 0x2C-0x3F (rest of 64-byte struct)
        }"""
        actor_struct_type = self.parse_type_string(actor_struct_def)[0]
        for i in range(vars.MAX_ACTORS):
            actor_addr = vars.ACTORS_START + (i * vars.ACTOR_STRUCT_SIZE)
            self.define_user_symbol(
                Symbol(SymbolType.DataSymbol, actor_addr, f"actor_{i}")
            )
            self.define_user_data_var(actor_addr, actor_struct_type)
        
        # Define current actor pointer
        self.define_user_symbol(
            Symbol(SymbolType.DataSymbol, CURRENT_ACTOR_ADDRESS, "current_actor_id")
        )
        self.define_user_data_var(CURRENT_ACTOR_ADDRESS, uint32_t)

        for start, end, name, create_function, segment_flag, section_semantics in self.scripts:
            # print("adding segment:", hex(start), hex(end), name)
            size = end - start

            self.add_auto_segment(
                start, size, start, size, segment_flag
            )

            self.add_user_section(
                name,
                start,
                size,
                section_semantics,
            )

            if create_function and not self.get_function_at(start):
                self.create_user_function(start)
                f = self.get_function_at(start)
                if f is not None:
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
