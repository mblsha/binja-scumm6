from binaryninja.binaryview import BinaryView;
from binaryninja.architecture import Architecture
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SymbolType, SectionSemantics, Endianness

class Scumm6View(BinaryView):
    name = 'SCUMM6 View'
    long_name = 'SCUMM6 Resources'

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,0x4)
        result = header[0:4] in [b"LECF"]
        print('is_valid_for_data', result)
        return result

    def __init__(self, data):
        arch = 'SCUMM6'
        # data is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.arch = Architecture[arch]
        self.platform = Architecture[arch].standalone_platform
        self.data = data

    def init(self):
        start = 0
        size  = 0x100000
        self.add_auto_segment(start, size, start, size, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        start = size
        size  = 0x200000
        self.add_auto_segment(start, size, start, size, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable)
        start = size
        size  = 0x300000
        self.add_auto_segment(start, size, start, size, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        # self.add_user_section("bank1", 0, 0x100000, SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_entry_point(0xC00402)
        return True

    def perform_get_default_endianness(self):
        return Endianness.LittleEndian

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0
