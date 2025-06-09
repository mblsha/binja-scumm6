# Mock binaryninja.enums for CI testing

class SegmentFlag:
    """Mock SegmentFlag enum"""
    SegmentExecutable = 1
    SegmentContainsCode = 2
    SegmentReadable = 4

class SectionSemantics:
    """Mock SectionSemantics enum"""
    ReadOnlyCodeSectionSemantics = 1
    ReadOnlyDataSectionSemantics = 2

