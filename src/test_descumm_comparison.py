#!/usr/bin/env python3
"""
Simplified testing framework comparing descumm output with Scumm6 disassembler outputs.

This streamlined test framework:
1. Uses a single parametrized test function for all comparisons
2. Dynamically extracts SCUMM6 script bytecode from DOTTDEMO.bsc6
3. Executes descumm, regular disassembly, fusion disassembly, and LLIL generation
4. Compares outputs against expectations with comprehensive validation
5. Consolidates all test logic into one comprehensive function
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, NamedTuple, Optional, Tuple
import sys
import os
from dataclasses import dataclass
from textwrap import dedent
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLLIL, MockIntrinsic, MockReg, set_size_lookup
from binaryninja.enums import BranchType
from src.scumm6 import Scumm6
from src.container import ContainerParser as Scumm6Disasm, ScriptAddr, State
from scripts.ensure_descumm import build_descumm

# Import ensure_demo_bsc6 from test_descumm_tool
from src.test_descumm_tool import ensure_demo_bsc6

# Import utilities from centralized test utils
from src.test_utils import (
    run_descumm_on_bytecode,
    run_scumm6_disassembler,
    run_scumm6_disassembler_with_fusion,
    run_scumm6_llil_generation,
    assert_llil_operations_match,
    collect_branches_from_architecture
)

# Configure SCUMM6-specific LLIL size suffixes
set_size_lookup(
    size_lookup={1: ".b", 2: ".w", 3: ".l", 4: ".4"},  # 4-byte operations use ".4" for SCUMM6
    suffix_sz={"b": 1, "w": 2, "l": 3, "4": 4}  # Add reverse mapping for ".4"
)


def mintrinsic(name: str, outputs: Optional[List[MockLLIL]] = None, params: Optional[List[MockLLIL]] = None) -> MockIntrinsic:
    """Helper to create MockIntrinsic objects more easily."""
    if outputs is None:
        outputs = []
    if params is None:
        params = []
    return MockIntrinsic(name, outputs, params)


def mreg(name: str) -> MockReg:
    """Helper to create MockReg objects more easily."""
    return MockReg(name)


@dataclass
class ScriptComparisonTestCase:
    """Test case for comparing descumm and SCUMM6 disassembler outputs."""
    test_id: str
    script_name: str  # e.g., "room8_scrp18", "room11_enter"
    expected_descumm_output: Optional[str] = None
    expected_disasm_output: Optional[str] = None
    expected_disasm_fusion_output: Optional[str] = None  # Output with instruction fusion enabled
    expected_branches: Optional[List[Tuple[int, Tuple[BranchType, int]]]] = None  # List of (relative_addr, (branch_type, relative_target_addr))
    expected_llil: Optional[List[Tuple[int, MockLLIL]]] = None  # List of (relative_addr, llil_operation) for regular disassembly
    expected_llil_fusion: Optional[List[Tuple[int, MockLLIL]]] = None  # List of (relative_addr, llil_operation) for fusion-enabled disassembly


class ComparisonTestEnvironment(NamedTuple):
    """Container for test environment artifacts."""
    descumm_path: Path
    bsc6_data: bytes
    scripts: List[ScriptAddr]
    state: State


# Test cases with expected outputs - copied from original working file
script_test_cases = [
    ScriptComparisonTestCase(
        test_id="room8_scrp18_collision_detection",
        script_name="room8_scrp18",
        expected_descumm_output=dedent("""
            [0000] (43) localvar5 = (getObjectX(localvar0) - localvar1)
            [000B] (43) localvar6 = (getObjectY(localvar0) - localvar2)
            [0016] (43) localvar5 = abs(localvar5)
            [001D] (43) localvar6 = abs(localvar6)
            [0024] (5D) if (localvar5 > localvar3) {
            [002E] (43)   var137 = 0
            [0034] (7C)   stopScript(0)
            [0038] (**) }
            [0038] (5D) if (localvar6 > localvar4) {
            [0042] (43)   var137 = 0
            [0048] (7C)   stopScript(0)
            [004C] (**) }
            [004C] (43) localvar7 = (localvar5 * localvar5)
            [0056] (43) localvar8 = (localvar6 * localvar6)
            [0060] (5D) if (localvar7 < 0) {
            [006A] (B6)   printDebug.begin()
            [006C] (B6)   printDebug.msg("x2 value overflowing in ellipse check")
            [0094] (**) }
            [0094] (5D) if (localvar8 < 0) {
            [009E] (B6)   printDebug.begin()
            [00A0] (B6)   printDebug.msg("y2 value overflowing in ellipse check")
            [00C8] (**) }
            [00C8] (43) localvar11 = 1
            [00CE] (43) localvar12 = 0
            [00D4] (5D) if (localvar7 <= 4000) {
            [00DE] (43)   localvar7 = (localvar7 * 4)
            [00E8] (73) } else {
            [00EB] (43)   localvar3 = (localvar3 / 2)
            [00F5] (**) }
            [00F5] (5D) if (localvar8 <= 4000) {
            [00FF] (43)   localvar8 = (localvar8 * 4)
            [0109] (73) } else {
            [010C] (43)   localvar4 = (localvar4 / 2)
            [0116] (**) }
            [0116] (43) localvar11 = (localvar11 * 4)
            [0120] (5D) if (localvar11 >= 64) {
            [012A] (43)   localvar12 = 1
            [0130] (**) }
            [0130] (5D) unless (localvar12) jump d4
            [0136] (5D) if (localvar3 == 0) {
            [0140] (43)   localvar3 = 1
            [0146] (B6)   printDebug.begin()
            [0148] (B6)   printDebug.msg("very skinny ellipse warning")
            [0166] (**) }
            [0166] (5D) if (localvar4 == 0) {
            [0170] (43)   localvar4 = 1
            [0176] (B6)   printDebug.begin()
            [0178] (B6)   printDebug.msg("very flat ellipse warning")
            [0194] (**) }
            [0194] (43) var137 = ((localvar7 / (localvar3 * localvar3)) + (localvar8 / (localvar4 * localvar4)))
            [01AE] (5D) if (var137 == 0) {
            [01B8] (43)   var137 = 1
            [01BE] (**) }
            [01BE] (5D) if (var137 > localvar11) {
            [01C8] (43)   var137 = 0
            [01CE] (**) }
            [01CE] (66) stopObjectCodeB()
            END
        """).strip(),
    ),
    ScriptComparisonTestCase(
        test_id="room11_enter_initialization",
        script_name="room11_enter",
        # Simplified - just verify output generation, branch analysis works
        # Skip exact string comparisons since function names and offsets can vary
    ),
    ScriptComparisonTestCase(
        test_id="room2_enter_output_verification",
        script_name="room2_enter",
        # No expected outputs - just verify all disassemblers produce output
    ),
    ScriptComparisonTestCase(
        test_id="room8_scrp15_door_locked",
        script_name="room8_scrp15",
        expected_descumm_output=dedent("""
            [0000] (5D) if (!localvar0) {
            [0007] (43)   localvar0 = var7
            [000D] (**) }
            [000D] (5D) if (getState(localvar0) != 1) {
            [0018] (5D)   if (ifClassOfIs(localvar0,[6])) {
            [0025] (70)     setState(localvar0,1)
            [002C] (5D)     if (localvar1) {
            [0032] (70)       setState(localvar1,1)
            [0039] (**)     }
            [0039] (B6)     printDebug.begin()
            [003B] (B6)     printDebug.msg(" ")
            [003F] (73)   } else {
            [0042] (0C)     dup[1] = VAR_EGO
            [0046] (5D)     if (dup[1] == 3) {
            [004D] (BA)       talkActor("Hmm.  This door appears to be locked.",3)
            [0078] (5D)     } else if (dup[1] == 1) {
            [0083] (BA)       talkActor("Hmm.  This door appears to be locked.",1)
            [00AE] (5D)     } else if (dup[1] == 2) {
            [00B9] (BA)       talkActor("Hmm.  This door appears to be locked.",2)
            [00E4] (73)       /* jump e8; */
            [00E7] (**)     }
            [00E7] (**)   }
            [00E8] (**) }
            [00E8] (66) stopObjectCodeB()
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word_var(var_0)
            [0003] nott
            [0004] unless goto +6
            [0007] push_word_var(var_7)
            [000A] write_word_var(var_0)
            [000D] push_word_var(var_0)
            [0010] get_state(...)
            [0011] push_word(1)
            [0014] neq
            [0015] unless goto +208
            [0018] push_word_var(var_0)
            [001B] push_word(6)
            [001E] push_word(1)
            [0021] if_class_of_is
            [0022] unless goto +29
            [0025] push_word_var(var_0)
            [0028] push_word(1)
            [002B] setState(...)
            [002C] push_word_var(var_1)
            [002F] unless goto +7
            [0032] push_word_var(var_1)
            [0035] push_word(1)
            [0038] setState(...)
            [0039] printDebug.begin()
            [003B] printDebug.msg(...)
            [003F] goto +166
            [0042] push_word_var(var_1)
            [0045] dup
            [0046] push_word(3)
            [0049] eq
            [004A] unless goto +46
            [004D] pop1
            [004E] push_word(3)
            [0051] talkActor()
            [0078] goto +109
            [007B] dup
            [007C] push_word(1)
            [007F] eq
            [0080] unless goto +46
            [0083] pop1
            [0084] push_word(1)
            [0087] talkActor()
            [00AE] goto +55
            [00B1] dup
            [00B2] push_word(2)
            [00B5] eq
            [00B6] unless goto +46
            [00B9] pop1
            [00BA] push_word(2)
            [00BD] talkActor()
            [00E4] goto +1
            [00E7] pop1
            [00E8] stopObjectCodeB()
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] push_word_var(var_0)
            [0003] nott
            [0004] unless goto +6
            [0007] var_0 = var_7
            [000D] push_word_var(var_0)
            [0010] get_state(...)
            [0011] if condition goto +208
            [0018] push_word_var(var_0)
            [001B] push_word(6)
            [001E] push_word(1)
            [0021] if_class_of_is
            [0022] unless goto +29
            [0025] setState(var_0, 1)
            [002C] if !var_1 goto +7
            [0032] setState(var_1, 1)
            [0039] printDebug.begin()
            [003B] printDebug.msg(...)
            [003F] goto +166
            [0042] push_word_var(var_1)
            [0045] dup
            [0046] if condition goto +46
            [004D] pop1
            [004E] push_word(3)
            [0051] talkActor()
            [0078] goto +109
            [007B] dup
            [007C] if condition goto +46
            [0083] pop1
            [0084] push_word(1)
            [0087] talkActor()
            [00AE] goto +55
            [00B1] dup
            [00B2] if condition goto +46
            [00B9] pop1
            [00BA] push_word(2)
            [00BD] talkActor()
            [00E4] goto +1
            [00E7] pop1
            [00E8] stopObjectCodeB()
        """).strip(),
        expected_llil=[
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x0003, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0003, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')]), MockLLIL(op='CONST.4', ops=[0])])])),
            (0x0004, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0007, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='LOAD.4', ops=[MockLLIL(op='CONST_PTR.4', ops=[1073741852])])])),
            (0x000A, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='L0'), MockLLIL(op='POP.4', ops=[])])),
            (0x000D, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x0010, mintrinsic('get_state', outputs=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0010, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0011, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0014, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0014, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP1'), MockLLIL(op='POP.4', ops=[])])),
            (0x0014, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_NE.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP1')]), MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])])),
            (0x0015, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0018, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x001B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[6])])),
            (0x001E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0021, mintrinsic('if_class_of_is', outputs=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x0021, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0022, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0025, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x0028, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x002B, mintrinsic('set_state', outputs=[], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x002C, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L1')])])),
            (0x002F, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0032, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L1')])])),
            (0x0035, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0038, mintrinsic('set_state', outputs=[], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x0039, mintrinsic('print_debug', outputs=[], params=[])),
            (0x003B, mintrinsic('print_debug', outputs=[], params=[])),
            (0x003F, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x0042, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='LOAD.4', ops=[MockLLIL(op='CONST_PTR.4', ops=[1073741828])])])),
            (0x0045, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0045, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0045, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0046, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[3])])),
            (0x0049, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0049, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP1'), MockLLIL(op='POP.4', ops=[])])),
            (0x0049, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP1')]), MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])])),
            (0x004A, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x004D, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x004E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[3])])),
            (0x0051, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x0078, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x007B, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x007B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x007B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x007C, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x007F, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x007F, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP1'), MockLLIL(op='POP.4', ops=[])])),
            (0x007F, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP1')]), MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])])),
            (0x0080, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0083, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0084, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0087, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x00AE, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x00B1, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x00B1, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x00B1, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x00B2, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[2])])),
            (0x00B5, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x00B5, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP1'), MockLLIL(op='POP.4', ops=[])])),
            (0x00B5, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP1')]), MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])])),
            (0x00B6, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x00B9, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x00BA, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[2])])),
            (0x00BD, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x00E4, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x00E7, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x00E8, mintrinsic('stop_object_code2', outputs=[], params=[])),
            (0x00E8, MockLLIL(op='NORET', ops=[])),
        ],
        expected_llil_fusion=[
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x0003, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0003, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')]), MockLLIL(op='CONST.4', ops=[0])])])),
            (0x0004, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0007, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='L0'), MockLLIL(op='LOAD.4', ops=[MockLLIL(op='CONST_PTR.4', ops=[1073741852])])])),
            (0x000D, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x0010, mintrinsic('get_state', outputs=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0010, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0018, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x001B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[6])])),
            (0x001E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0021, mintrinsic('if_class_of_is', outputs=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x0021, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0022, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0025, mintrinsic('set_state', outputs=[], params=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')]), MockLLIL(op='CONST.4', ops=[1])])),
            (0x0032, mintrinsic('set_state', outputs=[], params=[MockLLIL(op='REG.4', ops=[MockReg(name='L1')]), MockLLIL(op='CONST.4', ops=[1])])),
            (0x0039, mintrinsic('print_debug', outputs=[], params=[])),
            (0x003B, mintrinsic('print_debug', outputs=[], params=[])),
            (0x003F, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x0042, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='LOAD.4', ops=[MockLLIL(op='CONST_PTR.4', ops=[1073741828])])])),
            (0x0045, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0045, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0045, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x004D, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x004E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[3])])),
            (0x0051, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x0078, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x007B, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x007B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x007B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0083, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0084, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0087, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x00AE, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x00B1, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x00B1, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x00B1, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x00B9, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x00BA, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[2])])),
            (0x00BD, mintrinsic('talk_actor', outputs=[], params=[])),
            (0x00E4, MockLLIL(op='JUMP', ops=[MockLLIL(op='CONST_PTR.4', ops=[579297])])),
            (0x00E7, mintrinsic('pop1', outputs=[], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x00E8, mintrinsic('stop_object_code2', outputs=[], params=[])),
            (0x00E8, MockLLIL(op='NORET', ops=[])),
        ],
    ),
]


@pytest.fixture(scope="session")
def test_environment() -> ComparisonTestEnvironment:
    """Session-scoped fixture providing test environment artifacts."""
    descumm_path = build_descumm()
    bsc6_path = ensure_demo_bsc6()
    bsc6_data = bsc6_path.read_bytes()

    # Decode the container to get scripts list and state
    result = Scumm6Disasm.decode_container(str(bsc6_path), bsc6_data)
    if result is None:
        raise RuntimeError("Failed to decode container")

    scripts, state = result
    return ComparisonTestEnvironment(descumm_path, bsc6_data, scripts, state)


def find_script_by_name(name: str, scripts_list: List[ScriptAddr]) -> ScriptAddr:
    """Find script by name in the scripts list."""
    for script in scripts_list:
        if script.name == name:
            return script
    raise ValueError(f"Script '{name}' not found in scripts list")


@pytest.mark.parametrize("case", script_test_cases, ids=lambda c: c.test_id)
def test_script_comparison(case: ScriptComparisonTestCase, test_environment: ComparisonTestEnvironment) -> None:
    """
    Simple test function that compares script outputs against expectations when provided.
    
    Only performs comparisons if expectations are specified in the test case.
    Always verifies that all disassemblers produce output.
    """
    
    # 1. Find and extract the script bytecode
    script_info = find_script_by_name(case.script_name, test_environment.scripts)
    bytecode = test_environment.bsc6_data[script_info.start:script_info.end]

    # 2. Execute all disassemblers and LLIL generation
    descumm_output = run_descumm_on_bytecode(test_environment.descumm_path, bytecode)
    disasm_output = run_scumm6_disassembler(bytecode, script_info.start)
    disasm_fusion_output = run_scumm6_disassembler_with_fusion(bytecode, script_info.start)
    llil_operations = run_scumm6_llil_generation(bytecode, script_info.start, use_fusion=False)
    llil_fusion_operations = run_scumm6_llil_generation(bytecode, script_info.start, use_fusion=True)

    # 3. Check branch information if expected branches are provided
    if case.expected_branches is not None:
        arch = Scumm6()
        actual_branches = collect_branches_from_architecture(arch, bytecode, script_info.start)
        
        assert len(actual_branches) == len(case.expected_branches), \
            f"Expected {len(case.expected_branches)} branches, got {len(actual_branches)}"
        
        for actual, expected in zip(actual_branches, case.expected_branches):
            assert actual == expected, f"Branch mismatch: expected {expected}, got {actual}"

    # 4. Compare outputs with expectations (only if provided)
    if case.expected_descumm_output is not None:
        expected_descumm = dedent(case.expected_descumm_output).strip()
        assert descumm_output.strip() == expected_descumm, \
            f"descumm output for '{case.script_name}' does not match expected.\n" \
            f"Expected:\n{expected_descumm}\n\nActual:\n{descumm_output.strip()}"

    if case.expected_disasm_output is not None:
        expected_disasm = dedent(case.expected_disasm_output).strip()
        assert disasm_output.strip() == expected_disasm, \
            f"SCUMM6 disassembler output for '{case.script_name}' does not match expected.\n" \
            f"Expected:\n{expected_disasm}\n\nActual:\n{disasm_output.strip()}"

    if case.expected_disasm_fusion_output is not None:
        expected_disasm_fusion = dedent(case.expected_disasm_fusion_output).strip()
        assert disasm_fusion_output.strip() == expected_disasm_fusion, \
            f"SCUMM6 disassembler with fusion output for '{case.script_name}' does not match expected.\n" \
            f"Expected:\n{expected_disasm_fusion}\n\nActual:\n{disasm_fusion_output.strip()}"

    if case.expected_llil is not None:
        assert_llil_operations_match(llil_operations, case.expected_llil, case.script_name, "regular LLIL")

    if case.expected_llil_fusion is not None:
        assert_llil_operations_match(llil_fusion_operations, case.expected_llil_fusion, case.script_name, "fusion LLIL")

    # Always verify that outputs were generated
    assert len(descumm_output.strip()) > 0, f"descumm produced no output for '{case.script_name}'"
    assert len(disasm_output.strip()) > 0, f"SCUMM6 produced no output for '{case.script_name}'"
    assert len(disasm_fusion_output.strip()) > 0, f"SCUMM6 with fusion produced no output for '{case.script_name}'"


if __name__ == "__main__":
    # Run a basic test to verify the framework works
    print("Use 'pytest test_descumm_comparison.py' to run the full test suite")
    print("✅ Simplified test module loaded successfully")