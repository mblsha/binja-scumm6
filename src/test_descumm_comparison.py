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
from src.address_normalization import normalize_jump_addresses

# Configure SCUMM6-specific LLIL size suffixes
set_size_lookup(
    size_lookup={1: ".1", 2: ".2", 3: ".3", 4: ".4"},  # 4-byte operations use ".4" for SCUMM6
    suffix_sz={"1": 1, "2": 2, "3": 3, "4": 4}  # Add reverse mapping for ".4"
)


def mintrinsic(name: str, outputs: Optional[List[MockReg]] = None, params: Optional[List[MockLLIL]] = None) -> MockIntrinsic:
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
    script_name: Optional[str] = None  # e.g., "room8_scrp18", "room11_enter" - optional if bytecode is provided
    bytecode: Optional[bytes] = None  # Hard-coded bytecode sequence for testing
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
        expected_disasm_output=dedent("""
            [0000] push_word_var(keypress)
            [0003] getObjectX(...)
            [0004] push_word_var(ego)
            [0007] sub
            [0008] write_word_var(localvar5)
            [000B] push_word_var(keypress)
            [000E] getObjectY(...)
            [000F] push_word_var(cameraPosX)
            [0012] sub
            [0013] write_word_var(localvar6)
            [0016] push_word_var(override)
            [0019] abs
            [001A] write_word_var(localvar5)
            [001D] push_word_var(machineSpeed)
            [0020] abs
            [0021] write_word_var(localvar6)
            [0024] push_word_var(override)
            [0027] push_word_var(haveMsg)
            [002A] gt
            [002B] unless goto +10
            [002E] push_word(0)
            [0031] write_word_var(var_137)
            [0034] push_word(0)
            [0037] stopScript(...)
            [0038] push_word_var(machineSpeed)
            [003B] push_word_var(room)
            [003E] gt
            [003F] unless goto +10
            [0042] push_word(0)
            [0045] write_word_var(var_137)
            [0048] push_word(0)
            [004B] stopScript(...)
            [004C] push_word_var(override)
            [004F] push_word_var(override)
            [0052] mul
            [0053] write_word_var(localvar7)
            [0056] push_word_var(machineSpeed)
            [0059] push_word_var(machineSpeed)
            [005C] mul
            [005D] write_word_var(localvar8)
            [0060] push_word_var(me)
            [0063] push_word(0)
            [0066] lt
            [0067] unless goto +42
            [006A] printDebug.begin()
            [006C] printDebug.msg("x2 value overflowing in ellipse check")
            [0094] push_word_var(numActor)
            [0097] push_word(0)
            [009A] lt
            [009B] unless goto +42
            [009E] printDebug.begin()
            [00A0] printDebug.msg("y2 value overflowing in ellipse check")
            [00C8] push_word(1)
            [00CB] write_word_var(localvar11)
            [00CE] push_word(0)
            [00D1] write_word_var(localvar12)
            [00D4] push_word_var(me)
            [00D7] push_word(4000)
            [00DA] le
            [00DB] unless goto +13
            [00DE] push_word_var(me)
            [00E1] push_word(4)
            [00E4] mul
            [00E5] write_word_var(localvar7)
            [00E8] jump f5
            [00EB] push_word_var(haveMsg)
            [00EE] push_word(2)
            [00F1] div
            [00F2] write_word_var(localvar3)
            [00F5] push_word_var(numActor)
            [00F8] push_word(4000)
            [00FB] le
            [00FC] unless goto +13
            [00FF] push_word_var(numActor)
            [0102] push_word(4)
            [0105] mul
            [0106] write_word_var(localvar8)
            [0109] jump 116
            [010C] push_word_var(room)
            [010F] push_word(2)
            [0112] div
            [0113] write_word_var(localvar4)
            [0116] push_word_var(tmr1)
            [0119] push_word(4)
            [011C] mul
            [011D] write_word_var(localvar11)
            [0120] push_word_var(tmr1)
            [0123] push_word(64)
            [0126] ge
            [0127] unless goto +6
            [012A] push_word(1)
            [012D] write_word_var(localvar12)
            [0130] push_word_var(tmr2)
            [0133] unless goto -98
            [0136] push_word_var(haveMsg)
            [0139] push_word(0)
            [013C] eq
            [013D] unless goto +38
            [0140] push_word(1)
            [0143] write_word_var(localvar3)
            [0146] printDebug.begin()
            [0148] printDebug.msg("very skinny ellipse warning")
            [0166] push_word_var(room)
            [0169] push_word(0)
            [016C] eq
            [016D] unless goto +36
            [0170] push_word(1)
            [0173] write_word_var(localvar4)
            [0176] printDebug.begin()
            [0178] printDebug.msg("very flat ellipse warning")
            [0194] push_word_var(me)
            [0197] push_word_var(haveMsg)
            [019A] push_word_var(haveMsg)
            [019D] mul
            [019E] div
            [019F] push_word_var(numActor)
            [01A2] push_word_var(room)
            [01A5] push_word_var(room)
            [01A8] mul
            [01A9] div
            [01AA] add
            [01AB] write_word_var(var_137)
            [01AE] push_word_var(var_137)
            [01B1] push_word(0)
            [01B4] eq
            [01B5] unless goto +6
            [01B8] push_word(1)
            [01BB] write_word_var(var_137)
            [01BE] push_word_var(var_137)
            [01C1] push_word_var(tmr1)
            [01C4] gt
            [01C5] unless goto +6
            [01C8] push_word(0)
            [01CB] write_word_var(var_137)
            [01CE] stopObjectCodeB()
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] localvar5 = ((getObjectX(localvar0)) - (localvar1))
            [000B] localvar6 = ((getObjectY(localvar0)) - (localvar2))
            [0016] push_word_var(override)
            [0019] abs
            [001A] write_word_var(localvar5)
            [001D] push_word_var(machineSpeed)
            [0020] abs
            [0021] write_word_var(localvar6)
            [0024] if ((localvar5 > localvar3)) jump 38
            [002E] var_137 = 0
            [0034] stopScript(0)
            [0038] if ((localvar6 > localvar4)) jump 4c
            [0042] var_137 = 0
            [0048] stopScript(0)
            [004C] localvar7 = ((localvar5) * (localvar5))
            [0056] localvar8 = ((localvar6) * (localvar6))
            [0060] if ((localvar7 < 0)) jump 94
            [006A] printDebug.begin()
            [006C] printDebug.msg("x2 value overflowing in ellipse check")
            [0094] if ((localvar8 < 0)) jump c8
            [009E] printDebug.begin()
            [00A0] printDebug.msg("y2 value overflowing in ellipse check")
            [00C8] localvar11 = 1
            [00CE] localvar12 = 0
            [00D4] if ((localvar7 <= 4000)) jump eb
            [00DE] localvar7 = ((localvar7) * 4)
            [00E8] jump f5
            [00EB] localvar3 = ((localvar3) / 2)
            [00F5] if ((localvar8 <= 4000)) jump 10c
            [00FF] localvar8 = ((localvar8) * 4)
            [0109] jump 116
            [010C] localvar4 = ((localvar4) / 2)
            [0116] localvar11 = ((localvar11) * 4)
            [0120] if ((localvar11 >= 64)) jump 130
            [012A] localvar12 = 1
            [0130] while (!localvar12) { # 92 bytes
            [0136] unless ((localvar3 == 0)) jump 166
            [0140] localvar3 = 1
            [0146] printDebug.begin()
            [0148] printDebug.msg("very skinny ellipse warning")
            [0166] unless ((localvar4 == 0)) jump 194
            [0170] localvar4 = 1
            [0176] printDebug.begin()
            [0178] printDebug.msg("very flat ellipse warning")
            [0194] var_137 = ((((localvar7) / (((localvar3) * (localvar3))))) + (((localvar8) / (((localvar4) * (localvar4))))))
            [01AE] unless ((var_137 == 0)) jump 1be
            [01B8] var_137 = 1
            [01BE] if ((var_137 > localvar11)) jump 1ce
            [01C8] var_137 = 0
            [01CE] stopObjectCodeB()
        """).strip(),
    ),
    ScriptComparisonTestCase(
        test_id="room11_enter_initialization",
        script_name="room11_enter",
        expected_descumm_output=dedent("""
            [0000] (5D) if (!isScriptRunning(137)) {
            [0008] (5F)   startScriptQuick(93,[1])
            [0012] (9C)   roomOps.setScreen(0,200)
            [001A] (**) }
            [001A] (65) stopObjectCodeA()
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word(137)
            [0003] isScriptRunning(...)
            [0004] nott
            [0005] unless goto +18
            [0008] push_word(93)
            [000B] push_word(1)
            [000E] push_word(1)
            [0011] startScriptQuick(...)
            [0012] push_word(0)
            [0015] push_word(200)
            [0018] roomOps.setScreen(...)
            [001A] stopObjectCodeA()
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] if ((!isScriptRunning(137))) jump 1a
            [0008] startScriptQuick(93, [1])
            [0012] roomOps.setScreen(0, 200)
            [001A] stopObjectCodeA()
        """).strip(),
        expected_branches=[(0x05, (BranchType.TrueBranch, 0x1A))],
        expected_llil=[
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[137])])),
            (0x0003, mintrinsic('is_script_running', outputs=[mreg('TEMP0')], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0003, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[mreg('TEMP0')])])),
            (0x0004, MockLLIL(op='SET_REG.4{0}', ops=[mreg('TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0004, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[mreg('TEMP0')]), MockLLIL(op='CONST.4', ops=[0])])])),
            (0x0005, MockLLIL(op='SET_REG.4{0}', ops=[mreg('TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0008, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[93])])),
            (0x000B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x000E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0011, mintrinsic('start_script_quick', outputs=[], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x0012, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[0])])),
            (0x0015, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[200])])),
            (0x0018, mintrinsic('room_ops.room_screen', outputs=[], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
            (0x001A, mintrinsic('stop_object_code1', outputs=[], params=[])),
            (0x001A, MockLLIL(op='NORET', ops=[])),
        ],
        expected_llil_fusion=[
            # When instructions are fused, all LLIL operations are generated at the fused instruction's address
            (0x0000, mintrinsic('is_script_running', outputs=[mreg('TEMP0')], params=[MockLLIL(op='CONST.4', ops=[137])])),
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[mreg('TEMP0')])])),
            (0x0000, MockLLIL(op='SET_REG.4{0}', ops=[mreg('TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_E.4', ops=[MockLLIL(op='REG.4', ops=[mreg('TEMP0')]), MockLLIL(op='CONST.4', ops=[0])])])),
            (0x0000, MockLLIL(op='SET_REG.4{0}', ops=[mreg('TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0008, mintrinsic('start_script_quick', outputs=[], params=[MockLLIL(op='CONST.4', ops=[93]), MockLLIL(op='CONST.4', ops=[1])])),
            (0x0012, mintrinsic('room_ops.room_screen', outputs=[], params=[MockLLIL(op='CONST.4', ops=[0]), MockLLIL(op='CONST.4', ops=[200])])),
            (0x001A, mintrinsic('stop_object_code1', outputs=[], params=[])),
            (0x001A, MockLLIL(op='NORET', ops=[])),
        ],
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
            [0000] push_word_var(keypress)
            [0003] nott
            [0004] unless goto +6
            [0007] push_word_var(me)
            [000A] write_word_var(localvar0)
            [000D] push_word_var(keypress)
            [0010] get_state(...)
            [0011] push_word(1)
            [0014] neq
            [0015] unless goto +208
            [0018] push_word_var(keypress)
            [001B] push_word(6)
            [001E] push_word(1)
            [0021] if_class_of_is
            [0022] unless goto +29
            [0025] push_word_var(keypress)
            [0028] push_word(1)
            [002B] setState(...)
            [002C] push_word_var(ego)
            [002F] unless goto +7
            [0032] push_word_var(ego)
            [0035] push_word(1)
            [0038] setState(...)
            [0039] printDebug.begin()
            [003B] printDebug.msg(" ")
            [003F] jump e8
            [0042] push_word_var(ego)
            [0045] dup
            [0046] push_word(3)
            [0049] eq
            [004A] unless goto +46
            [004D] pop1
            [004E] push_word(3)
            [0051] talkActor()
            [0078] jump e8
            [007B] dup
            [007C] push_word(1)
            [007F] eq
            [0080] unless goto +46
            [0083] pop1
            [0084] push_word(1)
            [0087] talkActor()
            [00AE] jump e8
            [00B1] dup
            [00B2] push_word(2)
            [00B5] eq
            [00B6] unless goto +46
            [00B9] pop1
            [00BA] push_word(2)
            [00BD] talkActor()
            [00E4] jump e8
            [00E7] pop1
            [00E8] stopObjectCodeB()
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] if ((!!localvar0)) jump d
            [0007] localvar0 = me
            [000D] if ((get_state(localvar0) != 1)) jump e8
            [0018] if ((ifClassOfIs(localvar0,[6]))) jump 42
            [0025] setState(localvar0, 1)
            [002C] if ((!localvar1)) jump 39
            [0032] setState(localvar1, 1)
            [0039] printDebug.begin()
            [003B] printDebug.msg(" ")
            [003F] jump e8
            [0042] push_word_var(ego)
            [0045] dup
            [0046] unless ((eq(3))) jump 7b
            [004D] pop1
            [004E] talkActor("Hmm.  This door appears to be locked.", 3)
            [0078] jump e8
            [007B] dup
            [007C] unless ((eq(1))) jump b1
            [0083] pop1
            [0084] talkActor("Hmm.  This door appears to be locked.", 1)
            [00AE] jump e8
            [00B1] dup
            [00B2] unless ((eq(2))) jump e7
            [00B9] pop1
            [00BA] talkActor("Hmm.  This door appears to be locked.", 2)
            [00E4] jump e8
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
            (0x0010, mintrinsic('get_state', outputs=[MockReg(name='TEMP0')], params=[MockLLIL(op='POP.4', ops=[])])),
            (0x0010, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])),
            (0x0011, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0014, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0014, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP1'), MockLLIL(op='POP.4', ops=[])])),
            (0x0014, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CMP_NE.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='TEMP1')]), MockLLIL(op='REG.4', ops=[MockReg(name='TEMP0')])])])),
            (0x0015, MockLLIL(op='SET_REG.4{0}', ops=[MockReg(name='TEMP0'), MockLLIL(op='POP.4', ops=[])])),
            (0x0018, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='REG.4', ops=[MockReg(name='L0')])])),
            (0x001B, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[6])])),
            (0x001E, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[1])])),
            (0x0021, mintrinsic('if_class_of_is', outputs=[MockReg(name='TEMP0')], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
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
    ),
    ScriptComparisonTestCase(
        test_id="start_script_quick_multi_args",
        bytecode=bytes([
            0x01, 0x5D, 0x00, 0x01, 0x0B, 0x00, 0x01, 0x16,
            0x00, 0x01, 0x21, 0x00, 0x01, 0x03, 0x00, 0x5F,
        ]),
        expected_descumm_output=dedent("""
            [0000] (5F) startScriptQuick(93,[11,22,33])
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word(93)
            [0003] push_word(11)
            [0006] push_word(22)
            [0009] push_word(33)
            [000C] push_word(3)
            [000F] startScriptQuick(...)
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] startScriptQuick(93, [11, 22, 33])
        """).strip(),
        expected_llil=[
            (0x0000, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[93])])),
            (0x0003, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[11])])),
            (0x0006, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[22])])),
            (0x0009, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[33])])),
            (0x000C, MockLLIL(op='PUSH.4', ops=[MockLLIL(op='CONST.4', ops=[3])])),
            (0x000F, mintrinsic('start_script_quick', outputs=[], params=[MockLLIL(op='POP.4', ops=[]), MockLLIL(op='POP.4', ops=[])])),
        ],
        expected_llil_fusion=[
            (0x0000, mintrinsic('start_script_quick', outputs=[], params=[MockLLIL(op='CONST.4', ops=[93]), MockLLIL(op='CONST.4', ops=[11]), MockLLIL(op='CONST.4', ops=[22]), MockLLIL(op='CONST.4', ops=[33])])),
        ],
    ),
    ScriptComparisonTestCase(
        test_id="room2_scrp1_descumm_output",
        script_name="room2_scrp1",
        expected_descumm_output=dedent(
            """
            [0000] (74) startSound(4)
            [0004] (AC) soundKludge([264,4,0,47,0])
            [0017] (AC) soundKludge([270,4,3])
            [0024] (AC) soundKludge([271,262,4,0])
            [0034] (AC) soundKludge([271,-1])
            [003E] (AC) soundKludge([-1])
            [0045] (43) bitvar93 = 0
            [004B] (9D) actorOps.setCurActor(7)
            [0050] (9D) actorOps.init()
            [0052] (9D) actorOps.setCostume(6)
            [0057] (9D) actorOps.setTalkColor(13)
            [005C] (9D) actorOps.setName("Purple Tentacle")
            [006E] (9D) actorOps.setWalkSpeed(4,2)
            [0076] (9D) actorOps.setWalkSpeed(4,1)
            [007E] (9D) actorOps.setCurActor(6)
            [0083] (9D) actorOps.init()
            [0085] (9D) actorOps.setCostume(5)
            [008A] (9D) actorOps.setTalkColor(10)
            [008F] (9D) actorOps.setName("Green Tentacle")
            [00A0] (9D) actorOps.setWalkSpeed(4,2)
            [00A8] (9D) actorOps.setWalkSpeed(4,1)
            [00B0] (7F) putActorInXY(7,185,100,2)
            [00BD] (7F) putActorInXY(6,288,83,2)
            [00CA] (82) animateActor(7,248)
            [00D1] (82) animateActor(6,248)
            [00D8] (B0) delay(60)
            [00DC] (BA) talkActor(sound(0x8, 0xE) + "I don't think you should drink that^",6)
            [0115] (A9) wait.waitForMessage()
            [0117] (6C) breakHere()
            [0118] (5D) unless (bitvar327) jump 117
            [011E] (82) animateActor(7,250)
            [0125] (9D) actorOps.setCurActor(7)
            [012A] (9D) actorOps.setCostume(7)
            [012F] (82) animateActor(7,6)
            [0136] (CA) delayFrames(7)
            [013A] (82) animateActor(7,7)
            [0141] (CA) delayFrames(4)
            [0145] (82) animateActor(7,8)
            [014C] (CA) delayFrames(7)
            [0150] (CA) delayFrames(10)
            [0154] (82) animateActor(7,9)
            [015B] (CA) delayFrames(3)
            [015F] (B6) printDebug.begin()
            [0161] (B6) printDebug.msg(sound(0x78839, 0xA) + " ")
            [0175] (CA) delayFrames(7)
            [0179] (CA) delayFrames(5)
            [017D] (82) animateActor(7,250)
            [0184] (9D) actorOps.setCurActor(7)
            [0189] (9D) actorOps.init()
            [018B] (9D) actorOps.setCostume(6)
            [0190] (9D) actorOps.setTalkColor(13)
            [0195] (9D) actorOps.setName("Purple Tentacle")
            [01A7] (9D) actorOps.setWalkSpeed(4,2)
            [01AF] (BA) talkActor(sound(0x47DC, 0xE) + "Nonsense!",7)
            [01CD] (A9) wait.waitForMessage()
            [01CF] (BA) talkActor(sound(0x8517, 0x26) + "It makes me feel GREAT!" + wait() + "Smarter!  More aggressive!",7)
            [0217] (A9) wait.waitForMessage()
            [0219] (AC) soundKludge([272])
            [0220] (AC) soundKludge([-1])
            [0227] (AC) soundKludge([262,4,127])
            [0234] (AC) soundKludge([256,4,7])
            [0241] (AC) soundKludge([-1])
            [0248] (43) localvar1 = (20 + (VAR_SOUNDRESULT - ((VAR_SOUNDRESULT / 4) * 4)))
            [025E] (AC) soundKludge([256,4,8])
            [026B] (AC) soundKludge([-1])
            [0272] (43) localvar2 = VAR_SOUNDRESULT
            [0278] (AC) soundKludge([263,4,2,0,0])
            [028B] (AC) soundKludge([-1])
            [0292] (AC) soundKludge([264,4,2,localvar1,localvar2])
            [02A5] (AC) soundKludge([-1])
            [02AC] (5E) startScript(2,69,[0,7,7,241,108])
            [02C5] (CA) delayFrames(4)
            [02C9] (82) animateActor(6,246)
            [02D0] (6C) breakHere()
            [02D1] (5D) unless ((array236[7] == 0)) jump 2d0
            [02DE] (82) animateActor(7,245)
            [02E5] (A9) wait.waitForMessage()
            [02E7] (82) animateActor(7,246)
            [02EE] (BA) talkActor(sound(0x136FC, 0x1E) + "I feel like I could^",7)
            [0317] (A9) wait.waitForMessage()
            [0319] (AC) soundKludge([269,4,40,5])
            [0329] (AC) soundKludge([262,4,0])
            [0336] (AC) soundKludge([269,4,127,5])
            [0346] (AC) soundKludge([262,4,127])
            [0353] (AC) soundKludge([-1])
            [035A] (43) bitvar93 = 1
            [0360] (66) stopObjectCodeB()
            END
            """
        ).strip(),
    ),
    # ===== Migrated InstructionInfo test cases =====
    ScriptComparisonTestCase(
        test_id="instruction_info_unless_positive",
        bytecode=bytes([0x5D, 0x12, 0x00]),
        expected_branches=[(0x0, (BranchType.TrueBranch, 0x15))],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_unless_negative",
        bytecode=bytes([0x5D, 0x9E, 0xFF]),
        expected_branches=[(0x0, (BranchType.TrueBranch, -95))],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_if_positive",
        bytecode=bytes([0x5C, 0x0A, 0x00]),
        expected_branches=[(0x0, (BranchType.TrueBranch, 0x0D))],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_unconditional",
        bytecode=bytes([0x73, 0x0A, 0x00]),
        expected_branches=[(0x0, (BranchType.UnconditionalBranch, 0x0D))],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_if_class_of_is",
        bytecode=bytes([0x6D]),
        expected_branches=[],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_push_byte",
        bytecode=bytes([0x00, 0x05]),
        expected_branches=[],
    ),
    ScriptComparisonTestCase(
        test_id="instruction_info_add_operation",
        bytecode=bytes([0x14]),
        expected_branches=[],
    ),
    ScriptComparisonTestCase(
        test_id="delay_frames_simple",
        bytecode=bytes([0x01, 0x04, 0x00, 0xCA]),
        expected_descumm_output=dedent("""
            [0000] (CA) delayFrames(4)
            END
        """).strip(),
        expected_disasm_fusion_output="[0000] delayFrames(4)",
    ),
    ScriptComparisonTestCase(
        test_id="animate_actor_simple",
        bytecode=bytes([0x01, 0x0A, 0x00, 0x01, 0xFA, 0x00, 0x82]),
        expected_descumm_output=dedent("""
            [0000] (82) animateActor(10,250)
            END
        """).strip(),
        expected_disasm_fusion_output="[0000] animateActor(10, 250)",
    ),
    ScriptComparisonTestCase(
        test_id="sound_kludge_array",
        bytecode=bytes([0x01, 0x08, 0x01, 0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2F, 0x00, 0x01, 0x00, 0x00, 0x01, 0x05, 0x00, 0xAC]),
        expected_descumm_output=dedent("""
            [0000] (AC) soundKludge([264,4,0,47,0])
            END
        """).strip(),
        expected_disasm_fusion_output="[0000] soundKludge([264, 4, 0, 47, 0])",
    ),
    ScriptComparisonTestCase(
        test_id="talk_actor_with_sound",
        bytecode=bytes([0x01, 0x06, 0x00, 0xBA, 0xFF, 0x0A, 0x08, 0x00, 0xFF, 0x0A, 0x00, 0x00, 0xFF, 0x0A, 0x0E, 0x00, 0xFF, 0x0A, 0x00, 0x00, 0x49, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x74, 0x68, 0x69, 0x6E, 0x6B, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x73, 0x68, 0x6F, 0x75, 0x6C, 0x64, 0x20, 0x64, 0x72, 0x69, 0x6E, 0x6B, 0x20, 0x74, 0x68, 0x61, 0x74, 0x5E, 0x00]),
        expected_descumm_output=dedent("""
            [0000] (BA) talkActor(sound(0x8, 0xE) + "I don't think you should drink that^",6)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] talkActor(sound(0x8, 0xE) + "I don\'t think you should drink that^", 6)',
    ),
    ScriptComparisonTestCase(
        test_id="actor_ops_set_name",
        bytecode=bytes.fromhex("9D58507572706C652054656E7461636C6500"),
        expected_descumm_output=dedent("""
            [0000] (9D) actorOps.setName("Purple Tentacle")
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] actorOps.setName("Purple Tentacle")',
    ),
    ScriptComparisonTestCase(
        test_id="actor_ops_set_costume",
        bytecode=bytes.fromhex("00069D4C"),  # push_byte(6), actor_ops.set_costume
        expected_descumm_output=dedent("""
            [0000] (9D) actorOps.setCostume(6)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] actorOps.setCostume(6)',
    ),
    ScriptComparisonTestCase(
        test_id="wait_for_message",
        bytecode=bytes.fromhex("A9A9"),
        expected_descumm_output=dedent("""
            [0000] (A9) wait.waitForMessage()
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] wait.waitForMessage()',
    ),
    ScriptComparisonTestCase(
        test_id="jump_absolute_address",
        # Simple test with padding and a jump instruction to test absolute addressing
        bytecode=bytes.fromhex("01C80043890073F7FF"), 
        # [0000] push_word(200)      # 01 C8 00
        # [0003] write_word_var(137) # 43 89 00
        # [0006] jump -9             # 73 F7 FF (jumps to address 0x0006 + 3 + (-9) = 0 = 0x0)
        expected_descumm_output=dedent("""
            [0000] (43) var137 = 200
            [0006] (73) jump 0
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word(200)
            [0003] write_word_var(var_137)
            [0006] jump 0
        """).strip(),
        expected_disasm_fusion_output=dedent("""
            [0000] var_137 = 200
            [0006] jump 0
        """).strip(),
    ),
    ScriptComparisonTestCase(
        test_id="start_script_with_5_args",
        bytecode=bytes.fromhex("01020001450001000001070001070001F100016C000105005E"),
        expected_descumm_output=dedent("""
            [0000] (5E) startScript(2,69,[0,7,7,241,108])
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] startScript(2, 69, [0, 7, 7, 241, 108])',
    ),
    ScriptComparisonTestCase(
        test_id="array_conditional_jump",
        bytecode=bytes.fromhex("01070007EC000100000E5DF2FF"),
        expected_descumm_output=dedent("""
            [0000] (5D) unless ((array236[7] == 0)) jump ffffffff
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] unless ((array_236[7] == 0)) jump ffffffff',
    ),
    ScriptComparisonTestCase(
        test_id="is_script_running_conditional",
        bytecode=bytes.fromhex("0103008B5D1A00"),
        expected_descumm_output=dedent("""
            [0000] (5D) if (isScriptRunning(3)) {
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] if ((isScriptRunning(3))) jump 21',
    ),
    ScriptComparisonTestCase(
        test_id="complex_nested_expression",
        bytecode=bytes.fromhex("01140003380003380001040017010400161514430140"),
        expected_descumm_output=dedent("""
            [0000] (43) localvar1 = (20 + (VAR_SOUNDRESULT - ((VAR_SOUNDRESULT / 4) * 4)))
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] localvar1 = (20 + (((soundresult) - (((((soundresult) / 4)) * 4)))))',
    ),
    ScriptComparisonTestCase(
        test_id="is_script_running_negated",
        bytecode=bytes.fromhex("0103008B0D5D1200"),
        expected_descumm_output=dedent("""
            [0000] (5D) if (!isScriptRunning(3)) {
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] if ((!isScriptRunning(3))) jump 1a',
    ),
    ScriptComparisonTestCase(
        test_id="save_restore_verbs_fusion",
        bytecode=bytes.fromhex("010200010B00010200A58D"),
        expected_descumm_output=dedent("""
            [0000] (A5) saveRestoreVerbs.saveVerbs(2,11,2)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] saveRestoreVerbs.saveVerbs(2, 11, 2)',
    ),
    ScriptComparisonTestCase(
        test_id="var_gui_colors_array_write",
        bytecode=bytes.fromhex("010900010100476E00"),
        expected_descumm_output=dedent("""
            [0000] (47) VAR_GUI_COLORS[9] = 1
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] VAR_GUI_COLORS[9] = 1',
    ),
    ScriptComparisonTestCase(
        test_id="start_object_with_args",
        bytecode=bytes.fromhex("01000003004001030001000001030001020060"),
        expected_descumm_output=dedent("""
            [0000] (60) startObject(0,localvar0,3,[0,3])
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] startObject(0, localvar0, 3, [0, 3])',
    ),
    ScriptComparisonTestCase(
        test_id="var_pause_msg_string_assignment",
        bytecode=bytes.fromhex("010000A4CD5D0047616D65205061757365642E2020507265737320535041434520746F20436F6E74696E75652E00"),
        expected_descumm_output=dedent("""
            [0000] (A4) VAR_PAUSE_MSG[0] = "Game Paused.  Press SPACE to Continue."
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] VAR_PAUSE_MSG[0] = "Game Paused.  Press SPACE to Continue."',
    ),
    ScriptComparisonTestCase(
        test_id="if_class_of_is_conditional",
        bytecode=bytes.fromhex("030140018B000101006D5D0A00"),
        expected_descumm_output=dedent("""
            [0000] (5D) if (ifClassOfIs(localvar1,[139])) {
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] if ((ifClassOfIs(localvar1,[139]))) jump 17',
    ),
    ScriptComparisonTestCase(
        test_id="draw_object_with_nested_expression",
        bytecode=bytes.fromhex("01DD02010100010200871461"),
        expected_descumm_output=dedent("""
            [0000] (61) drawObject(733,(1 + getRandomNumber(2)))
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] drawObject(733, (1 + (getRandomNumber(2))))',
    ),
    ScriptComparisonTestCase(
        test_id="print_cursor_msg",
        bytecode=bytes.fromhex("B54B446179206F66207468652054656E7461636C6500"),
        expected_descumm_output=dedent("""
            [0000] (B5) printCursor.msg("Day of the Tentacle")
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printCursor.msg("Day of the Tentacle")',
    ),
    ScriptComparisonTestCase(
        test_id="print_line_msg_with_keep_text",
        bytecode=bytes.fromhex("B44B49424D206469736B2D626173656420616E642066756C6C20766F6963652074616C6B69652043442D524F4D2076657273696F6E7320617661696C61626C652053756D6D65722031393933FF0200"),
        expected_descumm_output=dedent("""
            [0000] (B4) printLine.msg("IBM disk-based and full voice talkie CD-ROM versions available Summer 1993" + keepText())
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printLine.msg("IBM disk-based and full voice talkie CD-ROM versions available Summer 1993" + keepText())',
    ),
    ScriptComparisonTestCase(
        test_id="print_cursor_xy",
        bytecode=bytes.fromhex("01A000012800B541"),
        expected_descumm_output=dedent("""
            [0000] (B5) printCursor.XY(160,40)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printCursor.XY(160, 40)',
    ),
    ScriptComparisonTestCase(
        test_id="print_system_msg",
        bytecode=bytes.fromhex("B74B4E6F7420656E6F7567682066726565206D656D6F727920746F2072756E2064656D6F2E00"),
        expected_descumm_output=dedent("""
            [0000] (B7) printSystem.msg("Not enough free memory to run demo.")
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printSystem.msg("Not enough free memory to run demo.")',
    ),
    ScriptComparisonTestCase(
        test_id="dim_array_bit",
        bytecode=bytes.fromhex("010F00BCC8F000"),
        expected_descumm_output=dedent("""
            [0000] (BC) dimArray.bit(var240,15)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] dimArray.bit(var_240, 15)',
    ),
    ScriptComparisonTestCase(
        test_id="pickup_object_fusion",
        bytecode=bytes([0x03, 0x00, 0x40, 0x03, 0x02, 0x40, 0x84]),
        expected_descumm_output=dedent("""
            [0000] (84) pickupObject(localvar0,localvar2)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] pickupObject(localvar0, localvar2)',
    ),
    ScriptComparisonTestCase(
        test_id="print_line_lucasarts_credits",
        bytecode=bytes.fromhex("B44B4C756361734172747320456E7465727461696E6D656E7420436F6D70616E79FF0150726573656E7473FF0200"),
        expected_descumm_output=dedent("""
            [0000] (B4) printLine.msg("LucasArts Entertainment Company" + newline() + "Presents" + keepText())
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printLine.msg("LucasArts Entertainment Company" + newline() + "Presents" + keepText())',
    ),
    ScriptComparisonTestCase(
        test_id="print_cursor_tentacle_amends",
        bytecode=bytes.fromhex("B54B54656E7461636C6520416D656E6473FE01436F6E737469747574696F6E00"),
        expected_descumm_output=dedent("""
            [0000] (B5) printCursor.msg("Tentacle Amends" + newline() + "Constitution")
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] printCursor.msg("Tentacle Amends" + newline() + "Constitution")',
    ),
    ScriptComparisonTestCase(
        test_id="begin_cutscene_with_args",
        bytecode=bytes([
            0x01, 0x0A, 0x00,  # push_word(10) - arg1
            0x01, 0x14, 0x00,  # push_word(20) - arg2  
            0x01, 0x1E, 0x00,  # push_word(30) - arg3
            0x01, 0x03, 0x00,  # push_word(3)  - arg_count
            0x68               # cutscene
        ]),
        expected_descumm_output=dedent("""
            [0000] (68) beginCutscene([10,20,30])
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] beginCutscene([10, 20, 30])',
    ),
    ScriptComparisonTestCase(
        test_id="save_restore_verbs_restore_verbs",
        bytecode=bytes.fromhex("010100010100010200A58E"),
        expected_descumm_output=dedent("""
            [0000] (A5) saveRestoreVerbs.restoreVerbs(1,1,2)
            END
        """).strip(),
        expected_disasm_fusion_output='[0000] saveRestoreVerbs.restoreVerbs(1, 1, 2)',
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
    
    # 1. Get the bytecode - either from hard-coded data or by finding the script
    if case.bytecode is not None:
        bytecode = case.bytecode
        start_addr = 0x0  # Use 0 as base address for hard-coded bytecode
    else:
        if case.script_name is None:
            raise ValueError("Either script_name or bytecode must be provided")
        script_info = find_script_by_name(case.script_name, test_environment.scripts)
        bytecode = test_environment.bsc6_data[script_info.start:script_info.end]
        start_addr = script_info.start

    # 2. Execute all disassemblers and LLIL generation
    descumm_output = run_descumm_on_bytecode(test_environment.descumm_path, bytecode)
    disasm_output = run_scumm6_disassembler(bytecode, start_addr)
    disasm_fusion_output = run_scumm6_disassembler_with_fusion(bytecode, start_addr)
    llil_operations = run_scumm6_llil_generation(bytecode, start_addr, use_fusion=False)
    llil_fusion_operations = run_scumm6_llil_generation(bytecode, start_addr, use_fusion=True)
    
    # Normalize addresses if script starts at non-zero address
    # This makes jump addresses more readable (e.g., "jump f5" instead of "jump 8d892")
    if start_addr != 0:
        disasm_output = normalize_jump_addresses(disasm_output, start_addr)
        disasm_fusion_output = normalize_jump_addresses(disasm_fusion_output, start_addr)

    # 3. Check branch information if expected branches are provided
    if case.expected_branches is not None:
        arch = Scumm6()
        actual_branches = collect_branches_from_architecture(arch, bytecode, start_addr)
        
        assert len(actual_branches) == len(case.expected_branches), \
            f"Expected {len(case.expected_branches)} branches, got {len(actual_branches)}"
        
        for actual, expected in zip(actual_branches, case.expected_branches):
            assert actual == expected, f"Branch mismatch: expected {expected}, got {actual}"

    # 4. Compare outputs with expectations (only if provided)
    if case.expected_descumm_output is not None:
        expected_descumm = dedent(case.expected_descumm_output).strip()
        assert descumm_output.strip() == expected_descumm, \
            f"descumm output for '{case.test_id}' does not match expected.\n" \
            f"Expected:\n{expected_descumm}\n\nActual:\n{descumm_output.strip()}"

    if case.expected_disasm_output is not None:
        expected_disasm = dedent(case.expected_disasm_output).strip()
        assert disasm_output.strip() == expected_disasm, \
            f"SCUMM6 disassembler output for '{case.test_id}' does not match expected.\n" \
            f"Expected:\n{expected_disasm}\n\nActual:\n{disasm_output.strip()}"

    if case.expected_disasm_fusion_output is not None:
        expected_disasm_fusion = dedent(case.expected_disasm_fusion_output).strip()
        assert disasm_fusion_output.strip() == expected_disasm_fusion, \
            f"SCUMM6 disassembler with fusion output for '{case.test_id}' does not match expected.\n" \
            f"Expected:\n{expected_disasm_fusion}\n\nActual:\n{disasm_fusion_output.strip()}"

    if case.expected_llil is not None:
        assert_llil_operations_match(llil_operations, case.expected_llil, case.test_id, "regular LLIL")

    if case.expected_llil_fusion is not None:
        assert_llil_operations_match(llil_fusion_operations, case.expected_llil_fusion, case.test_id, "fusion LLIL")

    # Always verify that outputs were generated
    assert len(descumm_output.strip()) > 0, f"descumm produced no output for '{case.test_id}'"
    assert len(disasm_output.strip()) > 0, f"SCUMM6 produced no output for '{case.test_id}'"
    assert len(disasm_fusion_output.strip()) > 0, f"SCUMM6 with fusion produced no output for '{case.test_id}'"
