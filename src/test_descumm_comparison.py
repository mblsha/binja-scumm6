#!/usr/bin/env python3
"""
Robust, extensible testing framework comparing descumm output with Scumm6 disassembler outputs.

This refactored test framework:
1. Dynamically extracts SCUMM6 script bytecode from DOTTDEMO.bsc6
2. Executes both descumm and Scumm6 disassembler on the same bytecode
3. Asserts outputs against golden-master strings using pytest.mark.parametrize
4. Provides extensible structure for adding new test cases
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, Any, NamedTuple, Optional, Tuple
import sys
import os
import subprocess
import tempfile
from dataclasses import dataclass
from textwrap import dedent
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction, MockLLIL, mllil
from binaryninja.enums import BranchType
from src.scumm6 import Scumm6, LastBV
from src.test_mocks import MockScumm6BinaryView
from src.disasm import Scumm6Disasm, ScriptAddr, State
from scripts.ensure_descumm import build_descumm

# Import ensure_demo_bsc6 from test_descumm_tool
from src.test_descumm_tool import ensure_demo_bsc6


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


# Test cases with expected outputs
script_test_cases = [
    ScriptComparisonTestCase(
        test_id="room8_scrp18_collision_detection",
        script_name="room8_scrp18",
        expected_descumm_output=dedent("""
            ERROR: No items on stack to pop!
            [0000] (43) localvar5 = (**** INVALID DATA **** - localvar1)
            [0007] (43) localvar6 = (getObjectY(localvar0) - localvar2)
            [0012] (43) localvar5 = abs(localvar5)
            [0019] (43) localvar6 = abs(localvar6)
            [0020] (5D) if (localvar5 > localvar3) {
            [002A] (43)   var137 = 0
            [0030] (7C)   stopScript(0)
            [0034] (**) }
            [0034] (5D) if (localvar6 > localvar4) {
            [003E] (43)   var137 = 0
            [0044] (7C)   stopScript(0)
            [0048] (**) }
            [0048] (43) localvar7 = (localvar5 * localvar5)
            [0052] (43) localvar8 = (localvar6 * localvar6)
            [005C] (5D) if (localvar7 < 0) {
            [0066] (B6)   printDebug.begin()
            [0068] (B6)   printDebug.msg("x2 value overflowing in ellipse check")
            [0090] (**) }
            [0090] (5D) if (localvar8 < 0) {
            [009A] (B6)   printDebug.begin()
            [009C] (B6)   printDebug.msg("y2 value overflowing in ellipse check")
            [00C4] (**) }
            [00C4] (43) localvar11 = 1
            [00CA] (43) localvar12 = 0
            [00D0] (5D) if (localvar7 <= 4000) {
            [00DA] (43)   localvar7 = (localvar7 * 4)
            [00E4] (73) } else {
            [00E7] (43)   localvar3 = (localvar3 / 2)
            [00F1] (**) }
            [00F1] (5D) if (localvar8 <= 4000) {
            [00FB] (43)   localvar8 = (localvar8 * 4)
            [0105] (73) } else {
            [0108] (43)   localvar4 = (localvar4 / 2)
            [0112] (**) }
            [0112] (43) localvar11 = (localvar11 * 4)
            [011C] (5D) if (localvar11 >= 64) {
            [0126] (43)   localvar12 = 1
            [012C] (**) }
            [012C] (5D) unless (localvar12) jump d0
            [0132] (5D) if (localvar3 == 0) {
            [013C] (43)   localvar3 = 1
            [0142] (B6)   printDebug.begin()
            [0144] (B6)   printDebug.msg("very skinny ellipse warning")
            [0162] (**) }
            [0162] (5D) if (localvar4 == 0) {
            [016C] (43)   localvar4 = 1
            [0172] (B6)   printDebug.begin()
            [0174] (B6)   printDebug.msg("very flat ellipse warning")
            [0190] (**) }
            [0190] (43) var137 = ((localvar7 / (localvar3 * localvar3)) + (localvar8 / (localvar4 * localvar4)))
            [01AA] (5D) if (var137 == 0) {
            [01B4] (43)   var137 = 1
            [01BA] (**) }
            [01BA] (5D) if (var137 > localvar11) {
            [01C4] (43)   var137 = 0
            [01CA] (**) }
            [01CA] (66) stopObjectCodeB()
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word_var(var_0)
            [0003] get_object_x
            [0004] push_word_var(var_1)
            [0007] sub
            [0008] write_word_var(var_5)
            [000B] push_word_var(var_0)
            [000E] get_object_y
            [000F] push_word_var(var_2)
            [0012] sub
            [0013] write_word_var(var_6)
            [0016] push_word_var(var_5)
            [0019] abs
            [001A] write_word_var(var_5)
            [001D] push_word_var(var_6)
            [0020] abs
            [0021] write_word_var(var_6)
            [0024] push_word_var(var_5)
            [0027] push_word_var(var_3)
            [002A] gt
            [002B] unless goto +10
            [002E] push_word(0)
            [0031] write_word_var(var_137)
            [0034] push_word(0)
            [0037] stop_script
            [0038] push_word_var(var_6)
            [003B] push_word_var(var_4)
            [003E] gt
            [003F] unless goto +10
            [0042] push_word(0)
            [0045] write_word_var(var_137)
            [0048] push_word(0)
            [004B] stop_script
            [004C] push_word_var(var_5)
            [004F] push_word_var(var_5)
            [0052] mul
            [0053] write_word_var(var_7)
            [0056] push_word_var(var_6)
            [0059] push_word_var(var_6)
            [005C] mul
            [005D] write_word_var(var_8)
            [0060] push_word_var(var_7)
            [0063] push_word(0)
            [0066] lt
            [0067] unless goto +42
            [006A] print_debug.begin()
            [006C] print_debug.msg("x2 value overflowing in ellipse check")
            [0094] push_word_var(var_8)
            [0097] push_word(0)
            [009A] lt
            [009B] unless goto +42
            [009E] print_debug.begin()
            [00A0] print_debug.msg("y2 value overflowing in ellipse check")
            [00C8] push_word(1)
            [00CB] write_word_var(var_11)
            [00CE] push_word(0)
            [00D1] write_word_var(var_12)
            [00D4] push_word_var(var_7)
            [00D7] push_word(4000)
            [00DA] le
            [00DB] unless goto +13
            [00DE] push_word_var(var_7)
            [00E1] push_word(4)
            [00E4] mul
            [00E5] write_word_var(var_7)
            [00E8] goto +10
            [00EB] push_word_var(var_3)
            [00EE] push_word(2)
            [00F1] div
            [00F2] write_word_var(var_3)
            [00F5] push_word_var(var_8)
            [00F8] push_word(4000)
            [00FB] le
            [00FC] unless goto +13
            [00FF] push_word_var(var_8)
            [0102] push_word(4)
            [0105] mul
            [0106] write_word_var(var_8)
            [0109] goto +10
            [010C] push_word_var(var_4)
            [010F] push_word(2)
            [0112] div
            [0113] write_word_var(var_4)
            [0116] push_word_var(var_11)
            [0119] push_word(4)
            [011C] mul
            [011D] write_word_var(var_11)
            [0120] push_word_var(var_11)
            [0123] push_word(64)
            [0126] ge
            [0127] unless goto +6
            [012A] push_word(1)
            [012D] write_word_var(var_12)
            [0130] push_word_var(var_12)
            [0133] unless goto -98
            [0136] push_word_var(var_3)
            [0139] push_word(0)
            [013C] eq
            [013D] unless goto +38
            [0140] push_word(1)
            [0143] write_word_var(var_3)
            [0146] print_debug.begin()
            [0148] print_debug.msg("very skinny ellipse warning")
            [0166] push_word_var(var_4)
            [0169] push_word(0)
            [016C] eq
            [016D] unless goto +36
            [0170] push_word(1)
            [0173] write_word_var(var_4)
            [0176] print_debug.begin()
            [0178] print_debug.msg("very flat ellipse warning")
            [0194] push_word_var(var_7)
            [0197] push_word_var(var_3)
            [019A] push_word_var(var_3)
            [019D] mul
            [019E] div
            [019F] push_word_var(var_8)
            [01A2] push_word_var(var_4)
            [01A5] push_word_var(var_4)
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
            [01C1] push_word_var(var_11)
            [01C4] gt
            [01C5] unless goto +6
            [01C8] push_word(0)
            [01CB] write_word_var(var_137)
            [01CE] stop_object_code2
        """).strip()
    ),
    ScriptComparisonTestCase(
        test_id="room11_enter_initialization",
        script_name="room11_enter",
        expected_descumm_output=dedent("""
            ERROR: No items on stack to pop!
            [0000] (5D) if (!**** INVALID DATA ****) {
            [0004] (5F)   startScriptQuick(93,[1])
            [000E] (9C)   roomOps.setScreen(0,200)
            [0016] (**) }
            [0016] (65) stopObjectCodeA()
            END
        """).strip(),
        expected_disasm_output=dedent("""
            [0000] push_word(137)
            [0003] is_script_running
            [0004] nott
            [0005] unless goto +18
            [0008] push_word(93)
            [000B] push_word(1)
            [000E] push_word(1)
            [0011] start_script_quick(script_id, ...)
            [0012] push_word(0)
            [0015] push_word(200)
            [0018] room_ops.room_screen
            [001A] stop_object_code1
        """).strip(),
        # TODO: Update when fusion is implemented for these instruction types
        # Expected fusion: unless nott(is_script_running(137)) goto +18, start_script_quick(93, 1, 1), etc.
        expected_disasm_fusion_output=dedent("""
            [0000] push_word(137)
            [0003] is_script_running
            [0004] nott
            [0005] unless goto +18
            [0008] push_word(93)
            [000B] push_word(1)
            [000E] push_word(1)
            [0011] start_script_quick(script_id, ...)
            [0012] push_word(0)
            [0015] push_word(200)
            [0018] room_ops.room_screen
            [001A] stop_object_code1
        """).strip(),
        # TODO: Add expected LLIL operations when needed for specific validation
        # Example format:
        # expected_llil=[
        #     (0x0000, mllil("PUSH.error", [mllil("CONST.error", [137])])),
        #     # Note: Complex operations like intrinsics and conditionals require special handling
        # ],
        # expected_llil_fusion=[ ... ],
        expected_branches=[
            # The conditional branch instruction at offset 0x0005 (unless goto +18)
            (0x0005, (BranchType.TrueBranch, 0x001A)),   # Jump to stop_object_code1 (relative +26)
            # Note: FalseBranch (fall-through) is implicit and not reported
        ]
    ),
    # Example of a test case that only verifies output generation without specific content
    ScriptComparisonTestCase(
        test_id="room2_enter_output_verification",
        script_name="room2_enter",
        # No expected outputs - just verifies all disassemblers produce output
        # TODO: Add expected LLIL when specific validation is needed:
        # expected_llil=[
        #     (0x0000, mllil("PUSH.error", [mllil("CONST.error", [1])])),
        #     (0x0003, mllil("PUSH.error", [mllil("CONST.error", [201])])),
        # ],
        # expected_llil_fusion=[ ... ],
    ),
    # Add more test cases here as needed
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


def run_descumm_on_bytecode(descumm_path: Path, bytecode: bytes) -> str:
    """Execute descumm on bytecode and return cleaned output."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_file:
        tmp_file.write(bytecode)
        tmp_file_path = tmp_file.name

    try:
        result = subprocess.run(
            [str(descumm_path), "-6", "-u", tmp_file_path],
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        # Return stdout even if descumm had errors
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            # Include stderr information if there was an error
            output = f"{output}\n<!-- descumm stderr: {result.stderr.strip()} -->"
        return output
    finally:
        os.unlink(tmp_file_path)


def run_scumm6_disassembler(bytecode: bytes, start_addr: int) -> str:
    """Execute SCUMM6 disassembler and return formatted output."""
    arch = Scumm6()
    view = MockScumm6BinaryView()
    view.write_memory(start_addr, bytecode)
    LastBV.set(view)

    output_lines = []
    offset = 0

    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]

        # Get instruction text
        result = arch.get_instruction_text(remaining_data, addr)
        if result is None:
            break

        tokens, length = result
        text = format_output_as_text(tokens)

        # Format as [offset] disassembly_text
        output_lines.append(f"[{offset:04X}] {text}")
        offset += length

    return '\n'.join(output_lines)


def run_scumm6_disassembler_with_fusion(bytecode: bytes, start_addr: int) -> str:
    """Execute SCUMM6 disassembler with instruction fusion and return formatted output."""
    from src.pyscumm6.disasm import decode_with_fusion_incremental
    
    output_lines = []
    offset = 0

    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]

        # Use fusion-enabled decoder
        instruction = decode_with_fusion_incremental(remaining_data, addr)
        if instruction is None:
            break

        # Get tokens from fused instruction rendering
        tokens = instruction.render()
        text = format_output_as_text(tokens)

        # Format as [offset] disassembly_text
        output_lines.append(f"[{offset:04X}] {text}")
        offset += instruction.length()

    return '\n'.join(output_lines)


def format_output_as_text(tokens: List[Any]) -> str:
    """Convert token list to plain text string."""
    return ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)


def run_scumm6_llil_generation(bytecode: bytes, start_addr: int, use_fusion: bool = False) -> List[Tuple[int, MockLLIL]]:
    """Execute SCUMM6 LLIL generation and return list of (offset, llil_operation) tuples."""
    if use_fusion:
        from src.pyscumm6.disasm import decode_with_fusion_incremental as decode_func
    else:
        from src.pyscumm6.disasm import decode as decode_func
    
    llil_operations = []
    offset = 0

    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]

        # Decode instruction
        instruction = decode_func(remaining_data, addr)
        if instruction is None:
            break

        # Generate LLIL for this instruction
        il = MockLowLevelILFunction()
        instruction.lift(il, addr)
        
        # Record each LLIL operation with its offset
        for llil_op in il.ils:
            llil_operations.append((offset, llil_op))
        
        offset += instruction.length()

    return llil_operations


def assert_llil_operations_match(actual_llil: List[Tuple[int, MockLLIL]], 
                                expected_llil: List[Tuple[int, MockLLIL]], 
                                script_name: str, 
                                test_type: str) -> None:
    """Verify that actual LLIL operations match expected operations."""
    assert len(actual_llil) == len(expected_llil), \
        f"LLIL operation count mismatch for '{script_name}' ({test_type}): " \
        f"expected {len(expected_llil)}, got {len(actual_llil)}"

    for i, ((actual_offset, actual_op), (expected_offset, expected_op)) in enumerate(zip(actual_llil, expected_llil)):
        assert actual_offset == expected_offset, \
            f"LLIL operation {i} offset mismatch for '{script_name}' ({test_type}): " \
            f"expected offset 0x{expected_offset:04X}, got 0x{actual_offset:04X}"
        
        assert actual_op == expected_op, \
            f"LLIL operation {i} mismatch for '{script_name}' ({test_type}) at offset 0x{actual_offset:04X}:\n" \
            f"Expected: {expected_op}\n" \
            f"Actual: {actual_op}"


def assert_no_unimplemented_llil(llil_operations: List[Tuple[int, MockLLIL]], script_name: str, test_type: str) -> None:
    """Verify that no LLIL operations are unimplemented."""
    for offset, llil_op in llil_operations:
        _check_no_unimplemented_recursive(llil_op, script_name, test_type, offset)


def _check_no_unimplemented_recursive(llil_op: MockLLIL, script_name: str, test_type: str, offset: int) -> None:
    """Recursively check that no LLIL operations are unimplemented."""
    if llil_op.bare_op() == "UNIMPL":
        raise AssertionError(f"Found unimplemented LLIL in '{script_name}' ({test_type}) at offset 0x{offset:04X}: {llil_op}")
    
    # Recursively check nested operations
    for nested_op in llil_op.ops:
        if isinstance(nested_op, MockLLIL):
            _check_no_unimplemented_recursive(nested_op, script_name, test_type, offset)


def collect_branches_from_architecture(arch: Any, bytecode: bytes, start_addr: int) -> List[Tuple[int, Tuple[BranchType, int]]]:
    """
    Generic function to collect branch information from any SCUMM6 architecture.

    Args:
        arch: The architecture instance (Scumm6)
        bytecode: The bytecode to analyze
        start_addr: The starting address of the bytecode

    Returns:
        List of (relative_offset, (branch_type, relative_target_address)) tuples
    """
    view = MockScumm6BinaryView()
    view.write_memory(start_addr, bytecode)
    LastBV.set(view)

    branches = []
    offset = 0
    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]

        info = arch.get_instruction_info(remaining_data, addr)
        if info is None:
            break

        # Check for branches at this offset
        instruction_branches = []
        if hasattr(info, 'branches') and info.branches:
            instruction_branches = [(b.type, b.target) for b in info.branches]
        elif hasattr(info, 'mybranches') and info.mybranches:
            instruction_branches = info.mybranches

        for branch_type, absolute_target in instruction_branches:
            # Convert absolute target to relative target (relative to script start)
            relative_target = absolute_target - start_addr
            branches.append((offset, (branch_type, relative_target)))

        offset += info.length

    return branches


def verify_branches_match_expected(actual_branches: List[Tuple[int, Tuple[BranchType, int]]],
                                   expected_branches: List[Tuple[int, Tuple[BranchType, int]]],
                                   script_name: str, arch_name: str) -> None:
    """
    Verify that actual branches match expected branches.

    Args:
        actual_branches: List of actual branches found
        expected_branches: List of expected branches
        script_name: Name of the script being tested
        arch_name: Name of the architecture being tested
    """
    assert len(actual_branches) == len(expected_branches), \
        f"Branch count mismatch for '{script_name}' in {arch_name}: expected {len(expected_branches)}, got {len(actual_branches)}"

    for expected_rel_addr, (expected_type, expected_target) in expected_branches:
        found = False
        for actual_rel_addr, (actual_type, actual_target) in actual_branches:
            if (expected_rel_addr == actual_rel_addr and
                expected_type == actual_type and
                expected_target == actual_target):
                found = True
                break

        assert found, \
            f"Expected branch not found for '{script_name}' in {arch_name}: " \
            f"offset {expected_rel_addr}, type {expected_type}, target 0x{expected_target:X}\n" \
            f"Actual branches: {actual_branches}"


@pytest.mark.parametrize("case", script_test_cases, ids=lambda c: c.test_id)
def test_script_comparison(case: ScriptComparisonTestCase, test_environment: ComparisonTestEnvironment) -> None:
    """Main parametrized test function comparing descumm and SCUMM6 outputs."""

    # 1. Find and extract the script bytecode
    script_info = find_script_by_name(case.script_name, test_environment.scripts)
    bytecode = test_environment.bsc6_data[script_info.start:script_info.end]

    # 2. Execute all disassemblers and LLIL generation
    descumm_output = run_descumm_on_bytecode(test_environment.descumm_path, bytecode)
    disasm_output = run_scumm6_disassembler(bytecode, script_info.start)
    disasm_fusion_output = run_scumm6_disassembler_with_fusion(bytecode, script_info.start)
    
    # Generate LLIL for both regular and fusion modes
    llil_operations = run_scumm6_llil_generation(bytecode, script_info.start, use_fusion=False)
    llil_fusion_operations = run_scumm6_llil_generation(bytecode, script_info.start, use_fusion=True)

    # 3. Check branch information if expected branches are provided
    if case.expected_branches is not None:
        print(f"\n=== Branch Analysis for {case.script_name} ===")

        # Test SCUMM6 architecture
        arch = Scumm6()
        arch_name = "SCUMM6"

        print(f"\n--- Testing {arch_name} ---")

        # Collect actual branches using the generic helper function
        actual_branches = collect_branches_from_architecture(arch, bytecode, script_info.start)

        print(f"Expected branches: {case.expected_branches}")
        print(f"Actual branches ({arch_name}): {actual_branches}")

        # Verify branches match expected using the verification helper
        verify_branches_match_expected(actual_branches, case.expected_branches, case.script_name, arch_name)

        print(f"✅ {arch_name} branch analysis passed")

    # 4. Print outputs for visibility (useful for generating new test cases)
    print(f"\n=== {case.script_name} Comparison ===")
    print("DESCUMM OUTPUT:")
    print(descumm_output)
    print("\nSCUMM6 DISASM OUTPUT:")
    print(disasm_output)
    print("\nSCUMM6 DISASM WITH FUSION OUTPUT:")
    print(disasm_fusion_output)
    
    # Print LLIL operations for visibility
    print(f"\nSCUMM6 LLIL OPERATIONS ({len(llil_operations)} total):")
    for offset, llil_op in llil_operations:
        print(f"  [{offset:04X}] {llil_op}")
    
    print(f"\nSCUMM6 LLIL FUSION OPERATIONS ({len(llil_fusion_operations)} total):")
    for offset, llil_op in llil_fusion_operations:
        print(f"  [{offset:04X}] {llil_op}")

    # 5. Optional assertions based on what's provided
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

    # LLIL validation
    if case.expected_llil is not None:
        assert_llil_operations_match(llil_operations, case.expected_llil, case.script_name, "regular LLIL")

    if case.expected_llil_fusion is not None:
        assert_llil_operations_match(llil_fusion_operations, case.expected_llil_fusion, case.script_name, "fusion LLIL")

    # 6. Always verify that outputs were generated
    assert len(descumm_output.strip()) > 0, f"descumm produced no output for '{case.script_name}'"
    assert len(disasm_output.strip()) > 0, f"SCUMM6 produced no output for '{case.script_name}'"
    assert len(disasm_fusion_output.strip()) > 0, f"SCUMM6 with fusion produced no output for '{case.script_name}'"
    
    # Always verify no unimplemented LLIL operations
    assert_no_unimplemented_llil(llil_operations, case.script_name, "regular LLIL")
    assert_no_unimplemented_llil(llil_fusion_operations, case.script_name, "fusion LLIL")
    
    # Verify LLIL operations were generated
    assert len(llil_operations) > 0, f"No LLIL operations generated for '{case.script_name}'"
    assert len(llil_fusion_operations) > 0, f"No fusion LLIL operations generated for '{case.script_name}'"


# Legacy test functions for backward compatibility
def test_descumm_comparison() -> None:
    """
    Legacy test function - kept for backward compatibility.
    The new parametrized test_script_comparison is the preferred approach.
    """
    # Run the first test case using the legacy approach
    if script_test_cases:
        case = script_test_cases[0]
        print(f"\nRunning legacy compatibility test for {case.test_id}")
        print("Note: Use 'pytest test_descumm_comparison.py::test_script_comparison' for the new framework")

        # Just verify the framework components work
        try:
            descumm_path = build_descumm()
            bsc6_path = ensure_demo_bsc6()
            print(f"✅ descumm built at: {descumm_path}")
            print(f"✅ bsc6 available at: {bsc6_path}")
            print("✅ Legacy compatibility test passed")
        except Exception as e:
            print(f"❌ Legacy compatibility test failed: {e}")
            raise


def test_specific_instruction_differences() -> None:
    """Test specific instruction type differences - legacy function for compatibility."""
    print("\n=== SPECIFIC INSTRUCTION COMPARISON (Legacy) ===")
    print("Note: This is a legacy test function. The new framework focuses on full script comparison.")

    # Simple validation that the architecture can be instantiated
    try:
        arch = Scumm6()
        print("✅ Architecture instantiated successfully")

        # Test a simple instruction
        view = MockScumm6BinaryView()
        bytecode = bytes([0x03, 0x00, 0x40])  # push_word_var(var_0)
        view.write_memory(0x1000, bytecode)
        LastBV.set(view)

        result = arch.get_instruction_text(bytecode, 0x1000)

        if result:
            print("✅ Architecture can disassemble instructions")
        else:
            print("⚠️  Architecture failed to disassemble")

    except Exception as e:
        print(f"❌ Architecture test failed: {e}")
        raise


def test_room11_enter_branch_info(test_environment: ComparisonTestEnvironment) -> None:
    """Test that room11_enter script branch instructions have correct InstructionInfo."""

    # Find and extract the room11_enter script bytecode
    script_info = find_script_by_name("room11_enter", test_environment.scripts)
    bytecode = test_environment.bsc6_data[script_info.start:script_info.end]

    # Create architecture instance
    arch = Scumm6()
    view = MockScumm6BinaryView()
    view.write_memory(script_info.start, bytecode)
    LastBV.set(view)

    # Test the branch instruction at offset 0x05
    # The instruction is: 5D 12 00 (unless goto +18)
    offset = 0x05
    addr = script_info.start + offset
    data = bytecode[offset:]

    # Get instruction info
    info = arch.get_instruction_info(data, addr)

    # Verify the instruction is recognized as a branch
    assert info is not None, "InstructionInfo should not be None for branch instruction"
    assert info.length == 3, f"Branch instruction length should be 3, got {info.length}"

    # The branch at 0x05 is an "unless goto +18" instruction
    # - Instruction address: script_info.start + 0x05
    # - Instruction length: 3
    # - Jump offset: +18 (0x12)
    # - True branch (when condition is true, jump taken): addr + 3 + 18
    # - False branch (when condition is false, fall through): addr + 3

    expected_true_branch = addr + 3 + 18  # Jump to addr + 3 + 18
    expected_false_branch = addr + 3       # Continue to next instruction

    # Check branch count (only TrueBranch, FalseBranch is implicit)
    assert len(info.branches) == 1, f"Expected 1 branch, got {len(info.branches)}"

    # Get the single branch
    branch = info.branches[0]

    # Verify branch target and type
    assert branch.target == expected_true_branch, f"Expected true branch {expected_true_branch:04X}, got {branch.target:04X}"
    
    # Verify branch type (should be TrueBranch only)
    from binaryninja.enums import BranchType
    assert branch.type == BranchType.TrueBranch, f"Expected TrueBranch type, got {branch.type}"

    print("\n✅ room11_enter branch info test passed")
    print(f"   Branch at 0x{offset:04X}: unless goto +18")
    print(f"   - True branch: 0x{expected_true_branch:04X} (jump taken)")
    print(f"   - False branch: 0x{expected_false_branch:04X} (implicit fall-through)")


if __name__ == "__main__":
    # Run the comparison test directly
    test_descumm_comparison()
    print("\n" + "="*80 + "\n")
    test_specific_instruction_differences()
