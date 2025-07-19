"""Centralized test utilities for SCUMM6 plugin testing.

This module consolidates common test helper functions to reduce duplication
across test files and provide consistent testing infrastructure.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, Any, Tuple, Dict, Optional, Union, Callable
from dataclasses import dataclass
import subprocess
import tempfile
from pathlib import Path

from binja_test_mocks import binja_api  # noqa: F401
from binja_test_mocks.mock_llil import MockLowLevelILFunction, MockLLIL
from binaryninja.enums import BranchType

from .scumm6 import Scumm6, LastBV
from .test_mocks import MockScumm6BinaryView
from .pyscumm6.disasm import decode_with_fusion
from .pyscumm6.instr.opcodes import Instruction


def assert_fusion_result(
    bytecode: bytes, 
    expected_class: str, 
    expected_fused_count: int, 
    expected_text: str,
    addr: int = 0x1000
) -> None:
    """Test fusion logic with standardized assertions.
    
    Args:
        bytecode: The bytecode to decode with fusion
        expected_class: Expected instruction class name
        expected_fused_count: Expected number of fused operands
        expected_text: Expected rendered text output
        addr: Starting address for decoding (default: 0x1000)
    """
    instruction = decode_with_fusion(bytecode, addr)
    assert instruction is not None, "Fusion decoding should not return None"
    
    assert instruction.__class__.__name__ == expected_class, \
        f"Expected instruction class {expected_class}, got {instruction.__class__.__name__}"
    
    assert len(instruction.fused_operands) == expected_fused_count, \
        f"Expected {expected_fused_count} fused operands, got {len(instruction.fused_operands)}"
    
    # Check render output
    tokens = instruction.render()
    actual_text = safe_token_text(tokens)
    assert actual_text == expected_text, \
        f"Expected text '{expected_text}', got '{actual_text}'"


def assert_no_fusion(bytecode: bytes, expected_class: str, addr: int = 0x1000) -> None:
    """Test that instruction does NOT undergo fusion.
    
    Args:
        bytecode: The bytecode to decode with fusion
        expected_class: Expected instruction class name  
        addr: Starting address for decoding (default: 0x1000)
    """
    instruction = decode_with_fusion(bytecode, addr)
    assert instruction is not None, "Decoding should not return None"
    
    assert instruction.__class__.__name__ == expected_class, \
        f"Expected instruction class {expected_class}, got {instruction.__class__.__name__}"
    
    assert len(instruction.fused_operands) == 0, \
        f"Expected no fusion, but got {len(instruction.fused_operands)} fused operands"


def assert_partial_fusion(
    bytecode: bytes,
    expected_class: str, 
    expected_fused_count: int,
    expected_stack_pops: int,
    addr: int = 0x1000
) -> None:
    """Test partial fusion where some operands are fused but stack pops remain.
    
    Args:
        bytecode: The bytecode to decode with fusion
        expected_class: Expected instruction class name
        expected_fused_count: Expected number of fused operands
        expected_stack_pops: Expected remaining stack pop count
        addr: Starting address for decoding (default: 0x1000)
    """
    instruction = decode_with_fusion(bytecode, addr)
    assert instruction is not None, "Partial fusion decoding should not return None"
    
    assert instruction.__class__.__name__ == expected_class, \
        f"Expected instruction class {expected_class}, got {instruction.__class__.__name__}"
    
    assert len(instruction.fused_operands) == expected_fused_count, \
        f"Expected {expected_fused_count} fused operands, got {len(instruction.fused_operands)}"
    
    assert instruction.stack_pop_count == expected_stack_pops, \
        f"Expected {expected_stack_pops} stack pops, got {instruction.stack_pop_count}"


def safe_token_text(tokens: List[Any]) -> str:
    """Extract text from token list safely handling different token types.
    
    Args:
        tokens: List of token objects with potentially different text access patterns
        
    Returns:
        Concatenated text from all tokens
    """
    return ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)


@dataclass
class FusionTestCase:
    """Data describing an instruction fusion test case."""

    test_id: str
    bytecode: bytes
    expected_class: str
    expected_fused_operands: int
    expected_stack_pops: int
    expected_render_text: Optional[str] = None
    expected_length: Optional[int] = None
    additional_validation: Optional[Callable[[Any], None]] = None
    addr: int = 0x1000


def run_fusion_test(case: FusionTestCase, *, expect_in_text: bool = False) -> None:
    """Decode bytecode with fusion and verify the resulting instruction."""

    instr = decode_with_fusion(case.bytecode, case.addr)
    assert instr is not None, f"Failed to decode {case.test_id}"

    assert instr.__class__.__name__ == case.expected_class
    assert len(instr.fused_operands) == case.expected_fused_operands
    assert instr.stack_pop_count == case.expected_stack_pops

    if case.expected_length is not None:
        assert instr.length() == case.expected_length

    token_text = safe_token_text(instr.render())
    if case.expected_render_text is not None:
        if expect_in_text:
            assert case.expected_render_text in token_text
        else:
            assert token_text == case.expected_render_text

    if case.additional_validation:
        case.additional_validation(instr)


def _clean_literal_mode_jumps(output: str) -> str:
    """
    Clean up descumm literal mode output by removing C-style comment wrappers from jump statements.
    
    Transforms:
        [00E4] (73) /* jump e8; */
    Into:
        [00E4] (73) jump e8
    
    Args:
        output: Raw descumm output
        
    Returns:
        Cleaned output with comment wrappers removed from jumps
    """
    import re
    
    # Pattern to match C-style comment wrappers around jump statements
    # Matches: /* jump xxx; */ or /* jump xxx */
    jump_comment_pattern = r'/\*\s*(jump\s+[a-fA-F0-9]+)\s*;?\s*\*/'
    
    # Replace comment-wrapped jumps with clean jump statements
    cleaned_output = re.sub(jump_comment_pattern, r'\1', output)
    
    return cleaned_output


def run_descumm_on_bytecode(descumm_path: Path, bytecode: bytes, literal_mode: bool = True) -> str:
    """Execute descumm on bytecode and return cleaned output.
    
    Args:
        descumm_path: Path to the descumm executable
        bytecode: SCUMM6 bytecode to disassemble
        literal_mode: Whether to use literal mode (-l flag) to disable prettification.
                     Default is True for easier comparison with pyscumm6 output.
        
    Returns:
        Cleaned descumm output as string
    """
    # Add SCRP header to bytecode for proper parsing
    header = b'SCRP'
    size = len(bytecode).to_bytes(4, byteorder='big')
    full_data = header + size + bytecode
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_file:
        tmp_file.write(full_data)
        tmp_file_path = tmp_file.name

    try:
        # Build command line with or without literal mode flag
        cmd = [str(descumm_path), "-6"]
        if literal_mode:
            cmd.append("-l")
        cmd.append(tmp_file_path)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        # Return stdout even if descumm had errors
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            # Include stderr information if there was an error
            output = f"{output}\n<!-- descumm stderr: {result.stderr.strip()} -->"
        
        # Post-process literal mode output to remove C-style comment wrappers from jumps
        if literal_mode:
            output = _clean_literal_mode_jumps(output)
        
        return output
    finally:
        os.unlink(tmp_file_path)


def run_scumm6_disassembler(bytecode: bytes, start_addr: int) -> str:
    """Execute SCUMM6 disassembler and return formatted output.
    
    Args:
        bytecode: SCUMM6 bytecode to disassemble
        start_addr: Starting address for disassembly
        
    Returns:
        Formatted disassembly output as string
    """
    arch = Scumm6()
    # Disable fusion for regular disassembly to match test expectations
    arch.enable_fusion_in_disassembly = False
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
        text = safe_token_text(tokens)

        # Format as [offset] disassembly_text
        output_lines.append(f"[{offset:04X}] {text}")
        offset += length

    return '\n'.join(output_lines)


def _run_fusion_disassembly(
    bytecode: bytes,
    start_addr: int,
    *,
    enable_loop_detection: bool = False,
    with_details: bool = False,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Internal helper for fusion-based disassembly."""

    from .pyscumm6.disasm import decode_with_fusion_incremental, decode

    output_lines: List[str] = []
    fusion_spans: List[Dict[str, Any]] = []
    offset = 0

    while offset < len(bytecode):
        addr = start_addr + offset
        remaining_data = bytecode[offset:]

        instruction = decode_with_fusion_incremental(remaining_data, addr, enable_loop_detection)
        if instruction is None:
            break

        tokens = instruction.render()
        text = safe_token_text(tokens)
        output_lines.append(f"[{offset:04X}] {text}")

        if with_details and instruction.fused_operands:
            raw_offsets = []
            temp_offset = 0
            while temp_offset < instruction.length():
                raw_data = bytecode[offset + temp_offset:]
                raw_instr = decode(raw_data, addr + temp_offset)
                if raw_instr:
                    raw_offsets.append(offset + temp_offset)
                    temp_offset += raw_instr.length()
                else:
                    break

            fusion_spans.append(
                {
                    "start_offset": offset,
                    "end_offset": offset + instruction.length(),
                    "fused_count": len(instruction.fused_operands),
                    "raw_instruction_offsets": raw_offsets,
                }
            )

        offset += instruction.length()

    return "\n".join(output_lines), fusion_spans


def run_scumm6_disassembler_with_fusion(
    bytecode: bytes,
    start_addr: int,
    enable_loop_detection: bool = False,
) -> str:
    """Execute SCUMM6 disassembler with instruction fusion and return formatted output."""

    text, _ = _run_fusion_disassembly(
        bytecode,
        start_addr,
        enable_loop_detection=enable_loop_detection,
        with_details=False,
    )
    return text


def run_scumm6_disassembler_with_fusion_details(
    bytecode: bytes,
    start_addr: int,
    enable_loop_detection: bool = False,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Execute fusion disassembler and also return fusion span information."""

    return _run_fusion_disassembly(
        bytecode,
        start_addr,
        enable_loop_detection=enable_loop_detection,
        with_details=True,
    )


def run_scumm6_llil_generation(bytecode: bytes, start_addr: int, use_fusion: bool = False) -> List[Tuple[int, MockLLIL]]:
    """Execute SCUMM6 LLIL generation and return list of (offset, llil_operation) tuples.
    
    Args:
        bytecode: SCUMM6 bytecode to analyze
        start_addr: Starting address for analysis
        use_fusion: Whether to use fusion-enabled decoding
        
    Returns:
        List of (offset, llil_operation) tuples
    """
    if use_fusion:
        from .pyscumm6.disasm import decode_with_fusion_incremental
        def decode_func(data: bytes, addr: int) -> Optional[Instruction]:
            return decode_with_fusion_incremental(data, addr, enable_loop_detection=False)
    else:
        from .pyscumm6.disasm import decode
        decode_func = decode
    
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


def assert_llil_operations_match(
    actual_llil: List[Tuple[int, MockLLIL]], 
    expected_llil: List[Tuple[int, MockLLIL]], 
    script_name: str, 
    test_type: str
) -> None:
    """Verify that actual LLIL operations match expected operations.
    
    Args:
        actual_llil: Generated LLIL operations
        expected_llil: Expected LLIL operations
        script_name: Name of script being tested (for error messages)
        test_type: Type of test being performed (for error messages)
    """
    
    # Filter out control flow operations which can vary between runs due to dynamic labels
    def filter_control_flow(llil_ops: List[Tuple[int, MockLLIL]]) -> List[Tuple[int, MockLLIL]]:
        """Filter out IF and LABEL operations which contain dynamic labels."""
        return [(addr, op) for addr, op in llil_ops 
                if op.__class__.__name__ not in ['MockIfExpr', 'MockLabel']]
    
    actual_filtered = filter_control_flow(actual_llil)
    expected_filtered = filter_control_flow(expected_llil)
    
    assert len(actual_filtered) == len(expected_filtered), \
        f"LLIL operation count mismatch for '{script_name}' ({test_type}): " \
        f"expected {len(expected_filtered)}, got {len(actual_filtered)} (after filtering control flow)"

    for i, ((actual_offset, actual_op), (expected_offset, expected_op)) in enumerate(zip(actual_filtered, expected_filtered)):
        assert actual_offset == expected_offset, \
            f"LLIL operation {i} offset mismatch for '{script_name}' ({test_type}): " \
            f"expected offset 0x{expected_offset:04X}, got 0x{actual_offset:04X}"
        
        # Compare operation types and key properties directly
        assert actual_op.op == expected_op.op, \
            f"LLIL operation {i} type mismatch for '{script_name}' ({test_type}) at offset 0x{actual_offset:04X}:\n" \
            f"Expected: {expected_op.op}\n" \
            f"Actual: {actual_op.op}"
            
        # For intrinsics, also check the function name
        if hasattr(actual_op, 'name') and hasattr(expected_op, 'name'):
            assert actual_op.name == expected_op.name, \
                f"LLIL intrinsic name mismatch for '{script_name}' ({test_type}) at offset 0x{actual_offset:04X}:\n" \
                f"Expected: {expected_op.name}\n" \
                f"Actual: {actual_op.name}"


def assert_llil_operations_partial_match(
    actual_llil: List[Tuple[int, MockLLIL]], 
    expected_llil: List[Tuple[int, MockLLIL]], 
    script_name: str, 
    test_type: str
) -> None:
    """Verify that specific LLIL operations match expectations (partial matching).
    
    This function only validates the specific operations listed in expected_llil,
    rather than requiring a complete match of all operations. This is useful for
    testing specific features like actor operations without needing to specify
    the entire script's LLIL.
    
    Args:
        actual_llil: Generated LLIL operations
        expected_llil: Expected LLIL operations (subset to validate)
        script_name: Name of script being tested (for error messages)
        test_type: Type of test being performed (for error messages)
    """
    
    # Create a lookup dictionary for actual operations by offset
    actual_by_offset = {offset: op for offset, op in actual_llil}
    
    # Validate each expected operation
    for expected_offset, expected_op in expected_llil:
        assert expected_offset in actual_by_offset, \
            f"Expected LLIL operation at offset 0x{expected_offset:04X} not found in '{script_name}' ({test_type})"
        
        actual_op = actual_by_offset[expected_offset]
        
        # Compare operation types and key properties directly
        assert actual_op.op == expected_op.op, \
            f"LLIL operation type mismatch for '{script_name}' ({test_type}) at offset 0x{expected_offset:04X}:\\n" \
            f"Expected: {expected_op.op}\\n" \
            f"Actual: {actual_op.op}"
            
        # For intrinsics, also check the function name
        if hasattr(actual_op, 'name') and hasattr(expected_op, 'name'):
            assert actual_op.name == expected_op.name, \
                f"LLIL intrinsic name mismatch for '{script_name}' ({test_type}) at offset 0x{expected_offset:04X}:\\n" \
                f"Expected: {expected_op.name}\\n" \
                f"Actual: {actual_op.name}"
        
        # Compare operands recursively
        assert len(actual_op.ops) == len(expected_op.ops), \
            f"LLIL operand count mismatch for '{script_name}' ({test_type}) at offset 0x{expected_offset:04X}:\\n" \
            f"Expected {len(expected_op.ops)} operands, got {len(actual_op.ops)}"
        
        # Recursively compare each operand
        for i, (actual_operand, expected_operand) in enumerate(zip(actual_op.ops, expected_op.ops)):
            _compare_llil_operands_recursive(actual_operand, expected_operand, script_name, test_type, expected_offset, i)


def _compare_llil_operands_recursive(actual: Any, expected: Any, script_name: str, test_type: str, offset: int, operand_idx: Union[int, str]) -> None:
    """Recursively compare LLIL operands."""
    if isinstance(expected, MockLLIL):
        assert isinstance(actual, MockLLIL), \
            f"Expected MockLLIL operand {operand_idx} at offset 0x{offset:04X} in '{script_name}' ({test_type}), got {type(actual)}"
        
        assert actual.op == expected.op, \
            f"LLIL operand {operand_idx} type mismatch at offset 0x{offset:04X} in '{script_name}' ({test_type}):\\n" \
            f"Expected: {expected.op}\\n" \
            f"Actual: {actual.op}"
        
        assert len(actual.ops) == len(expected.ops), \
            f"LLIL operand {operand_idx} sub-operand count mismatch at offset 0x{offset:04X} in '{script_name}' ({test_type}):\\n" \
            f"Expected {len(expected.ops)}, got {len(actual.ops)}"
        
        for j, (actual_sub, expected_sub) in enumerate(zip(actual.ops, expected.ops)):
            _compare_llil_operands_recursive(actual_sub, expected_sub, script_name, test_type, offset, f"{operand_idx}.{j}")
    else:
        # Simple value comparison
        assert actual == expected, \
            f"LLIL operand {operand_idx} value mismatch at offset 0x{offset:04X} in '{script_name}' ({test_type}):\\n" \
            f"Expected: {expected}\\n" \
            f"Actual: {actual}"


def assert_no_unimplemented_llil(llil_operations: List[Tuple[int, MockLLIL]], script_name: str, test_type: str) -> None:
    """Verify that no LLIL operations are unimplemented.
    
    Args:
        llil_operations: Generated LLIL operations to check
        script_name: Name of script being tested (for error messages)
        test_type: Type of test being performed (for error messages)
    """
    for offset, llil_op in llil_operations:
        _check_no_unimplemented_recursive(llil_op, script_name, test_type, offset)


def _check_no_unimplemented_recursive(llil_op: MockLLIL, script_name: str, test_type: str, offset: int) -> None:
    """Recursively check that no LLIL operations are unimplemented.
    
    Args:
        llil_op: LLIL operation to check
        script_name: Name of script being tested (for error messages)
        test_type: Type of test being performed (for error messages)
        offset: Bytecode offset of the operation (for error messages)
    """
    if llil_op.bare_op() == "UNIMPL":
        raise AssertionError(f"Found unimplemented LLIL in '{script_name}' ({test_type}) at offset 0x{offset:04X}: {llil_op}")
    
    # Recursively check nested operations
    for nested_op in llil_op.ops:
        if isinstance(nested_op, MockLLIL):
            _check_no_unimplemented_recursive(nested_op, script_name, test_type, offset)


def collect_branches_from_architecture(arch: Any, bytecode: bytes, start_addr: int) -> List[Tuple[int, Tuple[BranchType, Optional[int]]]]:
    """Generic function to collect branch information from any SCUMM6 architecture.

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
            # FunctionReturn branches have None as target
            if absolute_target is None:
                relative_target = None
            else:
                relative_target = absolute_target - start_addr
            branches.append((offset, (branch_type, relative_target)))

        offset += info.length

    return branches


def setup_mock_scumm6_environment() -> Tuple[Scumm6, MockScumm6BinaryView]:
    """Set up a standardized SCUMM6 test environment.
    
    Returns:
        Tuple of (architecture, mock_view) for testing
    """
    arch = Scumm6()
    view = MockScumm6BinaryView()
    LastBV.set(view)
    return arch, view
