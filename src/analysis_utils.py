"""Shared analysis utilities for SCUMM6 script analysis.

This module provides common functionality for analyzing DOTTDEMO.bsc6 scripts,
eliminating duplication between analysis scripts and test comparison utilities.
"""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, Optional, NamedTuple, Tuple, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from binja_test_mocks import binja_api  # noqa: F401

# Import container parsing functionality
from .container import ContainerParser as Scumm6Disasm, ScriptAddr, State
from .pyscumm6.disasm import decode, decode_with_fusion_incremental

# Import test utilities for disassembly functions
from .test_utils import run_descumm_on_bytecode, run_scumm6_disassembler, run_scumm6_disassembler_with_fusion


class Scumm6AnalysisEnvironment(NamedTuple):
    """Container for analysis environment artifacts."""
    descumm_path: Path
    bsc6_data: bytes
    scripts: List[ScriptAddr]
    state: State


@dataclass
class ScriptAnalysisResult:
    """Result of analyzing a single script."""
    script_info: ScriptAddr
    bytecode: bytes
    descumm_output: str
    legacy_output: str
    fusion_output: str
    hex_bytecode: str


def _count_non_empty_lines(text: str) -> int:
    """Return the number of non-empty lines in ``text``."""

    return sum(1 for line in text.splitlines() if line.strip())


class Scumm6AnalysisToolkit:
    """Shared toolkit for SCUMM6 script analysis tasks."""
    
    def __init__(self, bsc6_path: Optional[Path] = None, descumm_path: Optional[Path] = None):
        """Initialize the analysis toolkit.
        
        Args:
            bsc6_path: Path to DOTTDEMO.bsc6 file (auto-detected if None)
            descumm_path: Path to descumm executable (auto-built if None)
        """
        self.environment = self._setup_environment(bsc6_path, descumm_path)
        # Cache script lookups to avoid repeated linear searches when analyzing many scripts
        self._scripts_by_name: Dict[str, ScriptAddr] = {
            script.name: script for script in self.environment.scripts
        }
    
    def _setup_environment(self, bsc6_path: Optional[Path], descumm_path: Optional[Path]) -> Scumm6AnalysisEnvironment:
        """Set up the analysis environment with all required tools and data."""
        
        # Ensure demo BSC6 file is available
        if bsc6_path is None:
            from .test_descumm_tool import ensure_demo_bsc6
            bsc6_path = ensure_demo_bsc6()
        
        # Load container data
        with open(bsc6_path, "rb") as f:
            bsc6_data = f.read()
        
        # Parse container to get script list
        scripts, state = Scumm6Disasm.decode_container(bsc6_data)
        
        # Ensure descumm tool is available
        if descumm_path is None:
            from scripts.ensure_descumm import build_descumm
            descumm_path = build_descumm()
        
        return Scumm6AnalysisEnvironment(descumm_path, bsc6_data, scripts, state)
    
    def get_script_by_name(self, script_name: str) -> ScriptAddr:
        """Find a script by name in the loaded scripts.
        
        Args:
            script_name: Name of the script (e.g., "room8_scrp18")
            
        Returns:
            ScriptAddr object for the requested script
            
        Raises:
            ValueError: If script is not found
        """
        try:
            return self._scripts_by_name[script_name]
        except KeyError as exc:
            raise ValueError(
                f"Script '{script_name}' not found. Available scripts: {[s.name for s in self.environment.scripts]}"
            ) from exc
    
    def get_all_scripts(self) -> List[ScriptAddr]:
        """Get list of all available scripts."""
        return self.environment.scripts
    
    def extract_script_bytecode(self, script: ScriptAddr) -> bytes:
        """Extract bytecode for a specific script.
        
        Args:
            script: ScriptAddr object identifying the script
            
        Returns:
            Raw bytecode for the script
        """
        return self.environment.bsc6_data[script.start:script.end]
    
    def analyze_script(self, script_name: str) -> ScriptAnalysisResult:
        """Perform comprehensive analysis of a single script.
        
        Args:
            script_name: Name of the script to analyze
            
        Returns:
            ScriptAnalysisResult with all analysis outputs
        """
        script_info = self.get_script_by_name(script_name)
        bytecode = self.extract_script_bytecode(script_info)
        
        # Generate all disassembly outputs
        descumm_output = run_descumm_on_bytecode(self.environment.descumm_path, bytecode)
        legacy_output = run_scumm6_disassembler(bytecode, script_info.start)
        fusion_output = run_scumm6_disassembler_with_fusion(bytecode, script_info.start)
        
        # Generate hex representation
        hex_bytecode = ' '.join(f'{b:02X}' for b in bytecode)
        
        return ScriptAnalysisResult(
            script_info=script_info,
            bytecode=bytecode,
            descumm_output=descumm_output,
            legacy_output=legacy_output,
            fusion_output=fusion_output,
            hex_bytecode=hex_bytecode
        )
    
    def analyze_multiple_scripts(self, script_names: List[str]) -> List[ScriptAnalysisResult]:
        """Analyze multiple scripts efficiently.
        
        Args:
            script_names: List of script names to analyze
            
        Returns:
            List of ScriptAnalysisResult objects
        """
        return [self.analyze_script(name) for name in script_names]
    
    def filter_scripts_by_size(self, min_bytes: int = 0, max_bytes: int = 999999) -> List[ScriptAddr]:
        """Filter scripts by bytecode size.
        
        Args:
            min_bytes: Minimum script size in bytes
            max_bytes: Maximum script size in bytes
            
        Returns:
            List of scripts within the size range
        """
        filtered = []
        for script in self.environment.scripts:
            size = script.end - script.start
            if min_bytes <= size <= max_bytes:
                filtered.append(script)
        return filtered
    
    def get_simple_scripts(self, max_bytes: int = 50) -> List[ScriptAddr]:
        """Get simple scripts suitable for fusion analysis.
        
        Args:
            max_bytes: Maximum size for "simple" scripts
            
        Returns:
            List of simple scripts sorted by size
        """
        simple_scripts = self.filter_scripts_by_size(max_bytes=max_bytes)
        return sorted(simple_scripts, key=lambda s: s.end - s.start)
    
    def get_complex_scripts(self, min_bytes: int = 100) -> List[ScriptAddr]:
        """Get complex scripts for comprehensive analysis.
        
        Args:
            min_bytes: Minimum size for "complex" scripts
            
        Returns:
            List of complex scripts sorted by size (largest first)
        """
        complex_scripts = self.filter_scripts_by_size(min_bytes=min_bytes)
        return sorted(complex_scripts, key=lambda s: s.end - s.start, reverse=True)
    
    def decode_script_instructions(self, script_name: str, use_fusion: bool = False) -> List[Tuple[int, Any]]:
        """Decode a script into individual instructions.
        
        Args:
            script_name: Name of the script to decode
            use_fusion: Whether to use fusion-enabled decoding
            
        Returns:
            List of (offset, instruction) tuples
        """
        script_info = self.get_script_by_name(script_name)
        bytecode = self.extract_script_bytecode(script_info)
        
        decode_func = decode_with_fusion_incremental if use_fusion else decode
        
        instructions = []
        offset = 0
        
        while offset < len(bytecode):
            addr = script_info.start + offset
            remaining_data = bytecode[offset:]
            
            instruction = decode_func(remaining_data, addr)
            if instruction is None:
                break
                
            instructions.append((offset, instruction))
            offset += instruction.length()
        
        return instructions
    
    def compare_outputs(self, script_name: str) -> Dict[str, Any]:
        """Compare outputs between all three disassemblers for a script.
        
        Args:
            script_name: Name of the script to compare
            
        Returns:
            Dictionary with comparison results and metrics
        """
        result = self.analyze_script(script_name)
        
        # Count lines in each output
        descumm_lines = _count_non_empty_lines(result.descumm_output)
        legacy_lines = _count_non_empty_lines(result.legacy_output)
        fusion_lines = _count_non_empty_lines(result.fusion_output)
        
        return {
            'script_name': script_name,
            'bytecode_size': len(result.bytecode),
            'descumm_lines': descumm_lines,
            'legacy_lines': legacy_lines,
            'fusion_lines': fusion_lines,
            'fusion_compression_ratio': legacy_lines / fusion_lines if fusion_lines > 0 else 0,
            'outputs': {
                'descumm': result.descumm_output,
                'legacy': result.legacy_output,
                'fusion': result.fusion_output
            }
        }
    
    def generate_test_case(self, script_name: str, include_expected_outputs: bool = True) -> str:
        """Generate a test case for the descumm comparison framework.
        
        Args:
            script_name: Name of the script to generate test case for
            include_expected_outputs: Whether to include expected output strings
            
        Returns:
            Python code for a test case
        """
        result = self.analyze_script(script_name)
        
        test_case = f'''ScriptComparisonTestCase(
    test_id="{script_name}",
    script_name="{script_name}",'''
        
        if include_expected_outputs:
            test_case += f'''
    expected_descumm_output=dedent("""
{result.descumm_output}
    """).strip(),
    expected_disasm_output=dedent("""
{result.legacy_output}
    """).strip(),
    expected_disasm_fusion_output=dedent("""
{result.fusion_output}
    """).strip(),'''
        
        test_case += '\n),'
        
        return test_case


def create_analysis_toolkit(bsc6_path: Optional[Path] = None, descumm_path: Optional[Path] = None) -> Scumm6AnalysisToolkit:
    """Factory function to create a Scumm6AnalysisToolkit instance.
    
    Args:
        bsc6_path: Path to DOTTDEMO.bsc6 file (auto-detected if None)
        descumm_path: Path to descumm executable (auto-built if None)
        
    Returns:
        Configured Scumm6AnalysisToolkit instance
    """
    return Scumm6AnalysisToolkit(bsc6_path, descumm_path)
