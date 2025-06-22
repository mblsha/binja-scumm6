#!/usr/bin/env python3
"""
SCUMM6 Disassembly Comparison Tool

A command-line tool and TUI application to visualize and analyze semantic differences
between descumm and pyscumm6 disassemblers for Day of the Tentacle demo scripts.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Set mock environment before any Binary Ninja imports
os.environ["FORCE_BINJA_MOCK"] = "1"

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
import difflib
import re
import json

from plumbum import cli

# Import our modules
from src.container import ContainerParser as Scumm6Disasm, ScriptAddr, State
from src.test_utils import run_descumm_on_bytecode, run_scumm6_disassembler, run_scumm6_disassembler_with_fusion


@dataclass
class ScriptComparison:
    """Results of comparing a single script across three disassemblers."""
    name: str
    descumm_output: str
    fused_output: str
    raw_output: str
    is_match: bool
    match_score: float
    unmatched_lines: List[str]


class DataProvider:
    """Handles all data loading and processing."""
    
    def __init__(self, bsc6_path: Optional[Path] = None, descumm_path: Optional[Path] = None):
        self.scripts: List[ScriptAddr] = []
        self.state: Optional[State] = None
        self.bsc6_data: bytes = b""
        self.descumm_path: descumm_path
        self.bsc6_path = bsc6_path
        self.comparisons: Dict[str, ScriptComparison] = {}
        
    def initialize(self) -> None:
        """Load all data and process all scripts."""
        # Find descumm if not provided
        if self.descumm_path is None:
            # Default locations based on test setup
            possible_paths = [
                Path(__file__).parent.parent.parent / "scummvm-tools" / "descumm",
                Path(__file__).parent.parent.parent / "descumm",
                Path.home() / ".local" / "bin" / "descumm",
                Path("/usr/local/bin/descumm"),
                Path("/usr/bin/descumm"),
            ]
            
            for path in possible_paths:
                if path.exists() and path.is_file():
                    self.descumm_path = path
                    break
            
            if self.descumm_path is None:
                raise RuntimeError("descumm not found. Please specify path with --descumm-path")
        
        # Find DOTTDEMO.bsc6 if not provided
        if self.bsc6_path is None:
            # Default locations based on test setup
            possible_paths = [
                Path(__file__).parent.parent.parent / "DOTTDEMO.bsc6",
                Path(__file__).parent.parent.parent / "tests" / "DOTTDEMO.bsc6",
                Path.cwd() / "DOTTDEMO.bsc6",
            ]
            
            for path in possible_paths:
                if path.exists():
                    self.bsc6_path = path
                    break
            
            if self.bsc6_path is None:
                raise RuntimeError("DOTTDEMO.bsc6 not found. Please specify path with --bsc6-path")
        
        # Load the BSC6 file
        self.bsc6_data = self.bsc6_path.read_bytes()
        
        # Parse container
        result = Scumm6Disasm.decode_container(str(self.bsc6_path), self.bsc6_data)
        if result is None:
            raise RuntimeError("Failed to decode container")
        
        self.scripts, self.state = result
    
    def process_script(self, script_name: str) -> ScriptComparison:
        """Process a single script by name."""
        # Find the script
        script = None
        for s in self.scripts:
            if s.name == script_name:
                script = s
                break
        
        if script is None:
            raise ValueError(f"Script '{script_name}' not found")
        
        # Extract bytecode
        bytecode = self.bsc6_data[script.start:script.end]
        
        # Generate all three outputs
        try:
            descumm_output = run_descumm_on_bytecode(self.descumm_path, bytecode)
            fused_output = run_scumm6_disassembler_with_fusion(bytecode, script.start)
            raw_output = run_scumm6_disassembler(bytecode, script.start)
        except Exception as e:
            # Handle errors gracefully
            descumm_output = f"Error: {str(e)}"
            fused_output = f"Error: {str(e)}"
            raw_output = f"Error: {str(e)}"
        
        # Compare descumm with fused output
        is_match, match_score, unmatched_lines = self._compare_outputs(
            descumm_output, fused_output
        )
        
        # Store and return comparison
        comparison = ScriptComparison(
            name=script.name,
            descumm_output=descumm_output,
            fused_output=fused_output,
            raw_output=raw_output,
            is_match=is_match,
            match_score=match_score,
            unmatched_lines=unmatched_lines
        )
        self.comparisons[script.name] = comparison
        return comparison
    
    def process_all_scripts(self) -> None:
        """Process all scripts in the container."""
        for script in self.scripts:
            self.process_script(script.name)
    
    def _normalize_line(self, line: str) -> str:
        """Normalize a line for fuzzy matching."""
        # Strip address prefixes like [0000] or (43)
        line = re.sub(r'^\[[0-9A-Fa-f]+\]\s*', '', line)
        line = re.sub(r'^\([0-9A-Fa-f]+\)\s*', '', line)
        
        # Normalize variable names (localvar5 -> var_5)
        line = re.sub(r'localvar(\d+)', r'var_\1', line)
        
        # Normalize spacing
        line = ' '.join(line.split())
        
        # Strip trailing whitespace
        line = line.strip()
        
        return line
    
    def _compare_outputs(self, descumm: str, fused: str) -> Tuple[bool, float, List[str]]:
        """Compare descumm output with fused output."""
        descumm_lines = [l for l in descumm.strip().split('\n') if l.strip() and l.strip() != 'END']
        fused_lines = [l for l in fused.strip().split('\n') if l.strip()]
        
        # Normalize all lines
        norm_descumm = [self._normalize_line(l) for l in descumm_lines]
        norm_fused = [self._normalize_line(l) for l in fused_lines]
        
        # Track unmatched lines
        unmatched = []
        total_score = 0.0
        matched_count = 0
        
        # For each descumm line, find best match in fused
        for i, d_line in enumerate(norm_descumm):
            if not d_line:  # Skip empty lines
                continue
                
            best_score = 0.0
            best_match = None
            
            for f_line in norm_fused:
                if not f_line:
                    continue
                score = difflib.SequenceMatcher(None, d_line, f_line).ratio()
                if score > best_score:
                    best_score = score
                    best_match = f_line
            
            if best_score >= 0.85:  # High confidence match
                matched_count += 1
                total_score += best_score
            else:
                unmatched.append(descumm_lines[i])
        
        # Calculate overall match
        if len(norm_descumm) > 0:
            match_ratio = matched_count / len(norm_descumm)
            avg_score = total_score / len(norm_descumm) if len(norm_descumm) > 0 else 0
        else:
            match_ratio = 1.0
            avg_score = 1.0
        
        is_match = match_ratio >= 0.9  # 90% of lines must match
        
        return is_match, avg_score, unmatched


class Scumm6CompareApp(cli.Application):
    """Command-line interface for SCUMM6 disassembly comparison."""
    
    VERSION = "1.0.0"
    
    list_scripts = cli.Flag(["l", "list"], help="List all available scripts")
    compare_script = cli.SwitchAttr(
        ["c", "compare"], 
        str, 
        help="Compare a specific script and output JSON result"
    )
    show_diff = cli.Flag(
        ["d", "diff"], 
        help="Show side-by-side diff (use with --compare)",
        requires=["compare_script"]
    )
    bsc6_path = cli.SwitchAttr(
        ["b", "bsc6-path"],
        cli.ExistingFile,
        help="Path to DOTTDEMO.bsc6 file"
    )
    descumm_path = cli.SwitchAttr(
        ["D", "descumm-path"],
        cli.ExistingFile,
        help="Path to descumm executable"
    )
    output_file = cli.SwitchAttr(
        ["o", "output"],
        str,
        help="Save comparison results to file (JSON format)"
    )
    filter_pattern = cli.SwitchAttr(
        ["f", "filter"],
        str,
        help="Filter scripts by name pattern (case-insensitive)"
    )
    
    def main(self):
        """Main entry point."""
        # Initialize data provider with optional paths
        bsc6_path = Path(self.bsc6_path) if self.bsc6_path else None
        descumm_path = Path(self.descumm_path) if self.descumm_path else None
        
        self.data_provider = DataProvider(bsc6_path=bsc6_path, descumm_path=descumm_path)
        
        if not self.list_scripts and not self.compare_script:
            print("Loading DOTTDEMO.bsc6...", file=sys.stderr)
        
        try:
            self.data_provider.initialize()
            if not self.list_scripts and not self.compare_script:
                print(f"Loaded {len(self.data_provider.scripts)} scripts", file=sys.stderr)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        
        if self.list_scripts:
            self._list_scripts()
        elif self.compare_script:
            self._compare_script(self.compare_script)
        else:
            # Default: run TUI
            self._run_tui()
    
    def _list_scripts(self):
        """List all available scripts."""
        scripts = self.data_provider.scripts
        
        # Apply filter if provided
        if self.filter_pattern:
            pattern = self.filter_pattern.lower()
            scripts = [s for s in scripts if pattern in s.name.lower()]
            if not scripts:
                print(f"No scripts matching '{self.filter_pattern}'", file=sys.stderr)
                return
        
        for script in sorted(scripts, key=lambda s: s.name):
            print(f"{script.name:<30} {script.end - script.start:>6} bytes")
    
    def _compare_script(self, script_name: str):
        """Compare a specific script and output results."""
        try:
            comparison = self.data_provider.process_script(script_name)
            
            if self.show_diff:
                # Show side-by-side diff
                self._print_diff(comparison)
            else:
                # Output JSON for unit testing
                result = {
                    "name": comparison.name,
                    "is_match": comparison.is_match,
                    "match_score": comparison.match_score,
                    "unmatched_lines": comparison.unmatched_lines,
                    "descumm_output": comparison.descumm_output,
                    "fused_output": comparison.fused_output,
                    "raw_output": comparison.raw_output
                }
                
                # Save to file if requested
                if self.output_file:
                    with open(self.output_file, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Results saved to {self.output_file}", file=sys.stderr)
                else:
                    print(json.dumps(result, indent=2))
        
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    def _print_diff(self, comparison: ScriptComparison):
        """Print a side-by-side diff of the outputs."""
        print(f"\n=== Script: {comparison.name} ===")
        print(f"Match Score: {comparison.match_score:.1%}")
        print(f"Status: {'MATCH' if comparison.is_match else 'MISMATCH'}")
        
        # Split lines
        descumm_lines = comparison.descumm_output.strip().split('\n')
        fused_lines = comparison.fused_output.strip().split('\n')
        
        # Calculate column width
        max_width = 50
        
        print(f"\n{'descumm':<{max_width}} | {'pyscumm6 (fused)'}")
        print("-" * (max_width + 3 + max_width))
        
        # Pad to same length
        max_lines = max(len(descumm_lines), len(fused_lines))
        descumm_lines += [''] * (max_lines - len(descumm_lines))
        fused_lines += [''] * (max_lines - len(fused_lines))
        
        # Print side by side
        for d_line, f_line in zip(descumm_lines, fused_lines):
            d_line = d_line[:max_width].ljust(max_width)
            print(f"{d_line} | {f_line}")
        
        if comparison.unmatched_lines:
            print(f"\nUnmatched lines from descumm:")
            for line in comparison.unmatched_lines:
                print(f"  {line}")
    
    def _run_tui(self):
        """Run the interactive TUI application."""
        # Import here to avoid dependency if not using TUI
        try:
            from .tui_app import Scumm6ComparisonApp
        except ImportError:
            # Try absolute import if relative doesn't work
            from tui_app import Scumm6ComparisonApp
        
        print("Starting TUI application...", file=sys.stderr)
        app = Scumm6ComparisonApp(self.data_provider)
        app.run()


if __name__ == "__main__":
    Scumm6CompareApp.run()