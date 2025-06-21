#!/usr/bin/env python3
"""
Analyze simple SCUMM6 scripts to identify fusion opportunities.

This script systematically compares descumm output with our decoder implementations
to identify gaps and generate actionable recommendations for improvement.
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from textwrap import dedent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force mock Binary Ninja for testing
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401
from src.pyscumm6.disasm import decode, decode_with_fusion
from src.scumm6_container import Scumm6Container
from kaitaistruct import KaitaiStream


@dataclass
class ScriptAnalysis:
    """Results of analyzing a single script."""
    script_name: str
    bytecode: bytes
    hex_bytecode: str
    descumm_output: str
    legacy_output: str
    new_output: str
    fusion_output: str
    fusion_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    test_case: Optional[str] = None


@dataclass
class FusionPattern:
    """A pattern that could benefit from fusion."""
    pattern_name: str
    description: str
    example_bytecode: bytes
    current_output: str
    ideal_output: str
    implementation_notes: str


class SimpleScriptAnalyzer:
    """Analyze simple SCUMM6 scripts for fusion opportunities."""
    
    def __init__(self, container_path: str = "DOTTDEMO.bsc6"):
        self.container_path = container_path
        self.scripts, self.state, self.bsc6_data = self._load_container()
        self.descumm_path = self._find_or_build_descumm()
        
    def _load_container(self) -> Tuple[List[Any], Any, bytes]:
        """Load the SCUMM6 container file and decode it."""
        from src.disasm import Scumm6Disasm
        
        with open(self.container_path, "rb") as f:
            bsc6_data = f.read()
            
        result = Scumm6Disasm.decode_container(self.container_path, bsc6_data)
        if result is None:
            raise RuntimeError("Failed to decode container")
            
        scripts, state = result
        return scripts, state, bsc6_data
            
    def _find_or_build_descumm(self) -> str:
        """Find or build the descumm tool."""
        from scripts.ensure_descumm import build_descumm
        
        try:
            descumm_path = build_descumm()
            return str(descumm_path)
        except Exception as e:
            raise RuntimeError(f"Could not find or build descumm tool: {e}")
        
    def extract_script_bytecode(self, script_name: str) -> bytes:
        """Extract bytecode for a named script."""
        # Find the script in the scripts list
        for script in self.scripts:
            if script.name == script_name:
                return self.bsc6_data[script.start:script.end]
                
        raise ValueError(f"Script not found: {script_name}")
        
    def run_descumm(self, bytecode: bytes) -> str:
        """Run descumm on bytecode and return output."""
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as f:
            f.write(bytecode)
            temp_path = f.name
            
        try:
            result = subprocess.run(
                [self.descumm_path, "-6", temp_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                # If descumm failed, return the error message
                return f"Error: {result.stderr.strip()}"
            return result.stdout.strip()
        finally:
            os.unlink(temp_path)
            
    def run_new_decoder_simple(self, bytecode: bytes) -> str:
        """Run new decoder without fusion on bytecode."""
        output = []
        pos = 0
        
        try:
            while pos < len(bytecode):
                instr = decode(bytecode, pos)
                if instr is None:
                    break
                    
                tokens = instr.render()
                # Handle both Token objects and raw strings
                parts = []
                for t in tokens:
                    if hasattr(t, 'text'):
                        parts.append(t.text)
                    else:
                        parts.append(str(t))
                text = ''.join(parts)
                output.append(f"[{pos:04X}] {text}")
                pos += instr.length()
        except Exception as e:
            output.append(f"Error: {e}")
            
        return "\n".join(output)
        
    def run_new_decoder(self, bytecode: bytes, with_fusion: bool = False) -> str:
        """Run new decoder on bytecode."""
        output = []
        pos = 0
        
        try:
            while pos < len(bytecode):
                if with_fusion:
                    instr = decode_with_fusion(bytecode, pos)
                else:
                    instr = decode(bytecode, pos)
                    
                tokens = instr.render()
                # Handle both Token objects and raw strings
                parts = []
                for t in tokens:
                    if hasattr(t, 'text'):
                        parts.append(t.text)
                    else:
                        parts.append(str(t))
                text = ''.join(parts)
                output.append(f"[{pos:04X}] {text}")
                pos += instr.length()
        except Exception as e:
            output.append(f"Error: {e}")
            
        return "\n".join(output)
        
    def analyze_script(self, script_name: str) -> ScriptAnalysis:
        """Analyze a single script."""
        # Extract bytecode
        bytecode = self.extract_script_bytecode(script_name)
        hex_bytecode = bytecode.hex()
        
        # Run all decoders
        descumm_output = self.run_descumm(bytecode)
        new_output = self.run_new_decoder(bytecode, with_fusion=False)
        fusion_output = self.run_new_decoder(bytecode, with_fusion=True)
        
        # Create analysis
        analysis = ScriptAnalysis(
            script_name=script_name,
            bytecode=bytecode,
            hex_bytecode=hex_bytecode,
            descumm_output=descumm_output,
            legacy_output="",  # Not used anymore
            new_output=new_output,
            fusion_output=fusion_output
        )
        
        # Identify fusion gaps
        self._identify_fusion_gaps(analysis)
        
        # Generate recommendations
        self._generate_recommendations(analysis)
        
        # Generate test case
        self._generate_test_case(analysis)
        
        return analysis
        
    def _identify_fusion_gaps(self, analysis: ScriptAnalysis) -> None:
        """Identify gaps between descumm and our fusion output."""
        # Skip if descumm failed
        if analysis.descumm_output.startswith("Error:"):
            analysis.fusion_gaps.append("descumm cannot process this script (too small)")
            return
            
        # Compare fusion vs non-fusion output
        if analysis.new_output != analysis.fusion_output:
            analysis.fusion_gaps.append("Fusion changed the output (good - fusion is working)")
            
        # Look for specific patterns
        if "stopObjectCodeA()" in analysis.descumm_output and "stop_object_code" in analysis.fusion_output:
            analysis.fusion_gaps.append("Function name formatting: stopObjectCodeA() vs stop_object_code")
            
        if "END" in analysis.descumm_output and "END" not in analysis.fusion_output:
            analysis.fusion_gaps.append("Missing END marker in output")
            
        # Check for expression building
        if "=" in analysis.descumm_output and "=" not in analysis.fusion_output:
            analysis.fusion_gaps.append("Missing expression building (assignment operators)")
            
        # Check for function call syntax
        if "(" in analysis.descumm_output and "(" not in analysis.fusion_output:
            analysis.fusion_gaps.append("Missing function call syntax with parentheses")
            
        # Check for multi-line output consistency
        descumm_lines = analysis.descumm_output.split('\n')
        fusion_lines = analysis.fusion_output.split('\n')
        
        if len(descumm_lines) != len(fusion_lines):
            analysis.fusion_gaps.append(f"Line count mismatch: descumm {len(descumm_lines)} vs fusion {len(fusion_lines)}")
            
        # Check for semantic understanding
        if "localvar" in analysis.descumm_output and "localvar" not in analysis.fusion_output:
            analysis.fusion_gaps.append("Missing semantic variable names (localvar)")
            
        if "startScript" in analysis.descumm_output and "start_script" in analysis.fusion_output:
            analysis.fusion_gaps.append("Function naming convention: startScript vs start_script")
                
    def _generate_recommendations(self, analysis: ScriptAnalysis) -> None:
        """Generate actionable recommendations based on gaps."""
        for gap in analysis.fusion_gaps:
            if "Function name formatting" in gap:
                analysis.recommendations.append(
                    "Implement descumm-style function name mapping (e.g., stop_object_code → stopObjectCodeA)"
                )
            elif "Missing END marker" in gap:
                analysis.recommendations.append(
                    "Add END marker detection for script termination"
                )
            elif "expression building" in gap:
                analysis.recommendations.append(
                    "Implement assignment operator rendering for variable writes"
                )
            elif "function call syntax" in gap:
                analysis.recommendations.append(
                    "Add parentheses syntax for function calls"
                )
                
    def _generate_test_case(self, analysis: ScriptAnalysis) -> None:
        """Generate a test case for this script."""
        test_case = f'''
def test_{analysis.script_name}_fusion():
    """Test fusion for {analysis.script_name}."""
    bytecode = bytes.fromhex("{analysis.hex_bytecode}")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = {repr(analysis.descumm_output.split('\n'))}
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output
'''
        analysis.test_case = test_case
        
    def analyze_simple_scripts(self) -> List[ScriptAnalysis]:
        """Analyze all simple scripts."""
        # Print available scripts first
        print(f"Available scripts ({len(self.scripts)}):")
        for script in self.scripts[:10]:  # Show first 10
            print(f"  {script.name}: {script.end - script.start} bytes")
        if len(self.scripts) > 10:
            print(f"  ... and {len(self.scripts) - 10} more")
        print()
        
        # Find the smallest scripts first
        small_scripts = sorted(self.scripts, key=lambda s: s.end - s.start)[:10]
        print("Smallest scripts:")
        for script in small_scripts:
            bytecode = self.bsc6_data[script.start:script.end]
            print(f"  {script.name}: {script.end - script.start} bytes, hex: {bytecode.hex()}")
        print()
        
        # Start with small scripts - include both tiny and medium ones
        simple_scripts = [
            "room1_exit",   # 1 byte: 65
            "room1_enter",  # 1 byte: 65
            "room5_exit",   # 1 byte: 65
            "room2_exit",   # 5 bytes: 0105007c65
            "room9_enter",  # 9 bytes: 01000001c8009cae65
            "room7_enter",  # 11 bytes: 01000001c8000100005e65
            "room10_exit",  # 16 bytes: 0107008b5d08000100000190009cae65
            "room2_enter",  # 18 bytes
        ]
        
        results = []
        for script_name in simple_scripts:
            print(f"Analyzing {script_name}...")
            try:
                analysis = self.analyze_script(script_name)
                results.append(analysis)
            except Exception as e:
                print(f"  Error: {e}")
                
        return results
        
    def identify_fusion_patterns(self, analyses: List[ScriptAnalysis]) -> List[FusionPattern]:
        """Identify common patterns that could benefit from fusion."""
        patterns = []
        
        # Pattern 1: Simple function calls
        for analysis in analyses:
            if analysis.bytecode == b'\x65':  # stop_object_code
                patterns.append(FusionPattern(
                    pattern_name="Simple function call formatting",
                    description="Single-byte opcodes should render as function calls",
                    example_bytecode=b'\x65',
                    current_output="stop_object_code",
                    ideal_output="stopObjectCodeA()",
                    implementation_notes=dedent("""
                        1. Add a function name mapping table
                        2. Render with parentheses for consistency
                        3. Match descumm's exact function names
                    """).strip()
                ))
                break
                
        # Pattern 2: Function calls with arguments
        for analysis in analyses:
            if len(analysis.bytecode) > 1 and "startScriptQuick" in analysis.descumm_output:
                patterns.append(FusionPattern(
                    pattern_name="Function calls with arguments",
                    description="Multi-byte sequences should fuse into function calls with args",
                    example_bytecode=analysis.bytecode,
                    current_output=analysis.fusion_output,
                    ideal_output=analysis.descumm_output,
                    implementation_notes=dedent("""
                        1. Identify push operations preceding function calls
                        2. Fuse them into function arguments
                        3. Render as function(arg1, arg2, ...)
                    """).strip()
                ))
                break
                
        return patterns
        
    def generate_report(self, analyses: List[ScriptAnalysis], patterns: List[FusionPattern]) -> str:
        """Generate a comprehensive analysis report."""
        report = ["# Simple Script Analysis Report\n"]
        report.append("## Overview")
        report.append(f"Analyzed {len(analyses)} simple scripts from DOTTDEMO.bsc6\n")
        
        # Summary of gaps
        all_gaps = set()
        for analysis in analyses:
            all_gaps.update(analysis.fusion_gaps)
            
        report.append("## Fusion Gaps Identified")
        for gap in sorted(all_gaps):
            report.append(f"- {gap}")
        report.append("")
        
        # Detailed analysis per script
        report.append("## Detailed Script Analysis")
        for analysis in analyses:
            report.append(f"\n### {analysis.script_name}")
            report.append(f"**Bytecode**: `{analysis.hex_bytecode}`\n")
            
            report.append("**Descumm Output:**")
            report.append("```")
            report.append(analysis.descumm_output)
            report.append("```\n")
            
            report.append("**Current Fusion Output:**")
            report.append("```")
            report.append(analysis.fusion_output)
            report.append("```\n")
            
            if analysis.fusion_gaps:
                report.append("**Gaps:**")
                for gap in analysis.fusion_gaps:
                    report.append(f"- {gap}")
                report.append("")
                
            if analysis.recommendations:
                report.append("**Recommendations:**")
                for rec in analysis.recommendations:
                    report.append(f"- {rec}")
                report.append("")
                
        # Fusion patterns
        report.append("## Fusion Patterns")
        for pattern in patterns:
            report.append(f"\n### {pattern.pattern_name}")
            report.append(f"**Description**: {pattern.description}\n")
            report.append(f"**Example Bytecode**: `{pattern.example_bytecode.hex()}`\n")
            report.append(f"**Current Output**: `{pattern.current_output}`\n")
            report.append(f"**Ideal Output**: `{pattern.ideal_output}`\n")
            report.append("**Implementation Notes:**")
            report.append(pattern.implementation_notes)
            report.append("")
            
        # Test cases
        report.append("## Generated Test Cases")
        report.append("Add these test cases to validate fusion improvements:\n")
        for analysis in analyses:
            if analysis.test_case:
                report.append(f"### Test for {analysis.script_name}")
                report.append("```python")
                report.append(analysis.test_case)
                report.append("```\n")
                
        return "\n".join(report)


def main():
    """Main entry point."""
    analyzer = SimpleScriptAnalyzer()
    
    print("Analyzing simple scripts...")
    analyses = analyzer.analyze_simple_scripts()
    
    print("\nIdentifying fusion patterns...")
    patterns = analyzer.identify_fusion_patterns(analyses)
    
    print("\nGenerating report...")
    report = analyzer.generate_report(analyses, patterns)
    
    # Save report
    report_path = "simple_script_analysis_report.md"
    with open(report_path, "w") as f:
        f.write(report)
        
    print(f"\nAnalysis complete! Report saved to {report_path}")
    
    # Print summary
    print("\nSummary:")
    print(f"- Analyzed {len(analyses)} scripts")
    print(f"- Identified {len(patterns)} fusion patterns")
    
    all_gaps = set()
    for analysis in analyses:
        all_gaps.update(analysis.fusion_gaps)
    print(f"- Found {len(all_gaps)} unique fusion gaps")
    
    print("\nTop recommendations:")
    all_recs = set()
    for analysis in analyses:
        all_recs.update(analysis.recommendations)
    for i, rec in enumerate(sorted(all_recs)[:3], 1):
        print(f"  {i}. {rec}")


if __name__ == "__main__":
    main()