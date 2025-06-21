#!/usr/bin/env python3
"""
DOTTDEMO.bsc6 Script Inventory and Analysis System

This script extracts all available scripts from DOTTDEMO.bsc6 and provides
comprehensive analysis for systematic comparison with descumm output.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict

# Add parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force mock Binary Ninja for standalone execution
os.environ["FORCE_BINJA_MOCK"] = "1"

from src.disasm import Scumm6Disasm, ScriptAddr, State
from src.scumm6_container import Scumm6Container
from kaitaistruct import KaitaiStream, BytesIO
from src.pyscumm6.disasm import decode, decode_with_fusion_incremental
from src.pyscumm6.instr.opcodes import Instruction


@dataclass
class OpcodeStats:
    """Statistics about opcodes in a script."""
    total_count: int = 0
    unique_opcodes: Set[str] = field(default_factory=set)
    opcode_histogram: Dict[str, int] = field(default_factory=dict)
    push_instructions: int = 0
    control_flow_instructions: int = 0
    variable_operations: int = 0
    function_calls: int = 0


@dataclass
class ScriptMetrics:
    """Comprehensive metrics for a script."""
    name: str
    size_bytes: int
    instruction_count: int
    opcode_stats: OpcodeStats
    has_branches: bool
    has_loops: bool
    has_function_calls: bool
    max_stack_depth: int
    complexity_score: int
    fusion_opportunities: int
    semantic_patterns: List[str] = field(default_factory=list)
    

@dataclass
class ScriptAnalysis:
    """Complete analysis of a script including raw data and metrics."""
    script_name: str
    bytecode: bytes
    metrics: ScriptMetrics
    descumm_output: Optional[str] = None
    legacy_output: Optional[str] = None
    new_output: Optional[str] = None
    fusion_output: Optional[str] = None
    

class DottdemoAnalyzer:
    """Analyzes all scripts in DOTTDEMO.bsc6 for systematic improvement."""
    
    def __init__(self, bsc6_path: str):
        self.bsc6_path = Path(bsc6_path)
        self.bsc6_data = self.bsc6_path.read_bytes()
        self.scripts: Dict[str, ScriptAnalysis] = {}
        self.descumm_path = self._find_descumm()
        self.script_list: List[ScriptAddr] = []
        self.state: Optional[State] = None
        self._parse_container()
        
    def _find_descumm(self) -> Optional[Path]:
        """Find descumm executable."""
        possible_paths = [
            Path("scummvm-tools/descumm"),
            Path("../scummvm-tools/descumm"),
            Path("../../scummvm-tools/descumm"),
        ]
        for path in possible_paths:
            if path.exists() and path.is_file():
                return path
        return None
        
    def _parse_container(self) -> None:
        """Parse the BSC6 container and extract script information."""
        result = Scumm6Disasm.decode_container(str(self.bsc6_path), self.bsc6_data)
        if result:
            self.script_list, self.state = result
        else:
            raise ValueError(f"Failed to parse {self.bsc6_path}")
            
    def extract_all_scripts(self) -> None:
        """Extract all scripts from the BSC6 file."""
        print(f"Extracting scripts from {self.bsc6_path}...")
        print(f"Found {len(self.script_list)} scripts")
        
        # Analyze each script
        for script_info in self.script_list:
            self._analyze_script(script_info)
            
    def _analyze_script(self, script_info: ScriptAddr) -> None:
        """Analyze a single script."""
        try:
            script_name = script_info.name
            bytecode = self.bsc6_data[script_info.start:script_info.end]
            
            if not bytecode:
                return
                
            metrics = self._calculate_metrics(script_name, bytecode)
            analysis = ScriptAnalysis(
                script_name=script_name,
                bytecode=bytecode,
                metrics=metrics
            )
            
            # Get descumm output if available
            if self.descumm_path:
                analysis.descumm_output = self._get_descumm_output(bytecode)
                
            # Get plugin outputs
            analysis.legacy_output = self._get_legacy_output(bytecode)
            analysis.new_output = self._get_new_output(bytecode)
            analysis.fusion_output = self._get_fusion_output(bytecode)
            
            self.scripts[script_name] = analysis
            
        except Exception as e:
            print(f"Error analyzing {script_name}: {e}")
            
    def _calculate_metrics(self, script_name: str, bytecode: bytes) -> ScriptMetrics:
        """Calculate comprehensive metrics for a script."""
        opcode_stats = OpcodeStats()
        has_branches = False
        has_loops = False
        has_function_calls = False
        max_stack_depth = 0
        current_stack_depth = 0
        fusion_opportunities = 0
        semantic_patterns = []
        
        # Decode instructions
        offset = 0
        instructions = []
        
        while offset < len(bytecode):
            try:
                instr = decode(bytecode, offset)
                if not instr:
                    break
                    
                instructions.append(instr)
                opcode_name = instr.__class__.__name__
                
                # Update opcode statistics
                opcode_stats.total_count += 1
                opcode_stats.unique_opcodes.add(opcode_name)
                opcode_stats.opcode_histogram[opcode_name] = \
                    opcode_stats.opcode_histogram.get(opcode_name, 0) + 1
                    
                # Categorize instructions
                if opcode_name.startswith('Push'):
                    opcode_stats.push_instructions += 1
                    current_stack_depth += 1
                    max_stack_depth = max(max_stack_depth, current_stack_depth)
                    
                if opcode_name in ['IfNot', 'Iff', 'Jump']:
                    opcode_stats.control_flow_instructions += 1
                    has_branches = True
                    if current_stack_depth > 0:
                        current_stack_depth -= 1
                        
                if opcode_name in ['Jump'] and offset > 0:
                    # Check if it's a backward jump (potential loop)
                    if hasattr(instr, 'offset') and instr.offset < 0:
                        has_loops = True
                        
                if 'Var' in opcode_name:
                    opcode_stats.variable_operations += 1
                    
                if opcode_name in ['StartScript', 'DrawObject', 'WalkActorTo',
                                  'IsScriptRunning', 'StopScript']:
                    opcode_stats.function_calls += 1
                    has_function_calls = True
                    
                # Track stack operations for fusion opportunities
                if opcode_name in ['Add', 'Sub', 'Mul', 'Div', 'WriteByteVar',
                                  'WriteWordVar', 'ByteArrayWrite', 'WordArrayWrite']:
                    if current_stack_depth >= 1:
                        fusion_opportunities += 1
                        
                # Update stack depth for consumers
                if hasattr(instr, 'stack_pop_count'):
                    current_stack_depth = max(0, current_stack_depth - instr.stack_pop_count)
                    
                offset += instr.length()
                
            except Exception as e:
                print(f"Error decoding at offset {offset}: {e}")
                break
                
        # Identify semantic patterns
        for i in range(len(instructions) - 1):
            curr = instructions[i]
            next_instr = instructions[i + 1]
            
            # Push + operation pattern
            if (curr.__class__.__name__.startswith('Push') and 
                next_instr.__class__.__name__ in ['Add', 'Sub', 'Mul', 'Div']):
                semantic_patterns.append("arithmetic_expression")
                
            # Variable assignment pattern
            if (curr.__class__.__name__.startswith('Push') and
                next_instr.__class__.__name__ in ['WriteByteVar', 'WriteWordVar']):
                semantic_patterns.append("variable_assignment")
                
            # Comparison pattern
            if (curr.__class__.__name__ in ['Eq', 'Neq', 'Gt', 'Lt', 'Le', 'Ge'] and
                next_instr.__class__.__name__ in ['IfNot', 'Iff']):
                semantic_patterns.append("conditional_branch")
                
        # Calculate complexity score
        complexity_score = (
            opcode_stats.total_count +
            opcode_stats.control_flow_instructions * 3 +
            opcode_stats.function_calls * 2 +
            (10 if has_loops else 0) +
            max_stack_depth
        )
        
        return ScriptMetrics(
            name=script_name,
            size_bytes=len(bytecode),
            instruction_count=opcode_stats.total_count,
            opcode_stats=opcode_stats,
            has_branches=has_branches,
            has_loops=has_loops,
            has_function_calls=has_function_calls,
            max_stack_depth=max_stack_depth,
            complexity_score=complexity_score,
            fusion_opportunities=fusion_opportunities,
            semantic_patterns=list(set(semantic_patterns))
        )
        
    def _get_descumm_output(self, bytecode: bytes) -> Optional[str]:
        """Get descumm output for bytecode."""
        if not self.descumm_path:
            return None
            
        try:
            # Create temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
                
            # Run descumm
            result = subprocess.run(
                [str(self.descumm_path), '-6', tmp_path],
                capture_output=True,
                text=True
            )
            
            # Clean up
            os.unlink(tmp_path)
            
            return result.stdout.strip() if result.returncode == 0 else None
            
        except Exception as e:
            print(f"Error running descumm: {e}")
            return None
            
    def _get_legacy_output(self, bytecode: bytes) -> str:
        """Get legacy decoder output."""
        # Legacy output not available in standalone mode
        # Would require full Binary Ninja integration
        return "Legacy decoder output not available in standalone analysis"
        
    def _get_new_output(self, bytecode: bytes) -> str:
        """Get new decoder output without fusion."""
        lines = []
        offset = 0
        
        while offset < len(bytecode):
            try:
                instr = decode(bytecode, offset)
                if not instr:
                    break
                tokens = instr.render()
                # Handle different token types properly
                text_parts = []
                for t in tokens:
                    if hasattr(t, 'text'):
                        text_parts.append(t.text)
                    else:
                        text_parts.append(str(t))
                text = ''.join(text_parts)
                lines.append(f"[{offset:04X}] {text}")
                offset += instr.length()
            except Exception as e:
                print(f"Error in new decoder at {offset}: {e}")
                break
                
        return '\n'.join(lines)
        
    def _get_fusion_output(self, bytecode: bytes) -> str:
        """Get new decoder output with fusion."""
        lines = []
        offset = 0
        
        while offset < len(bytecode):
            try:
                remaining_data = bytecode[offset:]
                instr = decode_with_fusion_incremental(remaining_data, offset)
                if not instr:
                    break
                tokens = instr.render()
                # Handle different token types properly
                text_parts = []
                for t in tokens:
                    if hasattr(t, 'text'):
                        text_parts.append(t.text)
                    else:
                        text_parts.append(str(t))
                text = ''.join(text_parts)
                lines.append(f"[{offset:04X}] {text}")
                offset += instr.length()
            except Exception as e:
                print(f"Error in fusion decoder at {offset}: {e}")
                break
                
        return '\n'.join(lines)
        
    def generate_report(self, output_dir: str = "analysis_output") -> None:
        """Generate comprehensive analysis reports."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Summary report
        self._generate_summary_report(output_path)
        
        # Complexity-based categorization
        self._generate_complexity_report(output_path)
        
        # Fusion opportunity report
        self._generate_fusion_report(output_path)
        
        # Individual script reports
        scripts_dir = output_path / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        for script_name, analysis in self.scripts.items():
            self._generate_script_report(scripts_dir, analysis)
            
        print(f"Reports generated in {output_path}")
        
    def _generate_summary_report(self, output_path: Path) -> None:
        """Generate overall summary report."""
        with open(output_path / "summary.txt", "w") as f:
            f.write("DOTTDEMO.bsc6 Script Analysis Summary\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Total scripts analyzed: {len(self.scripts)}\n")
            
            # Calculate aggregate statistics
            total_bytes = sum(a.metrics.size_bytes for a in self.scripts.values())
            total_instructions = sum(a.metrics.instruction_count for a in self.scripts.values())
            scripts_with_branches = sum(1 for a in self.scripts.values() if a.metrics.has_branches)
            scripts_with_loops = sum(1 for a in self.scripts.values() if a.metrics.has_loops)
            scripts_with_functions = sum(1 for a in self.scripts.values() if a.metrics.has_function_calls)
            total_fusion_opportunities = sum(a.metrics.fusion_opportunities for a in self.scripts.values())
            
            f.write(f"Total bytecode size: {total_bytes} bytes\n")
            f.write(f"Total instructions: {total_instructions}\n")
            f.write(f"Scripts with branches: {scripts_with_branches}\n")
            f.write(f"Scripts with loops: {scripts_with_loops}\n")
            f.write(f"Scripts with function calls: {scripts_with_functions}\n")
            f.write(f"Total fusion opportunities: {total_fusion_opportunities}\n\n")
            
            # Most common opcodes
            all_opcodes = defaultdict(int)
            for analysis in self.scripts.values():
                for opcode, count in analysis.metrics.opcode_stats.opcode_histogram.items():
                    all_opcodes[opcode] += count
                    
            f.write("Top 20 Most Common Opcodes:\n")
            for opcode, count in sorted(all_opcodes.items(), key=lambda x: x[1], reverse=True)[:20]:
                f.write(f"  {opcode}: {count}\n")
                
    def _generate_complexity_report(self, output_path: Path) -> None:
        """Generate complexity-based categorization."""
        with open(output_path / "complexity_categories.txt", "w") as f:
            f.write("Scripts Categorized by Complexity\n")
            f.write("=" * 50 + "\n\n")
            
            # Sort by complexity
            sorted_scripts = sorted(
                self.scripts.items(),
                key=lambda x: x[1].metrics.complexity_score
            )
            
            # Define complexity tiers
            simple = []
            moderate = []
            complex = []
            
            for name, analysis in sorted_scripts:
                score = analysis.metrics.complexity_score
                if score < 20:
                    simple.append((name, analysis))
                elif score < 50:
                    moderate.append((name, analysis))
                else:
                    complex.append((name, analysis))
                    
            # Write each tier
            f.write(f"SIMPLE SCRIPTS ({len(simple)} scripts):\n")
            f.write("Good starting points for fusion implementation\n")
            f.write("-" * 30 + "\n")
            for name, analysis in simple[:10]:  # Top 10
                f.write(f"{name}: {analysis.metrics.instruction_count} instructions, "
                       f"score={analysis.metrics.complexity_score}\n")
            f.write("\n")
            
            f.write(f"MODERATE SCRIPTS ({len(moderate)} scripts):\n")
            f.write("Good for testing more complex patterns\n")
            f.write("-" * 30 + "\n")
            for name, analysis in moderate[:10]:  # Top 10
                f.write(f"{name}: {analysis.metrics.instruction_count} instructions, "
                       f"score={analysis.metrics.complexity_score}, "
                       f"branches={analysis.metrics.has_branches}, "
                       f"loops={analysis.metrics.has_loops}\n")
            f.write("\n")
            
            f.write(f"COMPLEX SCRIPTS ({len(complex)} scripts):\n")
            f.write("Ultimate test cases for semantic understanding\n")
            f.write("-" * 30 + "\n")
            for name, analysis in complex[:10]:  # Top 10
                f.write(f"{name}: {analysis.metrics.instruction_count} instructions, "
                       f"score={analysis.metrics.complexity_score}, "
                       f"patterns={','.join(analysis.metrics.semantic_patterns)}\n")
                       
    def _generate_fusion_report(self, output_path: Path) -> None:
        """Generate fusion opportunity analysis."""
        with open(output_path / "fusion_opportunities.txt", "w") as f:
            f.write("Fusion Opportunity Analysis\n")
            f.write("=" * 50 + "\n\n")
            
            # Sort by fusion opportunities
            sorted_by_fusion = sorted(
                self.scripts.items(),
                key=lambda x: x[1].metrics.fusion_opportunities,
                reverse=True
            )
            
            f.write("Top Scripts with Fusion Opportunities:\n")
            f.write("-" * 30 + "\n")
            
            for name, analysis in sorted_by_fusion[:20]:
                if analysis.metrics.fusion_opportunities > 0:
                    percentage = (analysis.metrics.fusion_opportunities / 
                                 analysis.metrics.instruction_count * 100)
                    f.write(f"{name}: {analysis.metrics.fusion_opportunities} opportunities "
                           f"({percentage:.1f}% of instructions)\n")
                           
            # Pattern analysis
            f.write("\n\nSemantic Pattern Distribution:\n")
            f.write("-" * 30 + "\n")
            
            pattern_counts = defaultdict(int)
            for analysis in self.scripts.values():
                for pattern in analysis.metrics.semantic_patterns:
                    pattern_counts[pattern] += 1
                    
            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{pattern}: {count} scripts\n")
                
    def _generate_script_report(self, scripts_dir: Path, analysis: ScriptAnalysis) -> None:
        """Generate detailed report for individual script."""
        script_file = scripts_dir / f"{analysis.script_name}.txt"
        
        with open(script_file, "w") as f:
            f.write(f"Script Analysis: {analysis.script_name}\n")
            f.write("=" * 50 + "\n\n")
            
            # Metrics
            f.write("METRICS:\n")
            f.write(f"  Size: {analysis.metrics.size_bytes} bytes\n")
            f.write(f"  Instructions: {analysis.metrics.instruction_count}\n")
            f.write(f"  Complexity Score: {analysis.metrics.complexity_score}\n")
            f.write(f"  Has Branches: {analysis.metrics.has_branches}\n")
            f.write(f"  Has Loops: {analysis.metrics.has_loops}\n")
            f.write(f"  Has Function Calls: {analysis.metrics.has_function_calls}\n")
            f.write(f"  Max Stack Depth: {analysis.metrics.max_stack_depth}\n")
            f.write(f"  Fusion Opportunities: {analysis.metrics.fusion_opportunities}\n")
            f.write(f"  Semantic Patterns: {', '.join(analysis.metrics.semantic_patterns)}\n\n")
            
            # Opcode distribution
            f.write("OPCODE DISTRIBUTION:\n")
            for opcode, count in sorted(
                analysis.metrics.opcode_stats.opcode_histogram.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                f.write(f"  {opcode}: {count}\n")
            f.write("\n")
            
            # Output comparisons
            if analysis.descumm_output:
                f.write("DESCUMM OUTPUT:\n")
                f.write("-" * 30 + "\n")
                f.write(analysis.descumm_output)
                f.write("\n\n")
                
            f.write("NEW DECODER OUTPUT (NO FUSION):\n")
            f.write("-" * 30 + "\n")
            f.write(analysis.new_output)
            f.write("\n\n")
            
            f.write("NEW DECODER OUTPUT (WITH FUSION):\n")
            f.write("-" * 30 + "\n")
            f.write(analysis.fusion_output)
            f.write("\n\n")
            
            # Gap analysis
            if analysis.descumm_output and analysis.fusion_output:
                f.write("GAP ANALYSIS:\n")
                f.write("-" * 30 + "\n")
                
                # Simple line count comparison
                descumm_lines = len(analysis.descumm_output.split('\n'))
                fusion_lines = len(analysis.fusion_output.split('\n'))
                
                f.write(f"Line count: descumm={descumm_lines}, fusion={fusion_lines}\n")
                
                # Check for semantic features in descumm
                descumm_lower = analysis.descumm_output.lower()
                has_expressions = '=' in descumm_lower and '(' in descumm_lower
                has_control_flow = 'if' in descumm_lower or 'while' in descumm_lower
                has_function_calls = '(' in descumm_lower and ')' in descumm_lower
                
                f.write(f"Descumm has expressions: {has_expressions}\n")
                f.write(f"Descumm has control flow: {has_control_flow}\n")
                f.write(f"Descumm has function calls: {has_function_calls}\n")
                
    def export_json(self, output_file: str = "dottdemo_analysis.json") -> None:
        """Export analysis data as JSON for further processing."""
        data = {}
        
        for script_name, analysis in self.scripts.items():
            data[script_name] = {
                "metrics": {
                    "size_bytes": analysis.metrics.size_bytes,
                    "instruction_count": analysis.metrics.instruction_count,
                    "complexity_score": analysis.metrics.complexity_score,
                    "has_branches": analysis.metrics.has_branches,
                    "has_loops": analysis.metrics.has_loops,
                    "has_function_calls": analysis.metrics.has_function_calls,
                    "max_stack_depth": analysis.metrics.max_stack_depth,
                    "fusion_opportunities": analysis.metrics.fusion_opportunities,
                    "semantic_patterns": analysis.metrics.semantic_patterns,
                    "unique_opcodes": list(analysis.metrics.opcode_stats.unique_opcodes),
                    "opcode_histogram": analysis.metrics.opcode_stats.opcode_histogram
                },
                "has_descumm_output": bool(analysis.descumm_output),
                "bytecode_hex": analysis.bytecode.hex()
            }
            
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
            
        print(f"Exported analysis to {output_file}")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze DOTTDEMO.bsc6 scripts for systematic improvement"
    )
    parser.add_argument(
        "--bsc6",
        default="DOTTDEMO.bsc6",
        help="Path to DOTTDEMO.bsc6 file"
    )
    parser.add_argument(
        "--output-dir",
        default="analysis_output",
        help="Directory for output reports"
    )
    parser.add_argument(
        "--json",
        help="Export analysis as JSON file"
    )
    
    args = parser.parse_args()
    
    # Check if BSC6 file exists
    if not os.path.exists(args.bsc6):
        print(f"Error: {args.bsc6} not found")
        sys.exit(1)
        
    # Create analyzer
    analyzer = DottdemoAnalyzer(args.bsc6)
    
    # Extract and analyze all scripts
    analyzer.extract_all_scripts()
    
    # Generate reports
    analyzer.generate_report(args.output_dir)
    
    # Export JSON if requested
    if args.json:
        analyzer.export_json(args.json)
        
    print("\nAnalysis complete!")
    print(f"Analyzed {len(analyzer.scripts)} scripts")
    print(f"Reports available in {args.output_dir}/")


if __name__ == "__main__":
    main()