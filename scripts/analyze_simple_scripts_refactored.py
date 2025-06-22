#!/usr/bin/env python3
"""
Refactored simple script analyzer using the shared analysis toolkit.

This script systematically compares descumm output with our decoder implementations
to identify gaps and generate actionable recommendations for improvement.
"""

import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force mock Binary Ninja for testing
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401
from src.analysis_utils import create_analysis_toolkit


@dataclass
class FusionGapAnalysis:
    """Analysis of fusion gaps between descumm and our implementation."""
    script_name: str
    bytecode_size: int
    descumm_lines: int
    legacy_lines: int
    fusion_lines: int
    fusion_improvement: float  # legacy_lines / fusion_lines
    identified_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SimpleScriptAnalyzer:
    """Analyze simple SCUMM6 scripts for fusion opportunities using shared toolkit."""
    
    def __init__(self) -> None:
        """Initialize analyzer with shared toolkit."""
        self.toolkit = create_analysis_toolkit()
        self.simple_scripts = self.toolkit.get_simple_scripts(max_bytes=50)
        
    def analyze_all_simple_scripts(self) -> List[FusionGapAnalysis]:
        """Analyze all simple scripts for fusion opportunities."""
        results = []
        
        print(f"Analyzing {len(self.simple_scripts)} simple scripts (≤50 bytes)...")
        
        for script in self.simple_scripts:
            analysis = self._analyze_single_script(script.name)
            results.append(analysis)
            
        return sorted(results, key=lambda x: x.fusion_improvement, reverse=True)
    
    def _analyze_single_script(self, script_name: str) -> FusionGapAnalysis:
        """Analyze a single script for fusion opportunities."""
        comparison = self.toolkit.compare_outputs(script_name)
        
        # Calculate fusion improvement ratio
        fusion_improvement = (comparison['legacy_lines'] / comparison['fusion_lines'] 
                            if comparison['fusion_lines'] > 0 else 1.0)
        
        # Identify gaps and recommendations
        gaps = self._identify_fusion_gaps(comparison)
        recommendations = self._generate_recommendations(comparison, gaps)
        
        return FusionGapAnalysis(
            script_name=script_name,
            bytecode_size=comparison['bytecode_size'],
            descumm_lines=comparison['descumm_lines'],
            legacy_lines=comparison['legacy_lines'],
            fusion_lines=comparison['fusion_lines'],
            fusion_improvement=fusion_improvement,
            identified_gaps=gaps,
            recommendations=recommendations
        )
    
    def _identify_fusion_gaps(self, comparison: Dict[str, Any]) -> List[str]:
        """Identify specific fusion gaps by analyzing outputs."""
        gaps = []
        
        descumm_output = comparison['outputs']['descumm']
        fusion_output = comparison['outputs']['fusion']
        
        # Look for patterns that indicate fusion opportunities
        if 'push_' in fusion_output:
            gaps.append("Unfused push operations detected")
            
        if 'startScript(' in descumm_output and 'startScript(...)' in fusion_output:
            gaps.append("Function call fusion incomplete - parameters not fused")
            
        if comparison['fusion_lines'] >= comparison['legacy_lines']:
            gaps.append("Fusion providing no compression benefit")
            
        # Check for variable assignment patterns
        if 'var_' in fusion_output and '=' not in fusion_output:
            gaps.append("Variable assignments not fused into assignment syntax")
            
        return gaps
    
    def _generate_recommendations(self, comparison: Dict[str, Any], gaps: List[str]) -> List[str]:
        """Generate actionable recommendations based on identified gaps."""
        recommendations = []
        
        script_name = comparison['script_name']
        
        for gap in gaps:
            if "Unfused push operations" in gap:
                recommendations.append(f"Implement fusion for remaining push operations in {script_name}")
                
            elif "Function call fusion incomplete" in gap:
                recommendations.append(f"Complete function parameter fusion for {script_name}")
                
            elif "Variable assignments not fused" in gap:
                recommendations.append(f"Implement assignment-style rendering for variable writes in {script_name}")
                
            elif "no compression benefit" in gap:
                recommendations.append(f"Review fusion logic for {script_name} - may have regression")
        
        # Add general recommendations based on size
        if comparison['bytecode_size'] <= 20:
            recommendations.append(f"Small script {script_name} - good candidate for comprehensive fusion test case")
            
        return recommendations
    
    def generate_summary_report(self, analyses: List[FusionGapAnalysis]) -> str:
        """Generate a comprehensive summary report."""
        total_scripts = len(analyses)
        improved_scripts = len([a for a in analyses if a.fusion_improvement > 1.0])
        avg_improvement = sum(a.fusion_improvement for a in analyses) / total_scripts
        
        report = f"""
# Simple Script Fusion Analysis Summary

## Overview
- **Total Scripts Analyzed**: {total_scripts}
- **Scripts with Fusion Improvement**: {improved_scripts}
- **Average Fusion Compression Ratio**: {avg_improvement:.2f}x

## Top Fusion Improvements
"""
        
        for analysis in analyses[:5]:  # Top 5
            report += f"""
### {analysis.script_name}
- **Size**: {analysis.bytecode_size} bytes
- **Fusion Improvement**: {analysis.fusion_improvement:.2f}x ({analysis.legacy_lines} → {analysis.fusion_lines} lines)
- **Gaps**: {', '.join(analysis.identified_gaps) if analysis.identified_gaps else 'None identified'}
"""
        
        report += """
## Action Items
"""
        
        # Aggregate recommendations
        all_recommendations = []
        for analysis in analyses:
            all_recommendations.extend(analysis.recommendations)
        
        unique_recommendations = list(set(all_recommendations))
        for i, rec in enumerate(unique_recommendations[:10], 1):  # Top 10
            report += f"{i}. {rec}\n"
        
        return report
    
    def generate_test_cases(self, analyses: List[FusionGapAnalysis], count: int = 3) -> str:
        """Generate test cases for the most promising scripts."""
        best_scripts = sorted(analyses, key=lambda x: x.fusion_improvement, reverse=True)[:count]
        
        test_cases = "# Generated Test Cases for Simple Scripts\n\n"
        
        for analysis in best_scripts:
            test_case = self.toolkit.generate_test_case(analysis.script_name, include_expected_outputs=True)
            test_cases += f"# {analysis.script_name} - {analysis.fusion_improvement:.2f}x improvement\n"
            test_cases += test_case + "\n\n"
        
        return test_cases
    
    def identify_fusion_patterns(self, analyses: List[FusionGapAnalysis]) -> List[str]:
        """Identify common fusion patterns across scripts."""
        patterns = []
        
        # Pattern 1: Scripts with excellent fusion (>2x improvement)
        excellent_fusion = [a for a in analyses if a.fusion_improvement >= 2.0]
        if excellent_fusion:
            patterns.append(f"Excellent fusion pattern: {len(excellent_fusion)} scripts achieve >2x compression")
        
        # Pattern 2: Scripts with no fusion benefit
        no_benefit = [a for a in analyses if a.fusion_improvement <= 1.0]
        if no_benefit:
            patterns.append(f"Fusion regression pattern: {len(no_benefit)} scripts show no improvement")
        
        # Pattern 3: Common gap patterns
        gap_counts: Dict[str, int] = {}
        for analysis in analyses:
            for gap in analysis.identified_gaps:
                gap_counts[gap] = gap_counts.get(gap, 0) + 1
        
        for gap, count in sorted(gap_counts.items(), key=lambda x: x[1], reverse=True):
            if count >= 3:  # Appears in 3+ scripts
                patterns.append(f"Common gap: '{gap}' appears in {count} scripts")
        
        return patterns


def main() -> None:
    """Main analysis execution."""
    analyzer = SimpleScriptAnalyzer()
    
    print("=== Simple Script Fusion Analysis ===")
    print(f"Found {len(analyzer.simple_scripts)} simple scripts to analyze\n")
    
    # Perform analysis
    analyses = analyzer.analyze_all_simple_scripts()
    
    # Generate summary report
    summary = analyzer.generate_summary_report(analyses)
    print(summary)
    
    # Identify patterns
    patterns = analyzer.identify_fusion_patterns(analyses)
    print("\n## Fusion Patterns Identified")
    for pattern in patterns:
        print(f"- {pattern}")
    
    # Generate test cases for top scripts
    test_cases = analyzer.generate_test_cases(analyses, count=3)
    
    # Write outputs to files
    output_dir = Path("analysis_output")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "simple_scripts_analysis.md", "w") as f:
        f.write(summary)
    
    with open(output_dir / "generated_test_cases.py", "w") as f:
        f.write(test_cases)
    
    print(f"\nAnalysis complete! Results written to {output_dir}/")
    print("- simple_scripts_analysis.md: Comprehensive analysis report")
    print("- generated_test_cases.py: Test cases for top scripts")


if __name__ == "__main__":
    main()