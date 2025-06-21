#!/usr/bin/env python3
"""
Simple script inventory for DOTTDEMO.bsc6 focusing on basic metrics.
This provides a foundation for systematic comparison work.
"""

import os
import sys
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List

# Add parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force mock Binary Ninja for standalone execution
os.environ["FORCE_BINJA_MOCK"] = "1"

from src.disasm import Scumm6Disasm


@dataclass
class SimpleScriptInfo:
    """Basic information about a script."""
    name: str
    size_bytes: int
    offset_in_file: int
    bytecode_hex: str
    bytecode_preview: str  # First 32 bytes as hex
    

class SimpleInventory:
    """Creates a simple inventory of all scripts in DOTTDEMO.bsc6."""
    
    def __init__(self, bsc6_path: str):
        self.bsc6_path = Path(bsc6_path)
        self.bsc6_data = self.bsc6_path.read_bytes()
        self.scripts: List[SimpleScriptInfo] = []
        self._parse_container()
        
    def _parse_container(self) -> None:
        """Parse the BSC6 container and extract script information."""
        result = Scumm6Disasm.decode_container(str(self.bsc6_path), self.bsc6_data)
        if result:
            script_list, state = result
            
            for script_info in script_list:
                bytecode = self.bsc6_data[script_info.start:script_info.end]
                
                # Create preview (first 32 bytes or entire script if shorter)
                preview_len = min(32, len(bytecode))
                preview = bytecode[:preview_len].hex()
                if len(bytecode) > preview_len:
                    preview += "..."
                    
                self.scripts.append(SimpleScriptInfo(
                    name=script_info.name,
                    size_bytes=len(bytecode),
                    offset_in_file=script_info.start,
                    bytecode_hex=bytecode.hex(),
                    bytecode_preview=preview
                ))
        else:
            raise ValueError(f"Failed to parse {self.bsc6_path}")
            
    def generate_report(self, output_file: str = "script_inventory.txt") -> None:
        """Generate a simple text report of all scripts."""
        # Sort by size for easy identification of complexity
        sorted_scripts = sorted(self.scripts, key=lambda s: s.size_bytes)
        
        with open(output_file, "w") as f:
            f.write("DOTTDEMO.bsc6 Script Inventory\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total scripts: {len(self.scripts)}\n")
            f.write(f"Total bytecode: {sum(s.size_bytes for s in self.scripts)} bytes\n\n")
            
            # Group by size ranges
            tiny = [s for s in sorted_scripts if s.size_bytes <= 10]
            small = [s for s in sorted_scripts if 10 < s.size_bytes <= 50]
            medium = [s for s in sorted_scripts if 50 < s.size_bytes <= 200]
            large = [s for s in sorted_scripts if s.size_bytes > 200]
            
            f.write(f"TINY SCRIPTS ({len(tiny)} scripts, <= 10 bytes):\n")
            f.write("Perfect for initial testing\n")
            f.write("-" * 40 + "\n")
            for script in tiny:
                f.write(f"{script.name:20} {script.size_bytes:4} bytes  {script.bytecode_hex}\n")
            f.write("\n")
            
            f.write(f"SMALL SCRIPTS ({len(small)} scripts, 11-50 bytes):\n")
            f.write("Good for basic fusion testing\n")
            f.write("-" * 40 + "\n")
            for script in small[:20]:  # Show first 20
                f.write(f"{script.name:20} {script.size_bytes:4} bytes  {script.bytecode_preview}\n")
            if len(small) > 20:
                f.write(f"... and {len(small) - 20} more\n")
            f.write("\n")
            
            f.write(f"MEDIUM SCRIPTS ({len(medium)} scripts, 51-200 bytes):\n")
            f.write("Complex control flow and expressions\n")
            f.write("-" * 40 + "\n")
            for script in medium[:10]:  # Show first 10
                f.write(f"{script.name:20} {script.size_bytes:4} bytes  {script.bytecode_preview}\n")
            if len(medium) > 10:
                f.write(f"... and {len(medium) - 10} more\n")
            f.write("\n")
            
            f.write(f"LARGE SCRIPTS ({len(large)} scripts, > 200 bytes):\n")
            f.write("Full algorithm implementations\n")
            f.write("-" * 40 + "\n")
            for script in large:
                f.write(f"{script.name:20} {script.size_bytes:4} bytes  {script.bytecode_preview}\n")
                
    def export_json(self, output_file: str = "script_inventory.json") -> None:
        """Export inventory as JSON for further processing."""
        data = {
            "total_scripts": len(self.scripts),
            "total_bytes": sum(s.size_bytes for s in self.scripts),
            "scripts": [asdict(s) for s in self.scripts]
        }
        
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
            
    def create_test_suite_suggestions(self, output_file: str = "test_suite_plan.md") -> None:
        """Create a suggested test suite plan based on script complexity."""
        sorted_scripts = sorted(self.scripts, key=lambda s: s.size_bytes)
        
        with open(output_file, "w") as f:
            f.write("# SCUMM6 Fusion Test Suite Plan\n\n")
            f.write("Based on analysis of DOTTDEMO.bsc6 scripts\n\n")
            
            f.write("## Phase 1: Basic Instruction Fusion (Tiny Scripts)\n\n")
            f.write("Start with the simplest scripts to verify basic fusion:\n\n")
            for script in sorted_scripts[:5]:
                f.write(f"- **{script.name}** ({script.size_bytes} bytes): `{script.bytecode_hex}`\n")
                
            f.write("\n## Phase 2: Expression Building (Small Scripts)\n\n")
            f.write("Test arithmetic and variable assignment fusion:\n\n")
            candidates = [s for s in sorted_scripts if 10 < s.size_bytes <= 30][:5]
            for script in candidates:
                f.write(f"- **{script.name}** ({script.size_bytes} bytes)\n")
                
            f.write("\n## Phase 3: Control Flow (Medium Scripts)\n\n")
            f.write("Test conditional and loop fusion:\n\n")
            candidates = [s for s in sorted_scripts if 30 < s.size_bytes <= 100][:5]
            for script in candidates:
                f.write(f"- **{script.name}** ({script.size_bytes} bytes)\n")
                
            f.write("\n## Phase 4: Complex Algorithms (Large Scripts)\n\n")
            f.write("Ultimate test cases:\n\n")
            candidates = [s for s in sorted_scripts if s.size_bytes > 200][:5]
            for script in candidates:
                f.write(f"- **{script.name}** ({script.size_bytes} bytes)\n")
                
            f.write("\n## Recommended Test Priorities\n\n")
            f.write("1. room11_enter - Known working test case with descumm comparison\n")
            f.write("2. room8_scrp18 - Collision detection algorithm (463 bytes)\n")
            f.write("3. room2_enter - Simple script with function calls\n")
            f.write("4. Small arithmetic scripts for expression fusion\n")
            f.write("5. Scripts with obvious patterns in bytecode\n")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Create simple inventory of DOTTDEMO.bsc6 scripts"
    )
    parser.add_argument(
        "--bsc6",
        default="DOTTDEMO.bsc6",
        help="Path to DOTTDEMO.bsc6 file"
    )
    
    args = parser.parse_args()
    
    # Check if BSC6 file exists
    if not os.path.exists(args.bsc6):
        print(f"Error: {args.bsc6} not found")
        sys.exit(1)
        
    # Create inventory
    inventory = SimpleInventory(args.bsc6)
    
    # Generate outputs
    inventory.generate_report("script_inventory.txt")
    inventory.export_json("script_inventory.json")
    inventory.create_test_suite_suggestions("test_suite_plan.md")
    
    print("Script inventory complete!")
    print(f"Found {len(inventory.scripts)} scripts")
    print("Reports generated:")
    print("  - script_inventory.txt")
    print("  - script_inventory.json")
    print("  - test_suite_plan.md")


if __name__ == "__main__":
    main()