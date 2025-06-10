#!/usr/bin/env python3
"""
Test suite for the descumm tool setup and functionality.

This module provides:
1. Unit tests for the descumm tool setup
2. Integration tests with actual SCUMM6 scripts
3. Helper functions for extracting and testing scripts
4. Examples of using the descumm tool programmatically
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional, Tuple
import subprocess
import os

from setup_descumm import DescummSetup


class TestDescummSetup(unittest.TestCase):
    """Test cases for the descumm setup functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.setup = DescummSetup()
        
    def test_dependencies_check(self):
        """Test that dependency checking works."""
        # This should pass in a properly configured environment
        result = self.setup.check_dependencies()
        self.assertTrue(result, "Dependencies should be available")
    
    def test_descumm_tool_exists(self):
        """Test that the descumm tool exists after setup."""
        if not self.setup.descumm_path.exists():
            # Try to set up first
            self.setup.setup()
        
        self.assertTrue(
            self.setup.descumm_path.exists(),
            f"Descumm tool should exist at {self.setup.descumm_path}"
        )
        
        # Test that it's executable
        self.assertTrue(
            os.access(self.setup.descumm_path, os.X_OK),
            "Descumm tool should be executable"
        )
    
    def test_descumm_help(self):
        """Test that descumm tool shows help."""
        if not self.setup.descumm_path.exists():
            self.skipTest("Descumm tool not available")
        
        try:
            result = subprocess.run(
                [str(self.setup.descumm_path), "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            # descumm shows help on any invalid option
            self.assertIn("SCUMM Script decompiler", result.stdout)
        except subprocess.TimeoutExpired:
            self.fail("Descumm tool timed out")
    
    def test_demo_files_exist(self):
        """Test that demo files can be downloaded and converted."""
        # Check if BSC6 file exists
        if not self.setup.demo_files["bsc6_file"].exists():
            # Try to download and convert
            self.assertTrue(
                self.setup.download_demo_files(),
                "Should be able to download demo files"
            )
            self.assertTrue(
                self.setup.convert_demo_to_bsc6(),
                "Should be able to convert demo to BSC6"
            )
        
        self.assertTrue(
            self.setup.demo_files["bsc6_file"].exists(),
            "BSC6 file should exist"
        )
    
    def test_script_extraction(self):
        """Test that scripts can be extracted from the demo."""
        if not self.setup.demo_files["bsc6_file"].exists():
            self.skipTest("BSC6 file not available")
        
        script_path = self.setup.extract_test_script()
        self.assertIsNotNone(script_path, "Should be able to extract a test script")
        self.assertTrue(script_path.exists(), "Extracted script file should exist")
        self.assertGreater(script_path.stat().st_size, 0, "Script file should not be empty")
    
    def test_descumm_on_extracted_script(self):
        """Test running descumm on an extracted script."""
        if not self.setup.descumm_path.exists():
            self.skipTest("Descumm tool not available")
        
        if not self.setup.demo_files["bsc6_file"].exists():
            self.skipTest("BSC6 file not available")
        
        script_path = self.setup.extract_test_script()
        if not script_path:
            self.skipTest("Could not extract test script")
        
        result = self.setup.test_descumm_tool(script_path)
        self.assertTrue(result, "Descumm should successfully process the extracted script")


class ScriptExtractor:
    """Helper class for extracting scripts from SCUMM6 files."""
    
    def __init__(self, bsc6_path: str):
        """Initialize with path to BSC6 file."""
        self.bsc6_path = Path(bsc6_path)
        if not self.bsc6_path.exists():
            raise FileNotFoundError(f"BSC6 file not found: {bsc6_path}")
    
    def extract_all_scripts(self, output_dir: str) -> List[Tuple[str, Path]]:
        """Extract all scripts from the BSC6 file to the output directory."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        scripts = []
        
        try:
            from src.scumm6_container import Scumm6Container
            from kaitaistruct import KaitaiStream, BytesIO
            
            with open(self.bsc6_path, 'rb') as f:
                data = f.read()
            
            container = Scumm6Container(KaitaiStream(BytesIO(data)))
            main_block = container.blocks[0]
            
            script_count = 0
            
            # Look through all room blocks
            for i, room_block in enumerate(main_block.block_data.blocks[1:], 1):
                if room_block.block_type.name == 'lflf':
                    # Look for script blocks in this room
                    for j, nested in enumerate(room_block.block_data.blocks):
                        if nested.block_type.name == 'scrp':
                            script_name = f"room{i}_script{j}.bin"
                            script_path = output_path / script_name
                            
                            script_data = nested.block_data.data
                            with open(script_path, 'wb') as f:
                                f.write(script_data)
                            
                            scripts.append((script_name, script_path))
                            script_count += 1
            
            print(f"Extracted {script_count} scripts to {output_path}")
            return scripts
            
        except ImportError:
            raise RuntimeError("Required modules not available. Run 'pip install -e .[dev]' first.")
    
    def get_script_info(self, script_path: str) -> dict:
        """Get information about a script file."""
        path = Path(script_path)
        if not path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")
        
        return {
            "path": str(path),
            "size": path.stat().st_size,
            "name": path.name,
        }


class DescummRunner:
    """Helper class for running descumm with various options."""
    
    def __init__(self, descumm_path: Optional[str] = None):
        """Initialize with path to descumm tool."""
        if descumm_path:
            self.descumm_path = Path(descumm_path)
        else:
            # Try to find it in the default location
            setup = DescummSetup()
            self.descumm_path = setup.descumm_path
        
        if not self.descumm_path.exists():
            raise FileNotFoundError(f"Descumm tool not found: {self.descumm_path}")
    
    def decompile_script(self, script_path: str, version: int = 6, 
                        unblocked: bool = True, show_offsets: bool = False,
                        extra_options: Optional[List[str]] = None) -> str:
        """Decompile a script file and return the output."""
        cmd = [str(self.descumm_path)]
        
        # Add version flag
        cmd.append(f"-{version}")
        
        # Add unblocked flag if needed
        if unblocked:
            cmd.append("-u")
        
        # Add offset flag if requested
        if show_offsets:
            cmd.append("-o")
        
        # Add any extra options
        if extra_options:
            cmd.extend(extra_options)
        
        # Add script path
        cmd.append(script_path)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Descumm failed: {e}\nStderr: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Descumm timed out")
    
    def analyze_script(self, script_path: str) -> dict:
        """Analyze a script and return information about it."""
        output = self.decompile_script(script_path, show_offsets=True)
        
        lines = output.strip().split('\n')
        instructions = []
        
        for line in lines:
            if line.startswith('[') and ']' in line:
                # Parse instruction line
                offset_end = line.find(']')
                offset = line[1:offset_end]
                instruction = line[offset_end+1:].strip()
                
                if instruction and instruction != 'END':
                    instructions.append({
                        'offset': offset,
                        'instruction': instruction
                    })
        
        return {
            'total_lines': len(lines),
            'instruction_count': len(instructions),
            'instructions': instructions,
            'raw_output': output
        }


def demo_usage():
    """Demonstrate usage of the descumm tools."""
    print("🎯 Descumm Tool Demo")
    print("=" * 50)
    
    # Set up the tool
    setup = DescummSetup()
    
    if not setup.descumm_path.exists():
        print("Setting up descumm tool...")
        if not setup.setup():
            print("❌ Setup failed!")
            return
    
    print(f"✅ Descumm tool available at: {setup.descumm_path}")
    
    # Extract scripts
    if setup.demo_files["bsc6_file"].exists():
        print("\n📦 Extracting scripts from demo...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            extractor = ScriptExtractor(str(setup.demo_files["bsc6_file"]))
            scripts = extractor.extract_all_scripts(temp_dir)
            
            if scripts:
                print(f"Found {len(scripts)} scripts")
                
                # Analyze the first few scripts
                runner = DescummRunner(str(setup.descumm_path))
                
                for script_name, script_path in scripts[:3]:  # Analyze first 3 scripts
                    print(f"\n🔍 Analyzing {script_name}:")
                    
                    try:
                        analysis = runner.analyze_script(str(script_path))
                        print(f"  Instructions: {analysis['instruction_count']}")
                        print(f"  Size: {script_path.stat().st_size} bytes")
                        
                        # Show first few instructions
                        print("  First instructions:")
                        for instr in analysis['instructions'][:5]:
                            print(f"    [{instr['offset']}] {instr['instruction']}")
                        
                        if len(analysis['instructions']) > 5:
                            print(f"    ... and {len(analysis['instructions']) - 5} more")
                    
                    except Exception as e:
                        print(f"  ❌ Error analyzing script: {e}")
            else:
                print("No scripts found in demo file")
    else:
        print("Demo BSC6 file not available")
    
    print("\n✨ Demo completed!")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            demo_usage()
        elif sys.argv[1] == "--test":
            # Run specific tests
            unittest.main(argv=['test_descumm.py'] + sys.argv[2:])
        else:
            print("Usage:")
            print("  python test_descumm.py --demo    # Run demonstration")
            print("  python test_descumm.py --test    # Run unit tests")
            print("  python test_descumm.py           # Run all tests")
    else:
        # Run all tests by default
        unittest.main()

