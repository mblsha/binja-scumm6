#!/usr/bin/env python3
"""
Script to ensure the descumm tool from scummvm-tools is compiled and working.

This script:
1. Initializes git submodules (including scummvm-tools)
2. Configures and compiles the scummvm-tools
3. Downloads the Day of the Tentacle demo files
4. Converts the demo files to .bsc6 format
5. Extracts a script portion from the demo
6. Tests the descumm tool with the extracted script
7. Provides a simple interface to run descumm on script portions
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional, List
import tempfile


class DescummSetup:
    def __init__(self, repo_root: Optional[str] = None):
        """Initialize the setup with the repository root directory."""
        self.repo_root = Path(repo_root) if repo_root else Path.cwd()
        self.scummvm_tools_dir = self.repo_root / "scummvm-tools"
        self.descumm_path = self.scummvm_tools_dir / "descumm"
        self.demo_files = {
            "zip_url": "https://archive.org/download/DayOfTheTentacleDemo/DOTTDEMO.ZIP",
            "zip_file": self.repo_root / "DOTTDEMO.ZIP",
            "demo_000": self.repo_root / "DOTTDEMO.000",
            "demo_001": self.repo_root / "DOTTDEMO.001",
            "bsc6_file": self.repo_root / "dottdemo.bsc6"
        }

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, 
                   check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        print(f"Running: {' '.join(cmd)}")
        if cwd:
            print(f"  in directory: {cwd}")
        
        result = subprocess.run(
            cmd, 
            cwd=cwd or self.repo_root, 
            check=check, 
            capture_output=capture_output,
            text=True
        )
        return result

    def check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        dependencies = ["git", "make", "g++", "python3"]
        missing = []
        
        for dep in dependencies:
            try:
                subprocess.run([dep, "--version"], 
                             capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                missing.append(dep)
        
        if missing:
            print(f"Missing dependencies: {', '.join(missing)}")
            print("Please install them before continuing.")
            return False
        
        print("All dependencies are available.")
        return True

    def init_submodules(self) -> bool:
        """Initialize git submodules."""
        print("Initializing git submodules...")
        try:
            self.run_command(["git", "submodule", "update", "--init", "--recursive"])
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to initialize submodules: {e}")
            return False

    def compile_scummvm_tools(self) -> bool:
        """Configure and compile scummvm-tools."""
        print("Configuring scummvm-tools...")
        
        if not self.scummvm_tools_dir.exists():
            print(f"scummvm-tools directory not found: {self.scummvm_tools_dir}")
            return False
        
        try:
            # Configure
            self.run_command(["./configure"], cwd=self.scummvm_tools_dir)
            
            # Compile
            print("Compiling scummvm-tools...")
            self.run_command(["make"], cwd=self.scummvm_tools_dir)
            
            # Check if descumm was built
            if not self.descumm_path.exists():
                print(f"descumm tool not found after compilation: {self.descumm_path}")
                return False
            
            print(f"Successfully compiled descumm tool: {self.descumm_path}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile scummvm-tools: {e}")
            return False

    def download_demo_files(self) -> bool:
        """Download the Day of the Tentacle demo files."""
        if self.demo_files["demo_000"].exists() and self.demo_files["demo_001"].exists():
            print("Demo files already exist, skipping download.")
            return True
        
        print("Downloading Day of the Tentacle demo...")
        try:
            urllib.request.urlretrieve(
                self.demo_files["zip_url"], 
                self.demo_files["zip_file"]
            )
            
            print("Extracting demo files...")
            with zipfile.ZipFile(self.demo_files["zip_file"], 'r') as zip_ref:
                zip_ref.extractall(self.repo_root)
            
            # Clean up zip file
            self.demo_files["zip_file"].unlink()
            
            if not (self.demo_files["demo_000"].exists() and 
                   self.demo_files["demo_001"].exists()):
                print("Demo files not found after extraction.")
                return False
            
            print("Successfully downloaded and extracted demo files.")
            return True
            
        except Exception as e:
            print(f"Failed to download demo files: {e}")
            return False

    def convert_demo_to_bsc6(self) -> bool:
        """Convert demo files to .bsc6 format."""
        if self.demo_files["bsc6_file"].exists():
            print("BSC6 file already exists, skipping conversion.")
            return True
        
        print("Converting demo files to .bsc6 format...")
        try:
            self.run_command([
                "python", "converter/cli.py",
                str(self.demo_files["demo_000"]),
                str(self.demo_files["demo_001"]),
                "-o", str(self.demo_files["bsc6_file"])
            ])
            
            if not self.demo_files["bsc6_file"].exists():
                print("BSC6 file not created after conversion.")
                return False
            
            print(f"Successfully converted demo to BSC6 format: {self.demo_files['bsc6_file']}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to convert demo files: {e}")
            return False

    def extract_test_script(self) -> Optional[Path]:
        """Extract a test script from the demo for testing."""
        print("Extracting test script from demo...")
        
        try:
            # Use the existing extraction code
            script_code = '''
from src.scumm6_container import Scumm6Container
from kaitaistruct import KaitaiStream, BytesIO

with open('dottdemo.bsc6', 'rb') as f:
    data = f.read()

container = Scumm6Container(KaitaiStream(BytesIO(data)))
main_block = container.blocks[0]

# Look for a script block in the rooms
for room_block in main_block.block_data.blocks[1:]:  # Skip LOFF
    if room_block.block_type.name == 'lflf':
        for nested in room_block.block_data.blocks:
            if nested.block_type.name == 'scrp':
                print(f"Found script block with {nested.block_size} bytes")
                script_data = nested.block_data.data
                with open('test_script.bin', 'wb') as f:
                    f.write(script_data)
                print(f"Extracted script to test_script.bin ({len(script_data)} bytes)")
                exit(0)

print("No script blocks found")
exit(1)
'''
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_code)
                temp_script = f.name
            
            try:
                self.run_command(["python", temp_script])
                test_script_path = self.repo_root / "test_script.bin"
                
                if test_script_path.exists():
                    print(f"Successfully extracted test script: {test_script_path}")
                    return test_script_path
                else:
                    print("Test script file not created.")
                    return None
                    
            finally:
                os.unlink(temp_script)
                
        except subprocess.CalledProcessError as e:
            print(f"Failed to extract test script: {e}")
            return None

    def test_descumm_tool(self, script_path: Path) -> bool:
        """Test the descumm tool with the extracted script."""
        print(f"Testing descumm tool with script: {script_path}")
        
        try:
            result = self.run_command([
                str(self.descumm_path), "-6", "-u", str(script_path)
            ], capture_output=True)
            
            if result.stdout:
                print("Descumm output:")
                print(result.stdout)
                print("✅ Descumm tool is working correctly!")
                return True
            else:
                print("No output from descumm tool.")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Failed to run descumm tool: {e}")
            if e.stderr:
                print(f"Error output: {e.stderr}")
            return False

    def run_descumm(self, script_path: str, version: int = 6, 
                   unblocked: bool = True, extra_args: Optional[List[str]] = None) -> str:
        """Run descumm on a script file and return the output."""
        if not self.descumm_path.exists():
            raise RuntimeError("Descumm tool not found. Run setup() first.")
        
        cmd = [str(self.descumm_path), f"-{version}"]
        if unblocked:
            cmd.append("-u")
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(script_path)
        
        try:
            result = self.run_command(cmd, capture_output=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Descumm failed: {e}")

    def setup(self) -> bool:
        """Run the complete setup process."""
        print("🚀 Setting up descumm tool...")
        
        steps = [
            ("Checking dependencies", self.check_dependencies),
            ("Initializing submodules", self.init_submodules),
            ("Compiling scummvm-tools", self.compile_scummvm_tools),
            ("Downloading demo files", self.download_demo_files),
            ("Converting demo to BSC6", self.convert_demo_to_bsc6),
        ]
        
        for step_name, step_func in steps:
            print(f"\n📋 {step_name}...")
            if not step_func():
                print(f"❌ Failed: {step_name}")
                return False
            print(f"✅ Completed: {step_name}")
        
        # Extract and test script
        print("\n📋 Extracting test script...")
        test_script = self.extract_test_script()
        if not test_script:
            print("❌ Failed to extract test script")
            return False
        print("✅ Extracted test script")
        
        print("\n📋 Testing descumm tool...")
        if not self.test_descumm_tool(test_script):
            print("❌ Descumm tool test failed")
            return False
        print("✅ Descumm tool test passed")
        
        print("\n🎉 Setup completed successfully!")
        print(f"Descumm tool is available at: {self.descumm_path}")
        print(f"Test script is available at: {test_script}")
        print(f"Demo BSC6 file is available at: {self.demo_files['bsc6_file']}")
        
        return True


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(__doc__)
        return
    
    setup = DescummSetup()
    
    if not setup.setup():
        print("\n❌ Setup failed!")
        sys.exit(1)
    
    print("\n✨ You can now use the descumm tool:")
    print(f"  {setup.descumm_path} -6 -u script-file")
    print("\n📚 Or use the Python interface in test_descumm.py")


if __name__ == "__main__":
    main()

