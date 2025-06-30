#!/usr/bin/env python3
"""
Binary Ninja restart script with process monitoring and window verification.
"""
import subprocess
import time
from pathlib import Path
from typing import Optional
from plumbum import cli

class BinaryNinjaRestartMonitor(cli.Application):
    """Restart Binary Ninja and monitor until file is loaded."""
    
    VERSION = "1.0.0"
    
    timeout = cli.SwitchAttr(
        ["-t", "--timeout"],
        int,
        default=30,
        help="Timeout in seconds for window detection"
    )
    
    graceful_quit_timeout = cli.SwitchAttr(
        ["-g", "--graceful-timeout"],
        int,
        default=5,
        help="Timeout in seconds for graceful quit"
    )
    
    extra_wait = cli.SwitchAttr(
        ["-w", "--wait"],
        int,
        default=3,
        help="Extra wait time after window appears"
    )
    
    force = cli.Flag(
        ["-f", "--force"],
        help="Skip graceful quit and force kill immediately"
    )
    
    verbose = cli.Flag(
        ["-v", "--verbose"],
        help="Enable verbose output"
    )
    
    def log(self, message: str, always: bool = False):
        """Log message if verbose or always is True."""
        if self.verbose or always:
            print(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def is_binja_running(self) -> bool:
        """Check if Binary Ninja is running from a valid .app bundle."""
        try:
            # Get all processes named binaryninja
            result = subprocess.run(
                ["pgrep", "-x", "binaryninja"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return False
                
            # Check each PID to verify it's from an .app bundle
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    # Get the full path of the process
                    ps_result = subprocess.run(
                        ["ps", "-p", pid, "-o", "comm="],
                        capture_output=True,
                        text=True
                    )
                    if ps_result.returncode == 0:
                        path = ps_result.stdout.strip()
                        # Check if it's from a valid .app bundle
                        if ("/Binary Ninja.app/Contents/MacOS/binaryninja" in path or
                            path.endswith("/Contents/MacOS/binaryninja")):
                            return True
            
            return False
        except:
            return False
    
    def kill_binja(self) -> bool:
        """Kill Binary Ninja processes."""
        if not self.force:
            self.log("Attempting graceful quit...", always=True)
            try:
                subprocess.run([
                    "osascript", "-e", 
                    'tell application "Binary Ninja" to quit'
                ], capture_output=True)
                
                # Try to handle save dialog if it appears
                time.sleep(0.5)
                subprocess.run([
                    "osascript", "-e",
                    '''tell application "System Events" to tell process "Binary Ninja"
                        repeat 3 times
                            if exists sheet 1 of window 1 then
                                if exists button "Don't Save" of sheet 1 of window 1 then
                                    click button "Don't Save" of sheet 1 of window 1
                                    delay 0.5
                                end if
                            end if
                        end repeat
                    end tell'''
                ], capture_output=True)
                
                # Wait for graceful quit
                for _ in range(self.graceful_quit_timeout):
                    time.sleep(1)
                    if not self.is_binja_running():
                        self.log("Binary Ninja quit gracefully")
                        return True
            except:
                pass
        
        if self.is_binja_running():
            self.log("Force killing Binary Ninja...", always=True)
            # Use pkill with full path pattern to only kill .app bundle processes
            subprocess.run([
                "pkill", "-f", "Binary Ninja\\.app/Contents/MacOS/binaryninja"
            ], capture_output=True)
            time.sleep(1)
            
            if self.is_binja_running():
                self.log("ERROR: Failed to kill Binary Ninja", always=True)
                return False
        
        return True
    
    def open_binja(self, file_path: Optional[str] = None) -> None:
        """Open Binary Ninja with optional file."""
        if file_path:
            self.log(f"Opening Binary Ninja with: {file_path}", always=True)
            subprocess.run(["open", "-a", "Binary Ninja", file_path])
        else:
            self.log("Opening Binary Ninja without file", always=True)
            subprocess.run(["open", "-a", "Binary Ninja"])
    
    def wait_for_window(self, file_name: Optional[str] = None) -> bool:
        """Wait for Binary Ninja window to open."""
        self.log(f"Waiting for window (timeout: {self.timeout}s)...", always=True)
        start_time = time.time()
        
        while time.time() - start_time < self.timeout:
            try:
                result = subprocess.run([
                    "osascript", "-e",
                    'tell application "System Events" to tell process "Binary Ninja" to get name of window 1'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    window_name = result.stdout.strip()
                    self.log(f"Found window: {window_name}")
                    
                    if file_name:
                        if file_name.lower() in window_name.lower():
                            print(f"✓ Window opened: {window_name}")
                            return True
                    else:
                        # If no file specified, any window is good
                        print(f"✓ Window opened: {window_name}")
                        return True
            except:
                pass
            
            time.sleep(0.5)
            if not self.verbose:
                print(".", end="", flush=True)
        
        if not self.verbose:
            print()
        print("✗ Timeout waiting for window")
        return False
    
    
    def verify_file_loaded(self, file_path: str) -> bool:
        """Additional wait time to ensure file is loaded."""
        self.log(f"Waiting {self.extra_wait}s for file to fully load...", always=True)
        time.sleep(self.extra_wait)
        print(f"✓ File loading wait complete")
        return True
    
    def main(self, file_path: str = None):
        """Main entry point."""
        # Verify file exists if provided
        if file_path and not Path(file_path).exists():
            print(f"Error: File not found: {file_path}")
            return 1
        
        file_name = Path(file_path).name if file_path else None
        
        print(f"Binary Ninja Restart")
        if file_path:
            print(f"File: {file_path}")
        else:
            print("No file specified - opening Binary Ninja only")
        print("-" * 40)
        
        # Kill existing instances
        if self.is_binja_running():
            if not self.kill_binja():
                return 1
        else:
            self.log("Binary Ninja not currently running")
        
        # Open Binary Ninja
        self.open_binja(file_path)
        
        # Wait for window
        if self.wait_for_window(file_name):
            # Additional verification only if file was provided
            if file_path:
                if self.verify_file_loaded(file_path):
                    print("\n✓ Binary Ninja successfully restarted and file loaded!")
                    return 0
            else:
                print("\n✓ Binary Ninja successfully restarted!")
                return 0
        
        print("\n✗ Failed to verify Binary Ninja loaded properly")
        return 1

if __name__ == "__main__":
    BinaryNinjaRestartMonitor.run()