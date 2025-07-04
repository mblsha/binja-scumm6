#!/usr/bin/env python3
"""Debug script to check LLIL operations for actor_ops instructions."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.test_utils import run_scumm6_llil_generation
from src.test_descumm_tool import ensure_demo_bsc6
from src.disasm import Scumm6Disasm

# Get the script data
ensure_demo_bsc6()
with open('DOTTDEMO.bsc6', 'rb') as f:
    container_data = f.read()

disasm = Scumm6Disasm()
scripts = disasm.parse_bsc6(container_data)

# Find room2_scrp1
script_info = None
for script in scripts:
    if script.name == 'room2_scrp1':
        script_info = script
        break

if script_info:
    print(f"Found script: {script_info.name}")
    print(f"Start: {hex(script_info.start)}, End: {hex(script_info.end)}")
    
    bytecode = container_data[script_info.start:script_info.end]
    start_addr = script_info.start
    
    # Generate LLIL with fusion
    llil_ops = run_scumm6_llil_generation(bytecode, start_addr, use_fusion=True)
    
    # Look for operations around our target addresses
    target_addrs = [0x004B, 0x0050, 0x0052, 0x0057, 0x007E]
    
    print('\nLooking for actor operations in LLIL:')
    for addr, op in llil_ops:
        rel_addr = addr - start_addr
        if rel_addr in target_addrs:
            print(f'  {hex(rel_addr)}: {op}')
        elif addr in target_addrs:
            print(f'  {hex(addr)} (abs): {op}')
    
    # Show first 20 operations to understand the pattern
    print(f'\nFirst 20 operations (total: {len(llil_ops)}):')
    for i, (addr, op) in enumerate(llil_ops[:20]):
        rel_addr = addr - start_addr
        print(f'  {hex(rel_addr)}: {op}')
        
    # Show operations around our target area  
    print('\nOperations around 0x004B - 0x007E:')
    for addr, op in llil_ops:
        rel_addr = addr - start_addr
        if 0x004B <= rel_addr <= 0x0090:
            print(f'  {hex(rel_addr)}: {op}')
else:
    print("Script room2_scrp1 not found!")