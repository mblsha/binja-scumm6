# SCUMM6 Fusion Test Suite Plan

Based on analysis of DOTTDEMO.bsc6 scripts

## Phase 1: Basic Instruction Fusion (Tiny Scripts)

Start with the simplest scripts to verify basic fusion:

- **room1_exit** (1 bytes): `65`
- **room1_enter** (1 bytes): `65`
- **room5_exit** (1 bytes): `65`
- **room6_exit** (1 bytes): `65`
- **room7_exit** (1 bytes): `65`

## Phase 2: Expression Building (Small Scripts)

Test arithmetic and variable assignment fusion:

- **room7_enter** (11 bytes)
- **room10_exit** (16 bytes)
- **room10_enter** (16 bytes)
- **room2_enter** (18 bytes)
- **room8_enter** (19 bytes)

## Phase 3: Control Flow (Medium Scripts)

Test conditional and loop fusion:

- **room8_scrp20** (31 bytes)
- **room8_scrp21** (31 bytes)
- **room8_scrp12** (32 bytes)
- **room4_enter** (36 bytes)
- **room12_enter** (39 bytes)

## Phase 4: Complex Algorithms (Large Scripts)

Ultimate test cases:

- **room8_scrp7** (225 bytes)
- **room8_scrp15** (233 bytes)
- **room8_local200** (238 bytes)
- **room8_scrp4** (243 bytes)
- **room5_scrp1** (245 bytes)

## Recommended Test Priorities

1. room11_enter - Known working test case with descumm comparison
2. room8_scrp18 - Collision detection algorithm (463 bytes)
3. room2_enter - Simple script with function calls
4. Small arithmetic scripts for expression fusion
5. Scripts with obvious patterns in bytecode
