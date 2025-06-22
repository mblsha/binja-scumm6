# SCUMM6 Disassembly Comparison TUI

## Product Requirements

### Purpose
Create a terminal user interface (TUI) application to visualize and analyze semantic differences between descumm and pyscumm6 disassemblers for Day of the Tentacle demo scripts.

### Core Features

#### 1. Script List View (Main Screen)
- [x] Display all DOTTDEMO scripts in a scrollable list
- [x] Show comparison status for each script:
  - ✓ = Semantically equivalent outputs  
  - ✗ = Differences detected
- [x] Display match percentage for each script
- [x] Color coding: Green for matches, Red for mismatches
- [x] Summary statistics at top (e.g., "58/66 scripts match (87.8%)")

#### 2. Detailed Diff View (Secondary Screen)
- [x] Three-panel layout showing:
  - Left: descumm output
  - Middle: pyscumm6 with fusion
  - Right: pyscumm6 without fusion
- [ ] Synchronized scrolling between panels
- [ ] Highlight differences between descumm and fused output
- [ ] Show line-by-line alignment where possible

#### 3. Navigation
- [x] Arrow keys to navigate script list
- [x] Enter to open detailed diff view
- [x] ESC to go back to list view
- [x] 'q' to quit application
- [x] '/' to search for script by name
- [x] 'r' to refresh/reprocess all scripts

#### 4. Fuzzy Matching Logic
- [x] Strip address prefixes ([0000] vs [0x0000])
- [x] Normalize variable names (localvar5 vs var_5)
- [x] Ignore whitespace differences
- [ ] Handle instruction name variations (stopObjectCodeA vs stop_object_code1)
- [ ] Consider semantic equivalence, not just string matching

### Technical Requirements

#### Architecture
- [x] Use Textual library for TUI framework
- [x] Use Plumbum.CLI for command-line argument parsing
- [x] Create in new subdirectory: tools/scumm6-tui/
- [x] Support both interactive TUI and CLI modes

#### CLI Options
- [x] `--list` - List all available scripts
- [x] `--compare <script>` - Compare specific script, output JSON
- [x] `--diff` - Show side-by-side diff (use with --compare)
- [x] `--bsc6-path <path>` - Override path to DOTTDEMO.bsc6
- [x] `--descumm-path <path>` - Override path to descumm executable
- [x] `--output <file>` - Save comparison results to file
- [x] `--filter <pattern>` - Filter scripts by name pattern

#### Data Processing
- [x] Load DOTTDEMO.bsc6 once at startup
- [x] Build descumm tool if needed
- [ ] Cache comparison results for performance
- [ ] Process scripts in parallel where possible

#### Testing Support
- [x] CLI mode outputs structured JSON for unit testing
- [x] Separate data processing from UI logic
- [x] Test script demonstrating CLI usage

### MVP Implementation Status

#### Phase 1: Core Infrastructure ✅
- [x] Create directory structure
- [x] Set up Plumbum.CLI application
- [x] Create DataProvider class for data loading
- [x] Implement script comparison logic
- [x] Add fuzzy matching algorithm

#### Phase 2: CLI Implementation ✅
- [x] Implement --list option
- [x] Implement --compare option with JSON output
- [x] Implement --diff option for visual diff
- [x] Add error handling for invalid scripts
- [x] Create test script for CLI

#### Phase 3: TUI Implementation ✅
- [x] Create basic TUI app structure
- [x] Implement script list view
- [x] Implement detailed diff screen
- [x] Add navigation bindings
- [x] Add search functionality
- [x] Add progress indicators
- [x] Polish UI styling (basic styling complete)
- [x] Create documentation and helper scripts

#### Phase 4: Enhancement Features
- [ ] Add caching for comparison results
- [ ] Implement parallel processing
- [ ] Add export functionality
- [ ] Add filter/sort options
- [ ] Improve diff highlighting

### Known Issues
- [ ] Large scripts may be slow to process
- [ ] Some string formatting differences not yet normalized (stopObjectCodeA vs stop_object_code1)
- [ ] Scrolling synchronization between panels not implemented
- [ ] Diff highlighting not implemented

### Future Enhancements
- [ ] Support for other SCUMM games/versions
- [ ] Integration with Binary Ninja plugin
- [ ] Export comparison reports
- [ ] Batch processing mode
- [ ] Configuration file support