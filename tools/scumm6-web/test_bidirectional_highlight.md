# Testing Bidirectional Highlighting in Web UI

## Implementation Summary

I've successfully implemented bidirectional highlighting in the SCUMM6 web UI. The feature now works as follows:

### Original Behavior (Unchanged)
- When hovering over an address in the **fused** or **descumm** panels, the corresponding raw instructions that were fused together are highlighted in purple in the **raw** panel

### New Behavior (Added)
- When hovering over an address in the **raw** panel, all fused instructions that contain that raw instruction are highlighted in purple in the **fused** panel

### Implementation Details

1. **Added `highlightFusedInstructions` function** (lines 953-972 in index.html):
   - Takes a raw instruction address as input
   - Finds all fusion spans that contain this raw instruction
   - Highlights all fused instructions that correspond to these spans

2. **Updated `handleAddressHover` function** (line 911):
   - Added check for hovering in raw panel
   - Calls `highlightFusedInstructions` when appropriate

3. **Data Structure Used**:
   - `window.currentFusionSpans` contains fusion span information:
     - `start_offset`: Starting offset of fused instruction
     - `end_offset`: Ending offset of fused instruction
     - `raw_instruction_offsets`: Array of raw instruction offsets that were combined

### Testing Instructions

1. Start the web server:
   ```bash
   cd tools/scumm6-web
   python app.py
   ```

2. Open browser to http://localhost:6001

3. Select a script with fusion (e.g., room2_enter, room11_enter)

4. Test the highlighting:
   - Hover over addresses in the **fused** panel → see raw instructions highlight
   - Hover over addresses in the **raw** panel → see fused instructions highlight

### Example Test Cases

1. **Script: room2_enter**
   - Fused: `[0000] startScript(1, 201, [])`
   - Raw: Multiple push and call instructions
   - Hovering on raw push instructions should highlight the fused startScript

2. **Script: delay_frames_simple**
   - Fused: `[0000] delayFrames(4)`
   - Raw: `push_word(4)` and `delayFrames`
   - Hovering on either raw instruction should highlight the fused delayFrames