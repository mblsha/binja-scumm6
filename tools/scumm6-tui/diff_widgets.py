#!/usr/bin/env python3
"""
Enhanced diff visualization widgets for SCUMM6 comparison TUI.

Provides synchronized scrolling and difference highlighting.
"""

from typing import List, Optional
import difflib
import re

from textual.app import ComposeResult
from textual.containers import ScrollableContainer
from textual.reactive import reactive
from textual.widget import Widget
from textual import events
from rich.text import Text
from rich.style import Style


class DiffLine:
    """Represents a single line in the diff with metadata."""
    
    def __init__(self, content: str, line_type: str = "normal", match_score: float = 1.0):
        self.content = content
        self.line_type = line_type  # "normal", "added", "removed", "changed"
        self.match_score = match_score
        self.normalized = self._normalize(content)
    
    def _normalize(self, line: str) -> str:
        """Normalize line for comparison."""
        # Strip address prefixes
        line = re.sub(r'^\[[0-9A-Fa-f]+\]\s*', '', line)
        line = re.sub(r'^\([0-9A-Fa-f]+\)\s*', '', line)
        
        # Normalize variable names
        line = re.sub(r'localvar(\d+)', r'var_\1', line)
        
        # Normalize spacing
        line = ' '.join(line.split())
        
        return line.strip()


class SynchronizedScrollView(ScrollableContainer):
    """A scrollable view that can be synchronized with other views."""
    
    # Reactive property for scroll position
    scroll_y = reactive(0)
    
    def __init__(self, *args, sync_group: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.sync_group = sync_group
        self._is_syncing = False
    
    def watch_scroll_y(self, old_value: int, new_value: int) -> None:
        """When scroll position changes, notify other views in sync group."""
        if not self._is_syncing and self.sync_group:
            # Notify other views in the same sync group
            for widget in self.screen.query(SynchronizedScrollView):
                if widget != self and widget.sync_group == self.sync_group:
                    widget.sync_scroll_to(new_value)
    
    def sync_scroll_to(self, y: int) -> None:
        """Synchronize scroll position from another view."""
        self._is_syncing = True
        self.scroll_to(0, y, animate=False)
        self._is_syncing = False
    
    def on_scroll(self, event: events.Scroll) -> None:
        """Update reactive property when scrolling."""
        self.scroll_y = self.scroll_offset.y


class HighlightedDiffPanel(Widget):
    """Panel that displays diff content with syntax highlighting."""
    
    def __init__(self, content: str, reference_content: Optional[str] = None, 
                 panel_type: str = "normal", align_lines: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.content = content
        self.reference_content = reference_content
        self.panel_type = panel_type
        self.align_lines = align_lines
        self.diff_lines = self._process_content()
    
    def _process_content(self) -> List[DiffLine]:
        """Process content and identify differences."""
        lines = self.content.strip().split('\n') if self.content.strip() else []
        diff_lines = []
        
        if self.reference_content and self.panel_type != "reference":
            # Compare with reference content
            ref_lines = self.reference_content.strip().split('\n') if self.reference_content.strip() else []
            
            if self.align_lines:
                # Use aligned comparison
                return self._create_aligned_diff(ref_lines, lines)
            
            # Create normalized versions for comparison
            norm_lines = [self._normalize_line(line) for line in lines]
            norm_ref_lines = [self._normalize_line(line) for line in ref_lines]
            
            # Use difflib to find differences
            matcher = difflib.SequenceMatcher(None, norm_ref_lines, norm_lines)
            
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == 'equal':
                    for i in range(j1, j2):
                        diff_lines.append(DiffLine(lines[i], "normal"))
                elif tag == 'insert':
                    for i in range(j1, j2):
                        diff_lines.append(DiffLine(lines[i], "added"))
                elif tag == 'delete':
                    # These lines exist in reference but not here
                    if self.align_lines:
                        for i in range(i1, i2):
                            diff_lines.append(DiffLine("", "removed"))
                elif tag == 'replace':
                    for i in range(j1, j2):
                        if i < len(lines):
                            # Calculate similarity score
                            ref_idx = i1 + (i - j1)
                            if ref_idx < len(norm_ref_lines):
                                score = difflib.SequenceMatcher(
                                    None, norm_ref_lines[ref_idx], norm_lines[i]
                                ).ratio()
                                diff_lines.append(DiffLine(lines[i], "changed", score))
                            else:
                                diff_lines.append(DiffLine(lines[i], "added"))
        elif self.panel_type == "reference" and self.align_lines:
            # For reference panel, we need to create alignment based on what other panels will show
            # This is a simplified approach - in production, we'd coordinate between panels
            diff_lines = [DiffLine(line, "normal") for line in lines]
        else:
            # No comparison, just normal lines
            diff_lines = [DiffLine(line, "normal") for line in lines]
        
        return diff_lines
    
    def _create_aligned_diff(self, ref_lines: List[str], lines: List[str]) -> List[DiffLine]:
        """Create aligned diff output with padding for missing lines."""
        # Create normalized versions
        norm_lines = [(line, self._normalize_line(line)) for line in lines]
        norm_ref_lines = [(line, self._normalize_line(line)) for line in ref_lines]
        
        # Build alignment using dynamic programming
        aligned_lines = []
        matcher = difflib.SequenceMatcher(
            None, 
            [norm for _, norm in norm_ref_lines],
            [norm for _, norm in norm_lines]
        )
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for i in range(j2 - j1):
                    aligned_lines.append(DiffLine(lines[j1 + i], "normal"))
            elif tag == 'insert':
                for i in range(j2 - j1):
                    aligned_lines.append(DiffLine(lines[j1 + i], "added"))
            elif tag == 'delete':
                # Add empty lines to maintain alignment
                for i in range(i2 - i1):
                    aligned_lines.append(DiffLine("", "removed"))
            elif tag == 'replace':
                # Add changed lines and padding
                ref_count = i2 - i1
                line_count = j2 - j1
                
                for i in range(max(ref_count, line_count)):
                    if i < line_count:
                        # Calculate similarity with corresponding ref line
                        if i < ref_count:
                            score = difflib.SequenceMatcher(
                                None,
                                norm_ref_lines[i1 + i][1],
                                norm_lines[j1 + i][1]
                            ).ratio()
                            aligned_lines.append(DiffLine(lines[j1 + i], "changed", score))
                        else:
                            aligned_lines.append(DiffLine(lines[j1 + i], "added"))
                    else:
                        # Padding for missing lines
                        aligned_lines.append(DiffLine("", "removed"))
        
        return aligned_lines
    
    def _normalize_line(self, line: str) -> str:
        """Normalize a line for comparison."""
        # Strip address prefixes
        line = re.sub(r'^\[[0-9A-Fa-f]+\]\s*', '', line)
        line = re.sub(r'^\([0-9A-Fa-f]+\)\s*', '', line)
        
        # Normalize variable names
        line = re.sub(r'localvar(\d+)', r'var_\1', line)
        
        # Normalize function names
        line = re.sub(r'stopObjectCodeA', 'stop_object_code1', line)
        line = re.sub(r'startScript', 'start_script', line)
        line = re.sub(r'roomOps\.setScreen', 'room_ops.room_screen', line)
        
        # Normalize spacing
        line = ' '.join(line.split())
        
        return line.strip()
    
    def render(self) -> Text:
        """Render the diff with highlighting."""
        output = Text()
        
        for i, diff_line in enumerate(self.diff_lines):
            if i > 0:
                output.append("\n")
            
            # Handle empty lines (used for alignment)
            if diff_line.line_type == "removed" and not diff_line.content:
                output.append(" ", Style(dim=True))  # Placeholder for alignment
                continue
            
            # Choose style based on line type
            if diff_line.line_type == "normal":
                style = Style(color="white")
            elif diff_line.line_type == "added":
                style = Style(color="green", bold=True)
            elif diff_line.line_type == "changed":
                # Color based on match score
                if diff_line.match_score < 0.5:
                    style = Style(color="red", bold=True)
                elif diff_line.match_score < 0.8:
                    style = Style(color="yellow")
                else:
                    style = Style(color="cyan")
            elif diff_line.line_type == "removed":
                style = Style(color="red", dim=True, strike=True)
            else:
                style = Style(color="white")
            
            output.append(diff_line.content or " ", style)
        
        return output


class DiffPanelContainer(Widget):
    """Container for a diff panel with header."""
    
    def __init__(self, title: str, content: str, reference_content: Optional[str] = None,
                 panel_type: str = "normal", sync_group: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.content = content
        self.reference_content = reference_content
        self.panel_type = panel_type
        self.sync_group = sync_group
    
    def compose(self) -> ComposeResult:
        """Create the panel layout."""
        with SynchronizedScrollView(sync_group=self.sync_group):
            yield HighlightedDiffPanel(
                self.content,
                reference_content=self.reference_content,
                panel_type=self.panel_type
            )