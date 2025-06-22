#!/usr/bin/env python3
"""
SCUMM6 Disassembly Comparison TUI Application

The Textual-based terminal user interface for interactive exploration of
disassembly differences.
"""

from typing import List, Dict
from dataclasses import dataclass

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, ListView, ListItem, Label, Static, Input, LoadingIndicator
from textual.screen import Screen
from textual.reactive import reactive
from textual.binding import Binding
from textual import events
from textual.widget import Widget
from textual.message import Message

# Import our enhanced diff widgets
try:
    from .diff_widgets import DiffPanelContainer, SynchronizedScrollView
except ImportError:
    from diff_widgets import DiffPanelContainer, SynchronizedScrollView


class DiffScreen(Screen):
    """Detailed diff view showing three panels of disassembly."""
    
    BINDINGS = [
        Binding("escape", "pop_screen", "Back to list"),
        Binding("h", "toggle_highlight", "Toggle highlighting"),
        Binding("s", "toggle_sync", "Toggle sync scrolling"),
    ]
    
    def __init__(self, comparison):
        super().__init__()
        self.comparison = comparison
        self.sync_enabled = True
        self.highlight_enabled = True
        
    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        yield Header()
        yield Container(
            Vertical(
                Label(f"Script: {self.comparison.name} | Match: {self.comparison.match_score:.0%}", id="script-name"),
                Horizontal(
                    Vertical(
                        Label("descumm (reference)", classes="panel-header reference-header"),
                        DiffPanelContainer(
                            "descumm",
                            self.comparison.descumm_output,
                            panel_type="reference",
                            sync_group="diff" if self.sync_enabled else None,
                            classes="panel-container",
                            id="descumm-panel"
                        ),
                        classes="panel-wrapper",
                    ),
                    Vertical(
                        Label("pyscumm6 (fused)", classes="panel-header fused-header"),
                        DiffPanelContainer(
                            "fused",
                            self.comparison.fused_output,
                            reference_content=self.comparison.descumm_output if self.highlight_enabled else None,
                            panel_type="comparison",
                            sync_group="diff" if self.sync_enabled else None,
                            classes="panel-container",
                            id="fused-panel"
                        ),
                        classes="panel-wrapper",
                    ),
                    Vertical(
                        Label("pyscumm6 (raw)", classes="panel-header raw-header"),
                        DiffPanelContainer(
                            "raw",
                            self.comparison.raw_output,
                            reference_content=self.comparison.descumm_output if self.highlight_enabled else None,
                            panel_type="comparison",
                            sync_group="diff" if self.sync_enabled else None,
                            classes="panel-container",
                            id="raw-panel"
                        ),
                        classes="panel-wrapper",
                    ),
                    id="panels",
                ),
                id="diff-container",
            )
        )
        yield Footer()
    
    def action_toggle_highlight(self) -> None:
        """Toggle difference highlighting."""
        self.highlight_enabled = not self.highlight_enabled
        self.refresh()
        self.notify(f"Highlighting {'enabled' if self.highlight_enabled else 'disabled'}")
    
    def action_toggle_sync(self) -> None:
        """Toggle synchronized scrolling."""
        self.sync_enabled = not self.sync_enabled
        self.refresh()
        self.notify(f"Synchronized scrolling {'enabled' if self.sync_enabled else 'disabled'}")


class ScriptListItem(ListItem):
    """Custom list item for script display."""
    
    def __init__(self, comparison):
        super().__init__()
        self.comparison = comparison
        
    def compose(self) -> ComposeResult:
        """Create the list item layout."""
        status_char = "✓" if self.comparison.is_match else "✗"
        status_class = "match" if self.comparison.is_match else "no-match"
        
        yield Horizontal(
            Label(status_char, classes=f"status-indicator {status_class}"),
            Label(self.comparison.name, classes="script-name"),
            Label(f"{self.comparison.match_score:.0%}", classes="match-score"),
        )


class Scumm6ComparisonApp(App):
    """Main TUI application for comparing SCUMM6 disassembly."""
    
    CSS = """
    #script-list {
        height: 100%;
        border: solid green;
    }
    
    .status-indicator {
        width: 3;
        text-align: center;
    }
    
    .status-indicator.match {
        color: green;
        text-style: bold;
    }
    
    .status-indicator.no-match {
        color: red;
        text-style: bold;
    }
    
    .script-name {
        width: 30;
    }
    
    .match-score {
        width: 10;
        text-align: right;
    }
    
    #summary {
        height: 3;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    
    #search-container {
        display: none;
        height: 3;
        background: $surface;
        border: solid $warning;
        padding: 0 1;
    }
    
    #search-container.visible {
        display: block;
    }
    
    #search-input {
        width: 100%;
        background: transparent;
    }
    
    #diff-container {
        height: 100%;
    }
    
    #script-name {
        height: 3;
        text-align: center;
        text-style: bold;
        background: $surface;
        padding: 0 1;
    }
    
    #panels {
        height: 100%;
    }
    
    .panel-wrapper {
        width: 1fr;
        height: 100%;
        margin: 0 1;
    }
    
    .panel-container {
        height: 100%;
        border: solid $primary;
    }
    
    .panel-header {
        height: 2;
        text-align: center;
        text-style: bold;
        padding: 0 1;
    }
    
    .reference-header {
        background: $success;
        color: $text;
    }
    
    .fused-header {
        background: $primary;
        color: $text;
    }
    
    .raw-header {
        background: $secondary;
        color: $text;
    }
    
    SynchronizedScrollView {
        height: 100%;
        scrollbar-size: 1 1;
    }
    
    HighlightedDiffPanel {
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("/", "search", "Search"),
        Binding("escape", "cancel_search", "Cancel", show=False),
    ]
    
    def __init__(self, data_provider):
        super().__init__()
        self.data_provider = data_provider
        self.title = "SCUMM6 Disassembly Comparison"
        self.search_active = False
        self.filtered_comparisons = []
        
    def on_mount(self) -> None:
        """Initialize data when app mounts."""
        self.load_data()
        
    def load_data(self) -> None:
        """Load and process all script data."""
        # Show loading state
        list_view = self.query_one("#script-list", ListView)
        list_view.loading = True
        self.notify("Loading scripts...", title="Please wait")
        
        try:
            self.data_provider.process_all_scripts()
            list_view.loading = False
            self.refresh_list()
            self.notify(f"Loaded {len(self.data_provider.scripts)} scripts", 
                       title="Success", severity="information")
        except Exception as e:
            list_view.loading = False
            self.notify(f"Error loading data: {str(e)}", 
                       title="Error", severity="error")
    
    def compose(self) -> ComposeResult:
        """Create the main UI layout."""
        yield Header()
        yield Container(
            Label("", id="summary"),
            Container(
                Input(placeholder="Search scripts...", id="search-input"),
                id="search-container"
            ),
            ListView(id="script-list"),
            id="main-container",
        )
        yield Footer()
    
    def refresh_list(self, filter_text: str = "") -> None:
        """Refresh the script list view."""
        list_view = self.query_one("#script-list", ListView)
        list_view.clear()
        
        # Sort scripts by name
        all_comparisons = sorted(
            self.data_provider.comparisons.values(),
            key=lambda c: c.name
        )
        
        # Filter if search is active
        if filter_text:
            self.filtered_comparisons = [
                c for c in all_comparisons 
                if filter_text.lower() in c.name.lower()
            ]
        else:
            self.filtered_comparisons = all_comparisons
        
        # Add items to list
        matched = 0
        for comparison in self.filtered_comparisons:
            if comparison.is_match:
                matched += 1
            list_view.append(ScriptListItem(comparison))
        
        # Update summary
        summary = self.query_one("#summary", Label)
        total = len(self.filtered_comparisons)
        if total > 0:
            if filter_text:
                summary.update(f"Filtered: {matched}/{total} scripts match ({matched/total:.0%})")
            else:
                summary.update(f"Matched: {matched}/{total} scripts ({matched/total:.0%})")
        else:
            summary.update("No scripts found")
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle list item selection."""
        if isinstance(event.item, ScriptListItem):
            self.push_screen(DiffScreen(event.item.comparison))
    
    def action_refresh(self) -> None:
        """Refresh all data."""
        self.load_data()
    
    def action_search(self) -> None:
        """Activate search mode."""
        self.search_active = True
        search_container = self.query_one("#search-container")
        search_container.add_class("visible")
        search_input = self.query_one("#search-input", Input)
        search_input.value = ""
        search_input.focus()
    
    def action_cancel_search(self) -> None:
        """Cancel search mode."""
        if self.search_active:
            self.search_active = False
            search_container = self.query_one("#search-container")
            search_container.remove_class("visible")
            self.refresh_list()  # Reset to show all scripts
            list_view = self.query_one("#script-list", ListView)
            list_view.focus()
    
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes."""
        if event.input.id == "search-input":
            self.refresh_list(event.value)
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle search input submission."""
        if event.input.id == "search-input":
            self.action_cancel_search()  # Close search after submission