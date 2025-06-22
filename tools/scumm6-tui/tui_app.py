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
from textual.widgets import Header, Footer, ListView, ListItem, Label, Static
from textual.screen import Screen
from textual.reactive import reactive
from textual.binding import Binding
from textual import events
from textual.widget import Widget


class DiffScreen(Screen):
    """Detailed diff view showing three panels of disassembly."""
    
    BINDINGS = [
        Binding("escape", "pop_screen", "Back to list"),
    ]
    
    def __init__(self, comparison):
        super().__init__()
        self.comparison = comparison
        
    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        yield Header()
        yield Container(
            Vertical(
                Label(f"Script: {self.comparison.name}", id="script-name"),
                Horizontal(
                    Vertical(
                        Label("descumm", classes="panel-header"),
                        Static(self.comparison.descumm_output, id="descumm-panel", classes="diff-panel"),
                        classes="panel-container",
                    ),
                    Vertical(
                        Label("pyscumm6 (fused)", classes="panel-header"),
                        Static(self.comparison.fused_output, id="fused-panel", classes="diff-panel"),
                        classes="panel-container",
                    ),
                    Vertical(
                        Label("pyscumm6 (raw)", classes="panel-header"),
                        Static(self.comparison.raw_output, id="raw-panel", classes="diff-panel"),
                        classes="panel-container",
                    ),
                    id="panels",
                ),
                id="diff-container",
            )
        )
        yield Footer()


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
    
    #diff-container {
        height: 100%;
    }
    
    #script-name {
        height: 3;
        text-align: center;
        text-style: bold;
        background: $surface;
    }
    
    #panels {
        height: 100%;
    }
    
    .panel-container {
        width: 1fr;
        height: 100%;
        border: solid $primary;
        margin: 0 1;
    }
    
    .panel-header {
        height: 1;
        text-align: center;
        text-style: bold;
        background: $primary;
        color: $text;
    }
    
    .diff-panel {
        height: 100%;
        overflow-y: scroll;
        padding: 0 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def __init__(self, data_provider):
        super().__init__()
        self.data_provider = data_provider
        self.title = "SCUMM6 Disassembly Comparison"
        
    def on_mount(self) -> None:
        """Initialize data when app mounts."""
        self.load_data()
        
    def load_data(self) -> None:
        """Load and process all script data."""
        self.notify("Loading scripts...", title="Please wait")
        try:
            self.data_provider.process_all_scripts()
            self.refresh_list()
            self.notify(f"Loaded {len(self.data_provider.scripts)} scripts", 
                       title="Success", severity="information")
        except Exception as e:
            self.notify(f"Error loading data: {str(e)}", 
                       title="Error", severity="error")
    
    def compose(self) -> ComposeResult:
        """Create the main UI layout."""
        yield Header()
        yield Container(
            Label("", id="summary"),
            ListView(id="script-list"),
            id="main-container",
        )
        yield Footer()
    
    def refresh_list(self) -> None:
        """Refresh the script list view."""
        list_view = self.query_one("#script-list", ListView)
        list_view.clear()
        
        # Sort scripts by name
        sorted_comparisons = sorted(
            self.data_provider.comparisons.values(),
            key=lambda c: c.name
        )
        
        # Add items to list
        matched = 0
        for comparison in sorted_comparisons:
            if comparison.is_match:
                matched += 1
            list_view.append(ScriptListItem(comparison))
        
        # Update summary
        summary = self.query_one("#summary", Label)
        total = len(sorted_comparisons)
        summary.update(f"Matched: {matched}/{total} scripts ({matched/total:.0%})")
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle list item selection."""
        if isinstance(event.item, ScriptListItem):
            self.push_screen(DiffScreen(event.item.comparison))
    
    def action_refresh(self) -> None:
        """Refresh all data."""
        self.load_data()