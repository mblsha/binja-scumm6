#!/usr/bin/env python3
"""
SCUMM6 Disassembly Comparison TUI Application

The Textual-based terminal user interface for interactive exploration of
disassembly differences.
"""


from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, Center, Middle
from textual.widgets import Header, Footer, ListView, ListItem, Label, Input, ProgressBar, Static
from textual.screen import Screen, ModalScreen
from textual.binding import Binding
from textual.worker import Worker
from textual.message import Message

# Import our enhanced diff widgets
try:
    from .diff_widgets import DiffPanelContainer
except ImportError:
    from diff_widgets import DiffPanelContainer


class LoadingScreen(ModalScreen):
    """Modal screen showing progress while loading scripts."""
    
    CSS = """
    LoadingScreen {
        align: center middle;
    }
    
    #loading-container {
        background: $surface;
        border: solid $primary;
        padding: 2 4;
        width: 60;
        height: 12;
    }
    
    #loading-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    
    #loading-status {
        text-align: center;
        margin-bottom: 1;
    }
    
    #loading-current {
        text-align: center;
        color: $text-muted;
        height: 3;
    }
    
    ProgressBar {
        margin: 1 0;
    }
    """
    
    def __init__(self):
        super().__init__()
        self.progress_bar = None
        self.status_label = None
        self.current_label = None
        
    def compose(self) -> ComposeResult:
        """Create the loading screen layout."""
        with Container(id="loading-container"):
            yield Label("Loading SCUMM6 Scripts", id="loading-title")
            yield Label("Initializing...", id="loading-status")
            yield ProgressBar(total=100, show_eta=False, id="loading-progress")
            yield Label("", id="loading-current")
    
    def on_mount(self) -> None:
        """Store references when mounted."""
        self.progress_bar = self.query_one("#loading-progress", ProgressBar)
        self.status_label = self.query_one("#loading-status", Label)
        self.current_label = self.query_one("#loading-current", Label)
    
    def update_progress(self, current: int, total: int, script_name: str) -> None:
        """Update the progress display."""
        if not self.is_mounted:
            return
            
        if total > 0:
            # Update progress bar
            if self.progress_bar:
                self.progress_bar.total = total
                self.progress_bar.progress = current
            
            # Update status text
            percentage = (current / total) * 100
            if self.status_label:
                self.status_label.update(f"Processing scripts: {current}/{total} ({percentage:.0f}%)")
            
            # Update current script
            if self.current_label:
                if script_name == "Complete":
                    self.current_label.update("✓ Analysis complete!")
                else:
                    self.current_label.update(f"Analyzing: {script_name}")
            
            # Force a refresh to ensure UI updates
            self.refresh()


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
    
    # Custom messages for worker communication
    class ProgressUpdate(Message):
        """Message to update progress."""
        def __init__(self, current: int, total: int, script_name: str):
            super().__init__()
            self.current = current
            self.total = total
            self.script_name = script_name
    
    class ProcessingComplete(Message):
        """Message when processing is complete."""
        pass
    
    class ProcessingError(Message):
        """Message when processing encounters an error."""
        def __init__(self, error: str):
            super().__init__()
            self.error = error
    
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
        # Show loading screen and start background processing
        self.loading_screen = LoadingScreen()
        self.push_screen(self.loading_screen)
        self.run_worker(self.process_scripts_worker(), exclusive=True)
        
    async def process_scripts_worker(self) -> None:
        """Process scripts in a background worker."""
        import asyncio
        import time
        from concurrent.futures import ThreadPoolExecutor
        
        # Store reference to app for posting messages
        app = self.app
        
        def process_with_progress():
            """Run processing in thread with progress updates."""
            def progress_callback(current, total, script_name):
                # Post message to app
                app.post_message(
                    Scumm6ComparisonApp.ProgressUpdate(current, total, script_name)
                )
                # Small delay to allow UI updates
                time.sleep(0.01)
            
            try:
                self.data_provider.process_all_scripts(progress_callback)
                app.post_message(Scumm6ComparisonApp.ProcessingComplete())
            except Exception as e:
                app.post_message(Scumm6ComparisonApp.ProcessingError(str(e)))
        
        # Run in thread executor
        with ThreadPoolExecutor(max_workers=1) as executor:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(executor, process_with_progress)
    
    def on_scripts_loaded(self) -> None:
        """Called when all scripts have been processed."""
        # Dismiss loading screen if it exists
        if hasattr(self, 'loading_screen') and self.loading_screen:
            try:
                self.pop_screen()
            except Exception:
                pass  # Screen might already be dismissed
        
        # Refresh the list
        self.refresh_list()
        
        # Show success notification
        self.notify(f"Loaded {len(self.data_provider.scripts)} scripts", 
                   title="Success", severity="information")
    
    def on_scripts_error(self, error_msg: str) -> None:
        """Called when there's an error processing scripts."""
        # Dismiss loading screen if it exists
        if hasattr(self, 'loading_screen') and self.loading_screen:
            try:
                self.pop_screen()
            except Exception:
                pass  # Screen might already be dismissed
        
        # Show error
        self.notify(f"Error loading data: {error_msg}", 
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
        # Clear existing comparisons
        self.data_provider.comparisons.clear()
        
        # Show loading screen and reprocess
        self.loading_screen = LoadingScreen()
        self.push_screen(self.loading_screen)
        self.run_worker(self.process_scripts_worker(), exclusive=True)
    
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
    
    def on_progress_update(self, message: ProgressUpdate) -> None:
        """Handle progress update messages."""
        if hasattr(self, 'loading_screen') and self.loading_screen:
            self.loading_screen.update_progress(
                message.current, message.total, message.script_name
            )
    
    def on_processing_complete(self, message: ProcessingComplete) -> None:
        """Handle processing complete message."""
        self.on_scripts_loaded()
    
    def on_processing_error(self, message: ProcessingError) -> None:
        """Handle processing error message."""
        self.on_scripts_error(message.error)