### **Product Requirements Document: Interactive Side-Panel Analyzer & Test Generator**

**Version:** 2.0
**Date:** 2023-10-27

### 1. Introduction & Goal

This document specifies the requirements for a major feature enhancement to the Scumm6 Disassembly Comparison UI. The current UI is a passive viewer; this feature will transform it into an **interactive analysis workbench**.

The primary goal is to provide developers with a seamless workflow to:
1.  **Isolate** a specific instruction or sequence of bytes for analysis.
2.  **Experiment** by modifying the bytecode and observing the real-time impact on both `descumm` and `pyscumm6` disassembly.
3.  **Document** findings and define the expected correct output.
4.  **Generate** a complete, copy-pasteable `pytest` unit test from the analysis session.

This will significantly accelerate the development and verification of the `pyscumm6` instruction fusion engine.

### 2. User Stories

*   **As a developer, I want to** select an instruction in the diff view and see an analysis panel appear next to it, **so that I can** maintain the original script's context while I work.
*   **As a developer, I want to** edit the raw bytecode for the selected instruction and have the disassembly views update instantly, **so that I can** get immediate feedback on my hypothesis about the byte sequence.
*   **As a developer, I want to** write down my notes and define the "correct" fused disassembly for a given sequence of bytes, **so that I can** formalize the goal for my implementation work.
*   **As a developer, I want to** click a single button to generate a complete `pytest` test case from my interactive session, **so that I can** create a regression test with near-zero friction.

### 3. Scope (Minimum Viable Product)

#### 3.1. In-Scope for MVP

*   **UI Layout:** A side-panel that opens for analysis, pushing the existing three columns to the left but keeping them visible.
*   **Modal Interaction:** When the side-panel is open, the main three disassembly columns become non-interactive (read-only context).
*   **Note Persistence:** A simple, local, file-based database (a single JSON file, e.g., `analysis_notes.json`) to store analysis notes associated with a script and address. Notes are addable and removable.
*   **Live Re-analysis:** The side-panel will allow users to edit bytecode (as a hex string). An "Update" button will trigger a backend call to re-disassemble the edited bytes and refresh the main `descumm` and `fused` view panels.
*   **Test Case Generation:** A "Generate Test" button will create a complete `pytest` test case string based on the content of the analysis panel.

#### 3.2. Out-of-Scope for MVP

*   Real-time disassembly updates on every keystroke (MVP will use a button).
*   Directly saving generated test cases into project files.
*   Advanced note management (e.g., tagging, searching, versioning).
*   A "revert to original" button for bytecode edits (user can close and reopen).

### 4. Functional Requirements

#### FR-1: Data Persistence (Notes Database)
*   **FR-1.1 (Note Data Model):** A "Note" shall be a structured object containing:
    *   `id`: A unique identifier (e.g., UUID or `script_name:address`).
    *   `script_name`: The script the note belongs to (e.g., "room8_scrp18").
    *   `address`: The absolute address of the instruction that was clicked.
    *   `original_bytes_hex`: The original bytecode at that address.
    *   `edited_bytes_hex`: User-modified bytecode. Defaults to `original_bytes_hex`.
    *   `expected_fused_output`: The developer's target disassembly string.
    *   `user_notes`: Free-form text for observations and analysis.
*   **FR-1.2 (Storage):** All notes will be stored in a local `analysis_notes.json` file. The application will load this on startup and save it upon any changes (create, update, delete).

#### FR-2: UI Interaction & Layout
*   **FR-2.1 (Trigger):** Any line in the three main disassembly columns (Descumm, Fused, Raw) shall be clickable. Each line must be associated with the address of the instruction it represents.
*   **FR-2.2 (Side-Panel Activation):**
    *   Clicking a line opens the **Interactive Analysis Panel** on the right side of the screen.
    *   The existing three columns should shrink horizontally to make space for the panel, but remain visible as context.
*   **FR-2.3 (Modal Behavior):** While the side-panel is active, the main three disassembly columns become "inert" (e.g., using `pointer-events: none` in CSS) to prevent interaction.
*   **FR-2.4 (Note Indicators):**
    *   In the main summary list, a counter `(3)` will show the number of notes for each script.
    *   In the detail view, an icon (e.g., 📝) will appear next to any line that has an existing note. Clicking it opens that note in the side-panel.

#### FR-3: Interactive Analysis Panel (The Side-Panel)
*   **FR-3.1 (Content):** The panel shall contain the following components:
    *   **Info (Read-only):** Script Name and Address.
    *   **Bytecode Input (Editable):** A text input pre-filled with the instruction's bytecode as a hex string (e.g., `01 E8 03 43 14 00`).
    *   **Expected Output (Editable):** A text area for the user to define their desired fused disassembly output (e.g., `var_20 = 1000`).
    *   **Notes (Editable):** A multi-line text area for analysis comments.
*   **FR-3.2 (Actions):**
    *   **`[Update View]` Button:** Triggers the dynamic re-visualization (FR-4).
    *   **`[Generate Test Case]` Button:** Populates a read-only text area with a generated `pytest` test case string (FR-5).
    *   **`[Save Note]` Button:** Persists the current state of the panel to `analysis_notes.json`.
    *   **`[Delete Note]` Button:** (Visible only if editing an existing note) Removes the note.
    *   **`[Close]` Button:** Closes the panel, reverting any dynamic changes in the main view to the original state.

#### FR-4: Dynamic Re-visualization and Analysis
*   **FR-4.1 (Backend API):** A backend endpoint (e.g., `/api/disassemble`) will accept a POST request with a JSON payload: `{"bytecode_hex": "..."}`.
*   **FR-4.2 (API Response):** The endpoint will return a JSON object containing the new disassembly strings:
    ```json
    {
      "descumm_output": "...",
      "fused_output": "..."
    }
    ```
*   **FR-4.3 (Frontend Update):** When the `[Update View]` button is clicked:
    1.  The frontend sends the content of the `Bytecode (Hex)` input to the API.
    2.  Upon receiving the response, the frontend **updates the content of the main `descumm` and `fused` view panels** with the new disassembly.
    3.  The `raw` panel can be cleared or display a message like "Dynamic Analysis".

#### FR-5: Test Case Generation
*   **FR-5.1 (Logic):** The `[Generate Test Case]` button triggers a backend call or frontend logic that formats the data from the note panel into a `ScriptComparisonTestCase` string.
*   **FR-5.2 (Content):**
    *   `test_id`: Generated automatically (e.g., `user_analysis_room8_scrp18_0xADDRESS`).
    *   `bytecode`: Populated from the `Bytecode (Hex)` input.
    *   `expected_disasm_fusion_output`: Populated from the `Expected Fused Output` text area.
    *   `expected_descumm_output`: Populated from the result of the dynamic `descumm` run.

### 5. Non-Functional Requirements
*   **NFR-1 (Performance):** The dynamic re-analysis triggered by the `[Update View]` button must complete in under 1 second. This is feasible given the small size of bytecode snippets.
*   **NFR-2 (Usability):** The interaction flow must be intuitive. The visual distinction between the static context (main columns) and the interactive panel must be clear.
*   **NFR-3 (Technology Stack):**
    *   **Frontend:** Flask with Jinja2 templates. JavaScript (`fetch` API) is required for the dynamic updates.
    *   **Backend:** Python, reusing the existing `DataProvider` and disassembly logic.

### 6. Architecture & Implementation Plan

1.  **Backend:**
    *   Extend `DataProvider` with CRUD methods for `analysis_notes.json`.
    *   Implement the `/api/disassemble` endpoint to process a hex string and return new disassembly.
    *   Implement `/api/notes` endpoints for `POST` (create/update) and `DELETE` requests.

2.  **Frontend (HTML/CSS):**
    *   Modify the main `detail.html` template to include a fourth, initially hidden column for the side-panel (`<div id="analysis-panel" style="display:none;">`).
    *   Add CSS to shrink the three main columns when the panel is visible.
    *   Add a CSS class (e.g., `.inert-view`) to disable pointer events on the main columns when the panel is active.

3.  **Frontend (JavaScript):**
    *   Add `click` event listeners to all disassembly lines. Store the address and original bytes in `data-*` attributes.
    *   **On Click:**
        *   Read the `data-address` and other info from the clicked element.
        *   Populate and show the `#analysis-panel`.
        *   Apply the `.inert-view` class to the main content area.
    *   **`[Update View]` Button:**
        *   Get the hex string from the input.
        *   `fetch('/api/disassemble', { method: 'POST', ... })`.
        *   On success, update the `innerHTML` of the main `descumm` and `fused` panel `<div>`s.
    *   **`[Save Note]` / `[Delete Note]` Buttons:**
        *   `fetch('/api/notes', ...)` with the relevant note data.
        *   On success, close the panel and refresh the page or just the note indicators.
    *   **`[Close]` Button:**
        *   Hide the panel and remove the `.inert-view` class.
        *   Reload the original disassembly for the selected script to revert the view.