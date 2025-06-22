#!/usr/bin/env python3
"""
SCUMM6 Disassembly Comparison Web Application

A Flask-based web interface for comparing disassembly output between
descumm and pyscumm6 Binary Ninja plugin.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
import difflib
import re
from dataclasses import dataclass, asdict

from flask import Flask, render_template, jsonify, request, session
from flask_cors import CORS

# Add parent directory to path for imports
plugin_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, plugin_root)

# Set mock environment before any Binary Ninja imports
os.environ["FORCE_BINJA_MOCK"] = "1"

import src.container as container_module
from src.container import ScriptAddr, State
from src.test_utils import run_descumm_on_bytecode, run_scumm6_disassembler, run_scumm6_disassembler_with_fusion, run_scumm6_disassembler_with_fusion_details

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'scumm6-comparison-secret-key'
CORS(app)

# Global data provider instance
data_provider = None


@dataclass
class ScriptComparison:
    """Results of comparing a single script."""
    name: str
    descumm_output: str
    fused_output: str
    raw_output: str
    is_match: bool
    match_score: float
    unmatched_lines: List[str]
    line_matches: List[Dict[str, any]]  # Line-by-line match information
    fusion_spans: List[Dict[str, int]]  # Fusion span information
    bytecode_hex: str = ""  # Hex representation of the bytecode


class DataProvider:
    """Handles all data loading and processing."""

    def __init__(self, bsc6_path: Optional[Path] = None, descumm_path: Optional[Path] = None):
        self.scripts: List[ScriptAddr] = []
        self.state: Optional[State] = None
        self.bsc6_data: bytes = b""
        self.descumm_path = descumm_path
        self.bsc6_path = bsc6_path
        self.comparisons: Dict[str, ScriptComparison] = {}
        self.initialization_error = None
        self.notes_file = Path(__file__).parent / "analysis_notes.json"
        self.notes: Dict[str, dict] = self._load_notes()

    def initialize(self) -> bool:
        """Load all data and process all scripts."""
        try:
            # Find descumm if not provided
            if self.descumm_path is None:
                possible_paths = [
                    Path(__file__).parent.parent.parent / "scummvm-tools" / "descumm",
                    Path(__file__).parent.parent.parent / "descumm",
                    Path.home() / ".local" / "bin" / "descumm",
                    Path("/usr/local/bin/descumm"),
                    Path("/usr/bin/descumm"),
                ]

                for path in possible_paths:
                    if path.exists() and path.is_file():
                        self.descumm_path = path
                        break

                if self.descumm_path is None:
                    self.initialization_error = "descumm not found"
                    return False

            # Find DOTTDEMO.bsc6 if not provided
            if self.bsc6_path is None:
                possible_paths = [
                    Path(__file__).parent.parent.parent / "DOTTDEMO.bsc6",
                    Path(__file__).parent.parent.parent / "tests" / "DOTTDEMO.bsc6",
                    Path.cwd() / "DOTTDEMO.bsc6",
                ]

                for path in possible_paths:
                    if path.exists():
                        self.bsc6_path = path
                        break

                if self.bsc6_path is None:
                    self.initialization_error = "DOTTDEMO.bsc6 not found"
                    return False

            # Load the BSC6 file
            self.bsc6_data = self.bsc6_path.read_bytes()

            # Parse container
            Scumm6Disasm = container_module.ContainerParser
            result = Scumm6Disasm.decode_container(str(self.bsc6_path), self.bsc6_data)
            if result is None:
                self.initialization_error = "Failed to decode container"
                return False

            self.scripts, self.state = result
            return True

        except Exception as e:
            self.initialization_error = str(e)
            return False

    def process_script(self, script_name: str) -> Optional[ScriptComparison]:
        """Process a single script by name."""
        # Check cache first
        if script_name in self.comparisons:
            return self.comparisons[script_name]

        # Find the script
        script = None
        for s in self.scripts:
            if s.name == script_name:
                script = s
                break

        if script is None:
            return None

        # Extract bytecode
        bytecode = self.bsc6_data[script.start:script.end]

        # Generate all three outputs
        fusion_spans = []
        try:
            descumm_output = run_descumm_on_bytecode(self.descumm_path, bytecode)
            fused_output, fusion_spans = run_scumm6_disassembler_with_fusion_details(bytecode, script.start)
            raw_output = run_scumm6_disassembler(bytecode, script.start)
        except Exception as e:
            # Handle errors gracefully
            descumm_output = f"Error: {str(e)}"
            fused_output = f"Error: {str(e)}"
            raw_output = f"Error: {str(e)}"

        # Compare descumm with fused output
        is_match, match_score, unmatched_lines, line_matches = self._compare_outputs(
            descumm_output, fused_output
        )

        # Store and return comparison
        comparison = ScriptComparison(
            name=script.name,
            descumm_output=descumm_output,
            fused_output=fused_output,
            raw_output=raw_output,
            is_match=is_match,
            match_score=match_score,
            unmatched_lines=unmatched_lines,
            line_matches=line_matches,
            fusion_spans=fusion_spans,
            bytecode_hex=bytecode.hex(' ')  # Store hex representation with spaces
        )
        self.comparisons[script.name] = comparison
        return comparison

    def _normalize_line(self, line: str) -> str:
        """Normalize a line for fuzzy matching."""
        # Strip address prefixes
        line = re.sub(r'^\[[0-9A-Fa-f]+\]\s*', '', line)
        line = re.sub(r'^\([0-9A-Fa-f]+\)\s*', '', line)

        # Normalize variable names
        line = re.sub(r'localvar(\d+)', r'var_\1', line)

        # Normalize spacing
        line = ' '.join(line.split())

        return line.strip()

    def _compare_outputs(self, descumm: str, fused: str) -> tuple:
        """Compare descumm output with fused output."""
        descumm_lines = [line for line in descumm.strip().split('\n') if line.strip() and line.strip() != 'END']
        fused_lines = [line for line in fused.strip().split('\n') if line.strip()]

        # Normalize all lines
        norm_descumm = [self._normalize_line(line) for line in descumm_lines]
        norm_fused = [self._normalize_line(line) for line in fused_lines]

        # Track unmatched lines and line matches
        unmatched = []
        total_score = 0.0
        matched_count = 0
        line_matches = []

        # For each descumm line, find best match in fused
        for i, d_line in enumerate(norm_descumm):
            if not d_line:
                continue

            best_score = 0.0
            best_match_idx = -1

            for j, f_line in enumerate(norm_fused):
                if not f_line:
                    continue
                score = difflib.SequenceMatcher(None, d_line, f_line).ratio()
                if score > best_score:
                    best_score = score
                    best_match_idx = j

            line_match_info = {
                'descumm_idx': i,
                'descumm_line': descumm_lines[i],
                'normalized_descumm': d_line,
                'match_score': best_score,
                'is_match': best_score >= 0.85
            }

            if best_score >= 0.85 and best_match_idx >= 0:
                matched_count += 1
                total_score += best_score
                line_match_info['fused_idx'] = best_match_idx
                line_match_info['fused_line'] = fused_lines[best_match_idx]
                line_match_info['normalized_fused'] = norm_fused[best_match_idx]
            else:
                unmatched.append(descumm_lines[i])
                line_match_info['fused_idx'] = None
                line_match_info['fused_line'] = None

            line_matches.append(line_match_info)

        # Calculate overall match
        if len(norm_descumm) > 0:
            match_ratio = matched_count / len(norm_descumm)
            avg_score = total_score / len(norm_descumm) if len(norm_descumm) > 0 else 0
        else:
            match_ratio = 1.0
            avg_score = 1.0

        is_match = match_ratio >= 0.9

        return is_match, avg_score, unmatched, line_matches

    def _load_notes(self) -> Dict[str, dict]:
        """Load notes from JSON file."""
        if self.notes_file.exists():
            try:
                with open(self.notes_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_notes(self) -> None:
        """Save notes to JSON file."""
        with open(self.notes_file, 'w') as f:
            json.dump(self.notes, f, indent=2)
    
    def get_note(self, note_id: str) -> Optional[dict]:
        """Get a specific note by ID."""
        return self.notes.get(note_id)
    
    def save_note(self, note_data: dict) -> str:
        """Save or update a note."""
        note_id = f"{note_data['script_name']}:{note_data['address']}"
        note_data['id'] = note_id
        self.notes[note_id] = note_data
        self._save_notes()
        return note_id
    
    def delete_note(self, note_id: str) -> bool:
        """Delete a note."""
        if note_id in self.notes:
            del self.notes[note_id]
            self._save_notes()
            return True
        return False
    
    def get_notes_for_script(self, script_name: str) -> List[dict]:
        """Get all notes for a specific script."""
        return [note for note in self.notes.values() if note.get('script_name') == script_name]


# Routes
@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')


@app.route('/api/scripts')
def get_scripts():
    """Get list of all scripts."""
    if data_provider is None:
        return jsonify({'error': 'Data provider not initialized'}), 500

    # Get basic info for all scripts
    scripts = []
    for script in data_provider.scripts:
        # Check if we have comparison data
        comparison = data_provider.comparisons.get(script.name)
        
        # Count notes for this script
        notes_count = len(data_provider.get_notes_for_script(script.name))

        scripts.append({
            'name': script.name,
            'size': script.end - script.start,
            'processed': comparison is not None,
            'is_match': comparison.is_match if comparison else None,
            'match_score': comparison.match_score if comparison else None,
            'notes_count': notes_count
        })

    return jsonify({
        'scripts': scripts,
        'total': len(scripts)
    })


@app.route('/api/scripts/<script_name>')
def get_script_comparison(script_name):
    """Get comparison data for a specific script."""
    if data_provider is None:
        return jsonify({'error': 'Data provider not initialized'}), 500

    comparison = data_provider.process_script(script_name)
    if comparison is None:
        return jsonify({'error': 'Script not found'}), 404

    return jsonify(asdict(comparison))


@app.route('/api/process_all', methods=['POST'])
def process_all_scripts():
    """Process all scripts and return summary."""
    if data_provider is None:
        return jsonify({'error': 'Data provider not initialized'}), 500

    processed = 0
    matched = 0

    for script in data_provider.scripts:
        comparison = data_provider.process_script(script.name)
        if comparison:
            processed += 1
            if comparison.is_match:
                matched += 1

    return jsonify({
        'processed': processed,
        'matched': matched,
        'total': len(data_provider.scripts),
        'match_percentage': (matched / processed * 100) if processed > 0 else 0
    })


@app.route('/api/status')
def get_status():
    """Get current status of the data provider."""
    if data_provider is None:
        return jsonify({
            'initialized': False,
            'error': 'Data provider not created'
        })

    return jsonify({
        'initialized': data_provider.scripts is not None and len(data_provider.scripts) > 0,
        'error': data_provider.initialization_error,
        'script_count': len(data_provider.scripts) if data_provider.scripts else 0,
        'processed_count': len(data_provider.comparisons)
    })


@app.route('/api/disassemble', methods=['POST'])
def disassemble_bytecode():
    """Disassemble arbitrary bytecode for dynamic analysis."""
    try:
        data = request.get_json()
        if not data or 'bytecode_hex' not in data:
            return jsonify({'error': 'Missing bytecode_hex parameter'}), 400
        
        # Parse hex string to bytes
        hex_string = data['bytecode_hex'].strip()
        # Remove spaces if present
        hex_string = hex_string.replace(' ', '')
        
        # Convert hex string to bytes
        try:
            bytecode = bytes.fromhex(hex_string)
        except ValueError as e:
            return jsonify({'error': f'Invalid hex string: {str(e)}'}), 400
        
        if not bytecode:
            return jsonify({'error': 'Empty bytecode'}), 400
        
        # Run disassemblers
        try:
            descumm_output = run_descumm_on_bytecode(data_provider.descumm_path, bytecode)
            fused_output, _ = run_scumm6_disassembler_with_fusion_details(bytecode, 0)
            raw_output = run_scumm6_disassembler(bytecode, 0)
        except Exception as e:
            return jsonify({'error': f'Disassembly failed: {str(e)}'}), 500
        
        return jsonify({
            'descumm_output': descumm_output,
            'fused_output': fused_output,
            'raw_output': raw_output
        })
        
    except Exception as e:
        return jsonify({'error': f'Internal error: {str(e)}'}), 500


@app.route('/api/notes', methods=['GET', 'POST'])
def handle_notes():
    """Handle notes CRUD operations."""
    if data_provider is None:
        return jsonify({'error': 'Data provider not initialized'}), 500
    
    if request.method == 'GET':
        # Get notes for a specific script
        script_name = request.args.get('script_name')
        if script_name:
            notes = data_provider.get_notes_for_script(script_name)
        else:
            notes = list(data_provider.notes.values())
        return jsonify({'notes': notes})
    
    elif request.method == 'POST':
        # Create or update a note
        try:
            note_data = request.get_json()
            if not note_data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validate required fields
            required_fields = ['script_name', 'address']
            for field in required_fields:
                if field not in note_data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Save the note
            note_id = data_provider.save_note(note_data)
            return jsonify({'id': note_id, 'message': 'Note saved successfully'})
            
        except Exception as e:
            return jsonify({'error': f'Failed to save note: {str(e)}'}), 500


@app.route('/api/notes/<note_id>', methods=['GET', 'DELETE'])
def handle_note(note_id):
    """Handle individual note operations."""
    if data_provider is None:
        return jsonify({'error': 'Data provider not initialized'}), 500
    
    if request.method == 'GET':
        note = data_provider.get_note(note_id)
        if note:
            return jsonify(note)
        return jsonify({'error': 'Note not found'}), 404
    
    elif request.method == 'DELETE':
        if data_provider.delete_note(note_id):
            return jsonify({'message': 'Note deleted successfully'})
        return jsonify({'error': 'Note not found'}), 404


@app.route('/api/generate_test', methods=['POST'])
def generate_test_case():
    """Generate a pytest test case from analysis data."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract data
        script_name = data.get('script_name', 'unknown')
        address = data.get('address', '0x0000')
        bytecode_hex = data.get('bytecode_hex', '')
        expected_fused = data.get('expected_fused_output', '')
        descumm_output = data.get('descumm_output', '')
        
        # Generate terse AI-friendly test case instruction
        clean_bytes = bytecode_hex.replace(' ', '').upper()
        test_case = f'''Add `{clean_bytes}` to the test_descumm_comparison.py as a new test case, with expected descumm output `{descumm_output.strip()}`. Want the fused disassembly to be similar to `{expected_fused.strip()}`.'''
        
        return jsonify({'test_case': test_case})
        
    except Exception as e:
        return jsonify({'error': f'Failed to generate test: {str(e)}'}), 500


# Initialize data provider on startup
def init_app():
    """Initialize the application."""
    global data_provider
    data_provider = DataProvider()
    if not data_provider.initialize():
        print(f"Warning: Failed to initialize data provider: {data_provider.initialization_error}")
    else:
        print(f"Loaded {len(data_provider.scripts)} scripts from DOTTDEMO.bsc6")


if __name__ == '__main__':
    init_app()
    app.run(debug=True, host='0.0.0.0', port=6001)
