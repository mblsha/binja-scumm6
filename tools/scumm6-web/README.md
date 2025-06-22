# SCUMM6 Disassembly Comparison Web App

A Flask-based web interface for comparing disassembly output between the industry-standard `descumm` tool and the `pyscumm6` Binary Ninja plugin.

## Features

- **Web-based interface**: No terminal required, works in any modern browser
- **Real-time search**: Filter scripts as you type
- **Three-panel comparison**: View descumm, pyscumm6 (fused), and pyscumm6 (raw) side-by-side
- **Synchronized scrolling**: All panels scroll together for easy comparison
- **Progress tracking**: Background processing with visual progress bar
- **Match statistics**: See at a glance which scripts match and overall statistics

## Installation

```bash
cd tools/scumm6-web
pip install -r requirements.txt
```

## Usage

### Starting the server

```bash
python app.py
```

Then open your browser to: http://localhost:5000

### API Endpoints

The Flask app also provides a REST API:

- `GET /api/scripts` - List all scripts with match status
- `GET /api/scripts/<name>` - Get detailed comparison for a specific script
- `POST /api/process_all` - Process all scripts and return summary
- `GET /api/status` - Get current status of the data provider

## Architecture

- **Backend**: Flask with RESTful API
- **Frontend**: Vanilla JavaScript with modern CSS
- **Data processing**: Same comparison engine as CLI/TUI tools
- **Caching**: Processed comparisons are cached in memory

## Development

To run in development mode with auto-reload:

```bash
FLASK_ENV=development python app.py
```

## Requirements

- Python 3.8+
- DOTTDEMO.bsc6 file (Day of the Tentacle demo)
- descumm executable (built from scummvm-tools)

The app will search common locations for these files, similar to the CLI tool.

## Comparison with Other Tools

| Feature | CLI | TUI | Web |
|---------|-----|-----|-----|
| Terminal required | Yes | Yes | No |
| Visual interface | No | Yes | Yes |
| Real-time updates | No | Yes | Yes |
| Remote access | No | No | Yes |
| REST API | No | No | Yes |
| Progress tracking | No | Yes | Yes |

The web app provides the most accessible interface while maintaining all the comparison functionality of the other tools.