# Leatt - Data Leak Prevention

A lightweight security application for individuals that monitors background processes to detect and prevent sensitive data leaks.

## Features

- **Process Monitoring**: Track running processes, detect new/suspicious ones, compute file hashes
- **File Monitoring**: Watch sensitive folders (Documents, Downloads, .ssh) for access to critical files
- **Network Monitoring**: Detect large uploads, suspicious ports, multiple destinations
- **Registry Monitoring** (Windows): Monitor startup keys for persistence attempts
- **Trust System**: Whitelist with 70+ pre-trusted apps, process signatures, learning mode
- **Detection Engine**: Rules-based + heuristic patterns + ML anomaly detection (Isolation Forest)
- **Web Dashboard**: Real-time alerts, process list, network/file events
- **System Tray**: Lightweight UI with notifications

## Architecture

```
leatt/
├── config/
│   ├── default.yaml          # Main configuration
│   └── rules.yaml            # Detection rules
├── src/
│   ├── main.py               # Entry point
│   ├── __main__.py           # Module runner
│   ├── core/
│   │   ├── daemon.py         # Main orchestrator
│   │   ├── process_monitor.py
│   │   ├── file_monitor.py
│   │   ├── network_monitor.py
│   │   └── registry_monitor.py
│   ├── detection/
│   │   ├── rules_engine.py   # Rule-based detection
│   │   ├── heuristics.py     # Behavioral analysis
│   │   └── ml_detector.py    # Isolation Forest
│   ├── trust/
│   │   ├── whitelist.py      # Trusted processes
│   │   ├── process_signature.py
│   │   └── learning.py       # Baseline learning
│   ├── ui/
│   │   ├── systray.py        # System tray app
│   │   └── notifications.py
│   ├── web/
│   │   └── app.py            # FastAPI dashboard
│   └── utils/
│       ├── config.py
│       ├── database.py       # SQLite storage
│       ├── logger.py
│       └── platform.py       # OS abstraction
├── tests/                    # Unit tests
├── data/                     # SQLite DB & ML models (gitignored)
├── requirements.txt
├── setup.py
└── run.py
```

## Installation

```bash
# Clone the repository
git clone https://github.com/BenjiPy/Leatt
cd leatt

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Linux

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run Leatt
python -m src

# With web dashboard
python -m src --web

# Verbose mode
python -m src -v

# Without systray (background only)
python -m src --no-systray

# Alternative
python run.py --web
```

The web dashboard is available at `http://127.0.0.1:8080` when enabled.

## Configuration

### `config/default.yaml`
- Monitoring intervals
- Watched folders
- Sensitive file extensions
- Registry keys to monitor
- Web dashboard settings

### `config/rules.yaml`
- Network upload thresholds
- Suspicious ports
- Blocked process names
- Heuristic patterns
- Risk scoring thresholds

## Detection Layers

| Layer | Description |
|-------|-------------|
| **Rules Engine** | 8 configurable rules (suspicious ports, upload limits, etc.) |
| **Heuristics** | 7 behavioral patterns (exfiltration chain, credential theft, etc.) |
| **ML Detector** | Isolation Forest for anomaly detection (optional) |

## Pre-trusted Applications

The whitelist includes 70+ common applications:
- **Browsers**: Chrome, Edge, Firefox, Brave, DuckDuckGo
- **Dev Tools**: VSCode, Cursor, Node, Python, Git, Docker
- **Apps**: Spotify, Discord, Slack, Teams, Zoom, Steam, OneDrive, Notion, Obsidian

## Requirements

- Python 3.10+
- Windows 10/11 or Linux (Ubuntu 22.04+)

## Tech Stack

| Component | Library |
|-----------|---------|
| Process monitoring | psutil |
| File monitoring | watchdog |
| System tray | pystray + Pillow |
| Notifications | plyer |
| Web dashboard | FastAPI + uvicorn |
| Database | SQLite + SQLAlchemy |
| ML | scikit-learn |
| Config | PyYAML |

## License

MIT License
