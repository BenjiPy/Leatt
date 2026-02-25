<div align="center">

# 🛡️ LEATT

### Data Leak Prevention for Individuals

[![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-00d4aa?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-blue?style=for-the-badge)]()

*A lightweight security application that monitors background processes to detect and prevent sensitive data leaks.*

---

</div>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Monitoring
- **Process Tracking** - Detect new/suspicious processes
- **File Watching** - Monitor sensitive folders
- **Network Analysis** - Detect large uploads
- **Registry Monitor** - Track persistence attempts (Windows)

</td>
<td width="50%">

### 🧠 Detection
- **Rules Engine** - 8 configurable rules
- **Heuristics** - 7 behavioral patterns
- **ML Detector** - Isolation Forest anomaly detection
- **PID Hijacking** - Detect process identity theft

</td>
</tr>
</table>

### 🎯 Trust System
> 70+ pre-trusted applications including Chrome, VSCode, Spotify, Discord, and more.
> Whitelist management with real-time updates.

### 🖥️ Dashboard
> Modern web interface with real-time alerts, filtering, and glassmorphism design.

---

## 🚀 Quick Start

```bash
# Clone & Setup
git clone https://github.com/BenjiPy/Leatt
cd Leatt
python -m venv venv && .\venv\Scripts\activate
pip install -r requirements.txt

# Run with web dashboard
python -m src --web
```

🌐 Dashboard available at `http://127.0.0.1:8080`

---

## 📁 Architecture

```
leatt/
├── 📂 config/
│   ├── default.yaml          # Main configuration
│   ├── rules.yaml            # Detection rules
│   ├── user.yaml             # User overrides (gitignored)
│   └── whitelist.yaml        # Custom whitelist (gitignored)
├── 📂 src/
│   ├── core/                 # Monitors (process, file, network, registry)
│   ├── detection/            # Rules, heuristics, ML
│   ├── trust/                # Whitelist & signatures
│   ├── ui/                   # Systray & notifications
│   ├── web/                  # FastAPI dashboard
│   └── utils/                # Config, DB, logging
├── 📂 data/                  # SQLite DB & ML models
└── 📄 requirements.txt
```

---

## ⚙️ Usage

| Command | Description |
|---------|-------------|
| `python -m src` | Run in background (systray only) |
| `python -m src --web` | Run with web dashboard |
| `python -m src -v` | Verbose mode |
| `python -m src --no-systray` | Background only (no UI) |
| `python run.py --web` | Alternative entry point |

---

## 🔒 Detection Layers

| Layer | Description | Examples |
|:------|:------------|:---------|
| 🎯 **Rules** | Configurable thresholds | Suspicious ports, upload limits |
| 🧩 **Heuristics** | Behavioral patterns | Exfiltration chain, credential theft |
| 🤖 **ML** | Anomaly detection | Isolation Forest algorithm |

---

## 📦 Tech Stack

<div align="center">

| Component | Library |
|:---------:|:-------:|
| Process Monitoring | `psutil` |
| File Watching | `watchdog` |
| System Tray | `pystray` |
| Notifications | `plyer` |
| Web Dashboard | `FastAPI` |
| Database | `SQLAlchemy` |
| Machine Learning | `scikit-learn` |

</div>

---

## 💻 Requirements

- **Python** 3.10+
- **OS**: Windows 10/11 or Linux (Ubuntu 22.04+)

---

## 📝 Configuration

<details>
<summary><b>config/default.yaml</b> - Main settings</summary>

- Monitoring intervals
- Watched folders (`~/Documents`, `~/Downloads`, `~/.ssh`)
- Sensitive file extensions (`.key`, `.pem`, `.env`, etc.)
- Web dashboard port

</details>

<details>
<summary><b>config/rules.yaml</b> - Detection rules</summary>

- Network upload thresholds
- Suspicious ports list
- Blocked process names
- Risk scoring thresholds

</details>

---

## ✅ Pre-trusted Applications

| Category | Apps |
|:---------|:-----|
| 🌐 Browsers | Chrome, Edge, Firefox, Brave, DuckDuckGo |
| 💻 Dev Tools | VSCode, Cursor, Node, Python, Git, Docker |
| 🎵 Apps | Spotify, Discord, Slack, Teams, Zoom, Steam |
| ☁️ Cloud | OneDrive, Notion, Obsidian |

---

<div align="center">

## 📄 License

MIT License © 2024

---

**Made with ❤️ for privacy-conscious individuals**

</div>
