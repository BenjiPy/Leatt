#!/usr/bin/env python3
"""
Leatt - Data Leak Prevention for individuals

Run this script to start Leatt:
    python run.py
    python run.py --web
    python run.py -v --web
    
Or run as module:
    python -m src
    python -m src --web
"""

import subprocess
import sys

if __name__ == "__main__":
    sys.exit(subprocess.call([sys.executable, "-m", "src"] + sys.argv[1:]))
