"""Additional API routes for the web dashboard."""

from typing import Optional
from datetime import datetime, timedelta


def format_timedelta(td: timedelta) -> str:
    """Format a timedelta as a human-readable string."""
    seconds = int(td.total_seconds())
    
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        return f"{seconds // 3600}h"
    else:
        return f"{seconds // 86400}d"


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    if num_bytes == 0:
        return "0 B"
    
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    
    return f"{num_bytes:.1f} PB"


def severity_to_color(severity: str) -> str:
    """Map severity to color class."""
    colors = {
        "low": "#3b82f6",
        "medium": "#f59e0b",
        "high": "#ef4444",
        "critical": "#dc2626",
    }
    return colors.get(severity.lower(), "#94a3b8")
