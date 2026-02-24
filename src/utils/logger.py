"""Logging configuration for Leatt."""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

_loggers: dict[str, logging.Logger] = {}


def setup_logging(
    log_level: str = "INFO",
    log_to_file: bool = True,
    log_dir: Optional[Path] = None,
) -> None:
    """Configure logging for the application."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    handlers: list[logging.Handler] = []
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))
    handlers.append(console_handler)
    
    if log_to_file:
        if log_dir is None:
            log_dir = Path(__file__).parent.parent.parent / "data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"leatt_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        handlers.append(file_handler)
    
    root_logger = logging.getLogger("leatt")
    root_logger.setLevel(level)
    root_logger.handlers = handlers


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module."""
    if name not in _loggers:
        logger = logging.getLogger(f"leatt.{name}")
        _loggers[name] = logger
    return _loggers[name]
