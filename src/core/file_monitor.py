"""File system monitoring module."""

import threading
from pathlib import Path
from typing import Optional
from queue import Queue

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileDeletedEvent,
    DirCreatedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    DirDeletedEvent,
)

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..utils.database import get_database

logger = get_logger("file_monitor")


class LeattFileHandler(FileSystemEventHandler):
    """Handle file system events."""
    
    def __init__(self, event_queue: Queue, sensitive_extensions: list[str]):
        super().__init__()
        self.event_queue = event_queue
        self.sensitive_extensions = [ext.lower() for ext in sensitive_extensions]
        self.db = get_database()
    
    def _is_sensitive_file(self, path: str) -> bool:
        """Check if a file is considered sensitive."""
        path_lower = path.lower()
        return any(path_lower.endswith(ext) for ext in self.sensitive_extensions)
    
    def _create_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None) -> None:
        """Create and queue a file event."""
        from .daemon import MonitorEvent
        
        is_sensitive = self._is_sensitive_file(src_path)
        
        data = {
            "file_path": src_path,
            "event_type": event_type,
            "is_sensitive": is_sensitive,
        }
        
        if dest_path:
            data["dest_path"] = dest_path
            if self._is_sensitive_file(dest_path):
                is_sensitive = True
                data["is_sensitive"] = True
        
        self.db.add_file_event(
            file_path=src_path,
            event_type=event_type,
            is_sensitive=is_sensitive,
        )
        
        if is_sensitive:
            event = MonitorEvent(
                source="file_monitor",
                event_type=f"file_{event_type}",
                data=data,
                risk_score=30.0 if is_sensitive else 0.0,
            )
            self.event_queue.put(event)
            logger.warning(f"Sensitive file {event_type}: {src_path}")
        else:
            logger.debug(f"File {event_type}: {src_path}")
    
    def on_created(self, event):
        if not isinstance(event, DirCreatedEvent):
            self._create_event("created", event.src_path)
    
    def on_modified(self, event):
        if not isinstance(event, DirModifiedEvent):
            self._create_event("modified", event.src_path)
    
    def on_moved(self, event):
        if not isinstance(event, DirMovedEvent):
            self._create_event("moved", event.src_path, event.dest_path)
    
    def on_deleted(self, event):
        if not isinstance(event, DirDeletedEvent):
            self._create_event("deleted", event.src_path)


class FileMonitor:
    """Monitor file system changes in sensitive folders."""
    
    def __init__(
        self,
        event_queue: Queue,
        stop_event: threading.Event,
        watched_folders: Optional[list[Path]] = None,
    ):
        self.event_queue = event_queue
        self.stop_event = stop_event
        
        config = get_config()
        self.sensitive_extensions = config.sensitive_extensions
        
        if watched_folders:
            self.watched_folders = watched_folders
        else:
            self.watched_folders = [
                Path.home() / "Documents",
                Path.home() / "Downloads",
                Path.home() / "Desktop",
            ]
        
        self._observer: Optional[Observer] = None
        self._handler: Optional[LeattFileHandler] = None
    
    def start(self) -> None:
        """Start monitoring file system changes."""
        logger.info("File monitor started")
        
        self._handler = LeattFileHandler(
            event_queue=self.event_queue,
            sensitive_extensions=self.sensitive_extensions,
        )
        
        self._observer = Observer()
        
        for folder in self.watched_folders:
            if folder.exists() and folder.is_dir():
                self._observer.schedule(
                    self._handler,
                    str(folder),
                    recursive=True,
                )
                logger.info(f"Watching folder: {folder}")
            else:
                logger.warning(f"Folder not found, skipping: {folder}")
        
        self._observer.start()
        
        while not self.stop_event.is_set():
            self.stop_event.wait(1.0)
        
        self.stop()
        logger.info("File monitor stopped")
    
    def stop(self) -> None:
        """Stop file monitoring."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None
    
    def add_watch_folder(self, folder: Path) -> bool:
        """Add a folder to watch list."""
        if folder.exists() and folder.is_dir():
            self.watched_folders.append(folder)
            if self._observer and self._handler:
                self._observer.schedule(
                    self._handler,
                    str(folder),
                    recursive=True,
                )
            logger.info(f"Added watch folder: {folder}")
            return True
        return False
    
    def remove_watch_folder(self, folder: Path) -> bool:
        """Remove a folder from watch list."""
        if folder in self.watched_folders:
            self.watched_folders.remove(folder)
            logger.info(f"Removed watch folder: {folder}")
            return True
        return False
