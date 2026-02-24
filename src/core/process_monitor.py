"""Process monitoring module."""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional
from queue import Queue

import psutil

from ..utils.logger import get_logger
from ..utils.platform import PlatformUtils
from ..utils.database import get_database

logger = get_logger("process_monitor")


@dataclass
class ProcessInfo:
    """Information about a monitored process."""
    pid: int
    name: str
    path: Optional[str] = None
    user: Optional[str] = None
    cmdline: list[str] = field(default_factory=list)
    create_time: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    num_connections: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    read_bytes: int = 0
    write_bytes: int = 0
    is_trusted: bool = False
    risk_score: float = 0.0
    hash_sha256: Optional[str] = None


class ProcessMonitor:
    """Monitor running processes and their behavior."""
    
    def __init__(
        self,
        event_queue: Queue,
        stop_event: threading.Event,
        interval: int = 5,
    ):
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.interval = interval
        
        self.db = get_database()
        
        self._known_processes: dict[int, ProcessInfo] = {}
        self._previous_io: dict[int, tuple[int, int]] = {}
        self._previous_net: dict[int, tuple[int, int]] = {}
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Extract information from a psutil Process object."""
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                
                try:
                    path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    path = None
                
                try:
                    user = proc.username()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    user = None
                
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = []
                
                try:
                    create_time = proc.create_time()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    create_time = 0.0
                
                try:
                    cpu_percent = proc.cpu_percent()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cpu_percent = 0.0
                
                try:
                    memory_percent = proc.memory_percent()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    memory_percent = 0.0
                
                try:
                    connections = proc.net_connections()
                    num_connections = len(connections)
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    num_connections = 0
                
                bytes_sent = 0
                bytes_recv = 0
                
                try:
                    io = proc.io_counters()
                    read_bytes = io.read_bytes
                    write_bytes = io.write_bytes
                except (psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
                    read_bytes = 0
                    write_bytes = 0
                
                return ProcessInfo(
                    pid=pid,
                    name=name,
                    path=path,
                    user=user,
                    cmdline=cmdline,
                    create_time=create_time,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    num_connections=num_connections,
                    bytes_sent=bytes_sent,
                    bytes_recv=bytes_recv,
                    read_bytes=read_bytes,
                    write_bytes=write_bytes,
                )
        
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
    
    def _check_new_process(self, info: ProcessInfo) -> None:
        """Handle a newly detected process."""
        is_trusted = self.db.is_process_trusted(
            name=info.name,
            path=info.path,
        )
        info.is_trusted = is_trusted
        
        if info.path and info.path not in ("Registry", "MemCompression", "System", "Idle"):
            expanded_path = PlatformUtils.expand_path(info.path)
            if expanded_path.exists():
                info.hash_sha256 = PlatformUtils.compute_file_hash(expanded_path)
        
        self.db.add_process(
            pid=info.pid,
            name=info.name,
            path=info.path,
            user=info.user,
            hash_sha256=info.hash_sha256,
        )
        
        process_age_seconds = time.time() - info.create_time if info.create_time > 0 else float('inf')
        is_recently_started = process_age_seconds < 60
        
        if not is_trusted and is_recently_started:
            from .daemon import MonitorEvent
            event = MonitorEvent(
                source="process_monitor",
                event_type="new_process",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "path": info.path,
                    "user": info.user,
                    "cmdline": info.cmdline,
                    "is_trusted": is_trusted,
                    "process_age_seconds": process_age_seconds,
                },
            )
            self.event_queue.put(event)
            logger.debug(f"New untrusted process detected: {info.name} (PID: {info.pid}, age: {process_age_seconds:.0f}s)")
    
    def _check_process_behavior(self, info: ProcessInfo) -> None:
        """Analyze process behavior changes."""
        from .daemon import MonitorEvent
        
        prev_io = self._previous_io.get(info.pid, (0, 0))
        io_delta_read = info.read_bytes - prev_io[0]
        io_delta_write = info.write_bytes - prev_io[1]
        self._previous_io[info.pid] = (info.read_bytes, info.write_bytes)
        
        mb_threshold = 10 * 1024 * 1024
        if io_delta_read > mb_threshold or io_delta_write > mb_threshold:
            event = MonitorEvent(
                source="process_monitor",
                event_type="high_io",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "read_bytes_delta": io_delta_read,
                    "write_bytes_delta": io_delta_write,
                    "is_trusted": info.is_trusted,
                },
            )
            self.event_queue.put(event)
            logger.debug(f"High I/O detected: {info.name} - Read: {io_delta_read}, Write: {io_delta_write}")
        
        if info.num_connections > 50:
            event = MonitorEvent(
                source="process_monitor",
                event_type="many_connections",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "num_connections": info.num_connections,
                    "is_trusted": info.is_trusted,
                },
            )
            self.event_queue.put(event)
    
    def _scan_processes(self) -> None:
        """Scan all running processes."""
        current_pids = set()
        
        for proc in psutil.process_iter():
            try:
                info = self._get_process_info(proc)
                if info is None:
                    continue
                
                current_pids.add(info.pid)
                
                if info.pid not in self._known_processes:
                    self._check_new_process(info)
                else:
                    info.is_trusted = self._known_processes[info.pid].is_trusted
                    self._check_process_behavior(info)
                
                self._known_processes[info.pid] = info
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        terminated = set(self._known_processes.keys()) - current_pids
        for pid in terminated:
            proc_info = self._known_processes.pop(pid, None)
            self._previous_io.pop(pid, None)
            self._previous_net.pop(pid, None)
            if proc_info:
                logger.debug(f"Process terminated: {proc_info.name} (PID: {pid})")
    
    def start(self) -> None:
        """Start the process monitor loop."""
        logger.info("Process monitor started")
        
        while not self.stop_event.is_set():
            try:
                self._scan_processes()
            except Exception as e:
                logger.error(f"Error scanning processes: {e}")
            
            self.stop_event.wait(self.interval)
        
        logger.info("Process monitor stopped")
    
    def stop(self) -> None:
        """Stop the process monitor."""
        pass
    
    def get_process_by_pid(self, pid: int) -> Optional[ProcessInfo]:
        """Get cached process info by PID."""
        return self._known_processes.get(pid)
    
    def get_all_processes(self) -> list[ProcessInfo]:
        """Get all known processes."""
        return list(self._known_processes.values())
