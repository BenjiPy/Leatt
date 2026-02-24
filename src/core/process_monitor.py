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
from ..trust.whitelist import Whitelist

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
        self._whitelist = Whitelist()
        
        self._known_processes: dict[int, ProcessInfo] = {}
        self._previous_io: dict[int, tuple[int, int]] = {}
        self._previous_net: dict[int, tuple[int, int]] = {}
        self._pid_fingerprints: dict[int, tuple[str, str, float]] = {}
    
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
        if info.path and info.path not in ("Registry", "MemCompression", "System", "Idle"):
            expanded_path = PlatformUtils.expand_path(info.path)
            if expanded_path.exists():
                info.hash_sha256 = PlatformUtils.compute_file_hash(expanded_path)
        
        is_trusted = self._whitelist.is_trusted(
            name=info.name,
            path=info.path,
            hash_sha256=info.hash_sha256,
        )
        info.is_trusted = is_trusted
        
        self._pid_fingerprints[info.pid] = (
            info.name,
            info.path or "",
            info.create_time,
        )
        
        info.risk_score = self._calculate_risk_score(info)
        
        self._save_process_to_db(info)
        
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
                    "risk_score": info.risk_score,
                    "process_age_seconds": process_age_seconds,
                },
            )
            self.event_queue.put(event)
            logger.debug(f"New untrusted process detected: {info.name} (PID: {info.pid}, risk: {info.risk_score:.0f})")
    
    def _check_pid_hijacking(self, info: ProcessInfo) -> bool:
        """Check if a PID has been hijacked by a different process."""
        if info.pid not in self._pid_fingerprints:
            return False
        
        old_name, old_path, old_create_time = self._pid_fingerprints[info.pid]
        
        if info.create_time != old_create_time:
            from .daemon import MonitorEvent
            event = MonitorEvent(
                source="process_monitor",
                event_type="pid_hijack",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "path": info.path,
                    "old_name": old_name,
                    "old_path": old_path,
                    "is_trusted": info.is_trusted,
                    "alert": "PID reused by different process - possible hijacking attempt",
                },
                risk_score=80.0,
            )
            self.event_queue.put(event)
            logger.warning(f"PID hijacking detected: PID {info.pid} was {old_name}, now {info.name}")
            
            self._pid_fingerprints[info.pid] = (info.name, info.path or "", info.create_time)
            return True
        
        if info.name != old_name or (info.path or "") != old_path:
            from .daemon import MonitorEvent
            event = MonitorEvent(
                source="process_monitor",
                event_type="process_mutation",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "path": info.path,
                    "old_name": old_name,
                    "old_path": old_path,
                    "is_trusted": info.is_trusted,
                    "alert": "Process identity changed - possible code injection",
                },
                risk_score=90.0,
            )
            self.event_queue.put(event)
            logger.warning(f"Process mutation detected: PID {info.pid} changed from {old_name} to {info.name}")
            return True
        
        return False
    
    def _calculate_risk_score(self, info: ProcessInfo) -> float:
        """Calculate risk score for a process.
        
        Even trusted processes can have risk scores if they exhibit
        anomalous behavior (potential hijacking/injection).
        """
        score = 0.0
        
        if info.is_trusted:
            if info.num_connections > 100:
                score += min(30.0, (info.num_connections - 100) * 0.3)
            
            if info.write_bytes > 500 * 1024 * 1024:
                score += 20.0
            
            if info.cpu_percent > 90.0:
                score += 10.0
            
            return min(50.0, score)
        
        if not info.path:
            score += 20.0
        
        if info.num_connections > 10:
            score += min(20.0, info.num_connections * 0.5)
        
        if info.memory_percent > 5.0:
            score += min(15.0, info.memory_percent)
        
        if info.cpu_percent > 50.0:
            score += min(15.0, (info.cpu_percent - 50) * 0.3)
        
        if info.write_bytes > 50 * 1024 * 1024:
            score += 15.0
        
        if info.cmdline:
            cmdline_str = ' '.join(info.cmdline).lower()
            suspicious_patterns = ['powershell', 'cmd', 'wget', 'curl', 'invoke-', 'bypass', 'hidden', 
                                   'encodedcommand', 'base64', '-enc', '-e ', 'downloadstring', 
                                   'iex', 'invoke-expression', 'net user', 'mimikatz']
            for pattern in suspicious_patterns:
                if pattern in cmdline_str:
                    score += 15.0
                    break
        
        return min(100.0, score)
    
    def _save_process_to_db(self, info: ProcessInfo) -> None:
        """Save process record to database with trust and risk info."""
        with self.db.get_session() as session:
            from ..utils.database import ProcessRecord
            existing = session.query(ProcessRecord).filter_by(
                name=info.name, path=info.path
            ).first()
            
            if existing:
                existing.last_seen = __import__('datetime').datetime.utcnow()
                existing.pid = info.pid
                existing.is_trusted = info.is_trusted
                existing.risk_score = info.risk_score
                session.commit()
            else:
                process = ProcessRecord(
                    pid=info.pid,
                    name=info.name,
                    path=info.path,
                    user=info.user,
                    hash_sha256=info.hash_sha256,
                    is_trusted=info.is_trusted,
                    risk_score=info.risk_score,
                )
                session.add(process)
                session.commit()
    
    def _check_process_behavior(self, info: ProcessInfo) -> None:
        """Analyze process behavior changes.
        
        Monitors ALL processes including trusted ones for anomalous behavior.
        Trusted processes have higher thresholds but are still monitored
        to detect potential hijacking or code injection.
        """
        from .daemon import MonitorEvent
        
        prev_io = self._previous_io.get(info.pid, (0, 0))
        io_delta_read = info.read_bytes - prev_io[0]
        io_delta_write = info.write_bytes - prev_io[1]
        self._previous_io[info.pid] = (info.read_bytes, info.write_bytes)
        
        mb_threshold_untrusted = 10 * 1024 * 1024
        mb_threshold_trusted = 100 * 1024 * 1024
        mb_threshold = mb_threshold_trusted if info.is_trusted else mb_threshold_untrusted
        
        if io_delta_read > mb_threshold or io_delta_write > mb_threshold:
            severity = "anomaly_trusted" if info.is_trusted else "high_io"
            event = MonitorEvent(
                source="process_monitor",
                event_type=severity,
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "path": info.path,
                    "read_bytes_delta": io_delta_read,
                    "write_bytes_delta": io_delta_write,
                    "is_trusted": info.is_trusted,
                    "alert": f"Unusual I/O activity from {'trusted' if info.is_trusted else 'untrusted'} process",
                },
                risk_score=40.0 if info.is_trusted else 60.0,
            )
            self.event_queue.put(event)
            logger.warning(f"High I/O from {'TRUSTED' if info.is_trusted else 'untrusted'}: {info.name} - Write: {io_delta_write / 1024 / 1024:.1f}MB")
        
        conn_threshold_untrusted = 50
        conn_threshold_trusted = 200
        conn_threshold = conn_threshold_trusted if info.is_trusted else conn_threshold_untrusted
        
        if info.num_connections > conn_threshold:
            event = MonitorEvent(
                source="process_monitor",
                event_type="many_connections",
                data={
                    "pid": info.pid,
                    "process_name": info.name,
                    "path": info.path,
                    "num_connections": info.num_connections,
                    "is_trusted": info.is_trusted,
                    "alert": f"Excessive network connections from {'trusted' if info.is_trusted else 'untrusted'} process",
                },
                risk_score=30.0 if info.is_trusted else 50.0,
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
                    hijacked = self._check_pid_hijacking(info)
                    if hijacked:
                        self._check_new_process(info)
                    else:
                        info.is_trusted = self._whitelist.is_trusted(info.name, info.path)
                        info.risk_score = self._calculate_risk_score(info)
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
