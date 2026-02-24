"""Network activity monitoring module."""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional
from queue import Queue
from collections import defaultdict

import psutil

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..utils.database import get_database

logger = get_logger("network_monitor")


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    pid: int
    process_name: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    family: str


@dataclass
class ProcessNetworkStats:
    """Network statistics for a process."""
    pid: int
    process_name: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    connections: list[ConnectionInfo] = field(default_factory=list)
    last_update: float = field(default_factory=time.time)


class NetworkMonitor:
    """Monitor network connections and data transfers."""
    
    def __init__(
        self,
        event_queue: Queue,
        stop_event: threading.Event,
        interval: int = 3,
    ):
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.interval = interval
        
        self.config = get_config()
        self.db = get_database()
        
        self._process_stats: dict[int, ProcessNetworkStats] = {}
        self._upload_tracking: dict[int, list[tuple[float, int]]] = defaultdict(list)
        
        self.suspicious_ports = set(self.config.suspicious_ports)
        self.max_upload_bytes_per_min = self.config.max_upload_mb_per_min * 1024 * 1024
    
    def _get_connections(self) -> list[ConnectionInfo]:
        """Get all network connections with process info."""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid is None or conn.pid == 0:
                    continue
                
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"
                
                local_addr = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                remote_addr = conn.raddr.ip if conn.raddr else ""
                remote_port = conn.raddr.port if conn.raddr else 0
                
                connections.append(ConnectionInfo(
                    pid=conn.pid,
                    process_name=process_name,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    status=conn.status,
                    family="ipv4" if conn.family.name == "AF_INET" else "ipv6",
                ))
        
        except (psutil.AccessDenied, OSError) as e:
            logger.debug(f"Error getting connections: {e}")
        
        return connections
    
    def _get_network_io(self) -> dict[int, tuple[int, int]]:
        """Get network I/O per process (bytes_sent, bytes_recv)."""
        io_stats = {}
        
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                conns = proc.net_connections()
                io = proc.io_counters()
                io_stats[proc.pid] = (io.write_bytes, io.read_bytes)
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        
        return io_stats
    
    def _check_suspicious_connection(self, conn: ConnectionInfo) -> None:
        """Check if a connection is suspicious."""
        from .daemon import MonitorEvent
        
        if conn.remote_port in self.suspicious_ports:
            event = MonitorEvent(
                source="network_monitor",
                event_type="suspicious_port",
                data={
                    "pid": conn.pid,
                    "process_name": conn.process_name,
                    "remote_address": conn.remote_address,
                    "remote_port": conn.remote_port,
                    "local_port": conn.local_port,
                },
                risk_score=60.0,
            )
            self.event_queue.put(event)
            logger.warning(
                f"Suspicious port connection: {conn.process_name} -> "
                f"{conn.remote_address}:{conn.remote_port}"
            )
            
            self.db.add_network_event(
                process_pid=conn.pid,
                process_name=conn.process_name,
                remote_address=conn.remote_address,
                remote_port=conn.remote_port,
            )
    
    def _check_upload_rate(self, pid: int, process_name: str, bytes_sent: int) -> None:
        """Check if upload rate exceeds threshold."""
        from .daemon import MonitorEvent
        
        current_time = time.time()
        self._upload_tracking[pid].append((current_time, bytes_sent))
        
        cutoff_time = current_time - 60
        self._upload_tracking[pid] = [
            (t, b) for t, b in self._upload_tracking[pid]
            if t > cutoff_time
        ]
        
        if len(self._upload_tracking[pid]) >= 2:
            oldest = self._upload_tracking[pid][0]
            newest = self._upload_tracking[pid][-1]
            bytes_in_window = newest[1] - oldest[1]
            
            if bytes_in_window > self.max_upload_bytes_per_min:
                mb_uploaded = bytes_in_window / (1024 * 1024)
                event = MonitorEvent(
                    source="network_monitor",
                    event_type="high_upload",
                    data={
                        "pid": pid,
                        "process_name": process_name,
                        "bytes_uploaded": bytes_in_window,
                        "mb_uploaded": round(mb_uploaded, 2),
                        "threshold_mb": self.config.max_upload_mb_per_min,
                    },
                    risk_score=70.0,
                )
                self.event_queue.put(event)
                logger.warning(
                    f"High upload rate: {process_name} uploaded {mb_uploaded:.2f} MB in 1 min"
                )
    
    def _scan_network(self) -> None:
        """Scan network activity."""
        connections = self._get_connections()
        
        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.remote_address:
                self._check_suspicious_connection(conn)
        
        current_io = self._get_network_io()
        
        for pid, (bytes_sent, bytes_recv) in current_io.items():
            if pid in self._process_stats:
                prev_stats = self._process_stats[pid]
                delta_sent = bytes_sent - prev_stats.bytes_sent
                
                if delta_sent > 0:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = prev_stats.process_name
                    
                    self._check_upload_rate(pid, process_name, bytes_sent)
                
                self._process_stats[pid].bytes_sent = bytes_sent
                self._process_stats[pid].bytes_recv = bytes_recv
                self._process_stats[pid].last_update = time.time()
            else:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"
                
                self._process_stats[pid] = ProcessNetworkStats(
                    pid=pid,
                    process_name=process_name,
                    bytes_sent=bytes_sent,
                    bytes_recv=bytes_recv,
                )
        
        stale_pids = [
            pid for pid, stats in self._process_stats.items()
            if time.time() - stats.last_update > 300
        ]
        for pid in stale_pids:
            del self._process_stats[pid]
            self._upload_tracking.pop(pid, None)
    
    def start(self) -> None:
        """Start the network monitor loop."""
        logger.info("Network monitor started")
        
        while not self.stop_event.is_set():
            try:
                self._scan_network()
            except Exception as e:
                logger.error(f"Error scanning network: {e}")
            
            self.stop_event.wait(self.interval)
        
        logger.info("Network monitor stopped")
    
    def stop(self) -> None:
        """Stop the network monitor."""
        pass
    
    def get_active_connections(self) -> list[ConnectionInfo]:
        """Get current active connections."""
        return self._get_connections()
    
    def get_process_stats(self, pid: int) -> Optional[ProcessNetworkStats]:
        """Get network stats for a specific process."""
        return self._process_stats.get(pid)
