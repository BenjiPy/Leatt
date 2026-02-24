"""Learning engine for establishing baseline behavior."""

import time
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..utils.database import get_database

logger = get_logger("learning")


@dataclass
class ProcessBehavior:
    """Learned behavior profile for a process."""
    name: str
    path: Optional[str] = None
    
    avg_cpu_percent: float = 0.0
    avg_memory_percent: float = 0.0
    avg_connections: float = 0.0
    avg_io_read_bytes: float = 0.0
    avg_io_write_bytes: float = 0.0
    
    max_cpu_percent: float = 0.0
    max_memory_percent: float = 0.0
    max_connections: int = 0
    max_io_read_bytes: int = 0
    max_io_write_bytes: int = 0
    
    typical_ports: set[int] = field(default_factory=set)
    typical_destinations: set[str] = field(default_factory=set)
    
    sample_count: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class LearningStats:
    """Statistics about the learning process."""
    start_time: datetime
    duration_days: int
    processes_learned: int
    total_samples: int
    is_complete: bool


class LearningEngine:
    """Learn normal behavior patterns during learning mode."""
    
    def __init__(self):
        self.config = get_config()
        self.db = get_database()
        
        self._behaviors: dict[str, ProcessBehavior] = {}
        self._learning_start: Optional[datetime] = None
        self._learning_duration = timedelta(days=self.config.get("app.learning_duration_days", 7))
        
        self._is_learning = self.config.learning_mode
        
        if self._is_learning:
            self._learning_start = datetime.utcnow()
            logger.info(f"Learning mode started, will run for {self._learning_duration.days} days")
    
    @property
    def is_learning(self) -> bool:
        """Check if still in learning mode."""
        if not self._is_learning:
            return False
        
        if self._learning_start is None:
            return False
        
        elapsed = datetime.utcnow() - self._learning_start
        if elapsed >= self._learning_duration:
            self._is_learning = False
            logger.info("Learning mode completed")
            return False
        
        return True
    
    @property
    def learning_progress(self) -> float:
        """Get learning progress as percentage (0-100)."""
        if not self._is_learning or self._learning_start is None:
            return 100.0
        
        elapsed = datetime.utcnow() - self._learning_start
        progress = (elapsed.total_seconds() / self._learning_duration.total_seconds()) * 100
        return min(100.0, progress)
    
    def _get_behavior_key(self, name: str, path: Optional[str] = None) -> str:
        """Generate key for behavior lookup."""
        return f"{name.lower()}:{path or ''}"
    
    def record_sample(
        self,
        name: str,
        path: Optional[str] = None,
        cpu_percent: float = 0.0,
        memory_percent: float = 0.0,
        num_connections: int = 0,
        io_read_bytes: int = 0,
        io_write_bytes: int = 0,
        remote_ports: Optional[list[int]] = None,
        remote_addresses: Optional[list[str]] = None,
    ) -> None:
        """Record a behavior sample for a process."""
        if not self.is_learning:
            return
        
        key = self._get_behavior_key(name, path)
        
        if key not in self._behaviors:
            self._behaviors[key] = ProcessBehavior(name=name, path=path)
        
        behavior = self._behaviors[key]
        n = behavior.sample_count
        
        behavior.avg_cpu_percent = (behavior.avg_cpu_percent * n + cpu_percent) / (n + 1)
        behavior.avg_memory_percent = (behavior.avg_memory_percent * n + memory_percent) / (n + 1)
        behavior.avg_connections = (behavior.avg_connections * n + num_connections) / (n + 1)
        behavior.avg_io_read_bytes = (behavior.avg_io_read_bytes * n + io_read_bytes) / (n + 1)
        behavior.avg_io_write_bytes = (behavior.avg_io_write_bytes * n + io_write_bytes) / (n + 1)
        
        behavior.max_cpu_percent = max(behavior.max_cpu_percent, cpu_percent)
        behavior.max_memory_percent = max(behavior.max_memory_percent, memory_percent)
        behavior.max_connections = max(behavior.max_connections, num_connections)
        behavior.max_io_read_bytes = max(behavior.max_io_read_bytes, io_read_bytes)
        behavior.max_io_write_bytes = max(behavior.max_io_write_bytes, io_write_bytes)
        
        if remote_ports:
            behavior.typical_ports.update(remote_ports)
        if remote_addresses:
            behavior.typical_destinations.update(remote_addresses)
        
        behavior.sample_count += 1
        behavior.last_seen = datetime.utcnow()
    
    def get_behavior(self, name: str, path: Optional[str] = None) -> Optional[ProcessBehavior]:
        """Get learned behavior for a process."""
        key = self._get_behavior_key(name, path)
        return self._behaviors.get(key)
    
    def is_behavior_normal(
        self,
        name: str,
        path: Optional[str] = None,
        cpu_percent: float = 0.0,
        memory_percent: float = 0.0,
        num_connections: int = 0,
        io_read_bytes: int = 0,
        io_write_bytes: int = 0,
        tolerance: float = 2.0,
    ) -> tuple[bool, list[str]]:
        """
        Check if current behavior is within normal range.
        
        Returns:
            Tuple of (is_normal, list of anomaly descriptions)
        """
        behavior = self.get_behavior(name, path)
        
        if behavior is None or behavior.sample_count < 10:
            return True, []
        
        anomalies = []
        
        if cpu_percent > behavior.max_cpu_percent * tolerance:
            anomalies.append(
                f"CPU usage {cpu_percent:.1f}% exceeds normal max {behavior.max_cpu_percent:.1f}%"
            )
        
        if memory_percent > behavior.max_memory_percent * tolerance:
            anomalies.append(
                f"Memory usage {memory_percent:.1f}% exceeds normal max {behavior.max_memory_percent:.1f}%"
            )
        
        if num_connections > behavior.max_connections * tolerance:
            anomalies.append(
                f"Connection count {num_connections} exceeds normal max {behavior.max_connections}"
            )
        
        if io_read_bytes > behavior.max_io_read_bytes * tolerance:
            anomalies.append(
                f"I/O read {io_read_bytes} bytes exceeds normal max {behavior.max_io_read_bytes}"
            )
        
        if io_write_bytes > behavior.max_io_write_bytes * tolerance:
            anomalies.append(
                f"I/O write {io_write_bytes} bytes exceeds normal max {behavior.max_io_write_bytes}"
            )
        
        return len(anomalies) == 0, anomalies
    
    def is_port_typical(self, name: str, port: int, path: Optional[str] = None) -> bool:
        """Check if a port is typical for this process."""
        behavior = self.get_behavior(name, path)
        if behavior is None:
            return True
        return port in behavior.typical_ports
    
    def is_destination_typical(self, name: str, address: str, path: Optional[str] = None) -> bool:
        """Check if a destination is typical for this process."""
        behavior = self.get_behavior(name, path)
        if behavior is None:
            return True
        return address in behavior.typical_destinations
    
    def get_stats(self) -> LearningStats:
        """Get learning statistics."""
        total_samples = sum(b.sample_count for b in self._behaviors.values())
        
        return LearningStats(
            start_time=self._learning_start or datetime.utcnow(),
            duration_days=self._learning_duration.days,
            processes_learned=len(self._behaviors),
            total_samples=total_samples,
            is_complete=not self.is_learning,
        )
    
    def export_behaviors(self) -> dict:
        """Export learned behaviors as dictionary."""
        return {
            key: {
                "name": b.name,
                "path": b.path,
                "avg_cpu": b.avg_cpu_percent,
                "avg_memory": b.avg_memory_percent,
                "avg_connections": b.avg_connections,
                "max_cpu": b.max_cpu_percent,
                "max_memory": b.max_memory_percent,
                "max_connections": b.max_connections,
                "sample_count": b.sample_count,
                "typical_ports": list(b.typical_ports),
            }
            for key, b in self._behaviors.items()
        }
    
    def start_learning(self) -> None:
        """Manually start learning mode."""
        self._is_learning = True
        self._learning_start = datetime.utcnow()
        logger.info("Learning mode started manually")
    
    def stop_learning(self) -> None:
        """Manually stop learning mode."""
        self._is_learning = False
        logger.info("Learning mode stopped manually")
