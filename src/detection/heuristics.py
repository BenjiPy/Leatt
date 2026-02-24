"""Heuristics-based behavioral analysis engine."""

import time
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..utils.database import AlertSeverity

logger = get_logger("heuristics")


@dataclass
class ProcessActivity:
    """Track activity for a single process."""
    pid: int
    name: str
    first_seen: float = field(default_factory=time.time)
    
    file_accesses: list[dict] = field(default_factory=list)
    network_events: list[dict] = field(default_factory=list)
    registry_events: list[dict] = field(default_factory=list)
    
    sensitive_files_accessed: int = 0
    bytes_uploaded: int = 0
    unique_destinations: set[str] = field(default_factory=set)
    
    risk_score: float = 0.0


@dataclass
class HeuristicPattern:
    """Definition of a heuristic detection pattern."""
    name: str
    description: str
    risk_score: float
    conditions: dict
    cooldown_seconds: int = 60


class HeuristicsEngine:
    """
    Behavioral analysis using heuristic patterns.
    
    Correlates events across different sources to detect
    complex attack patterns like data exfiltration.
    """
    
    def __init__(self):
        self.config = get_config()
        
        self._process_activities: dict[int, ProcessActivity] = {}
        self._activity_window = timedelta(seconds=self.config.get_rule(
            "heuristics.correlation_window_seconds", 60
        ))
        
        self._alert_cooldowns: dict[str, float] = {}
        
        self._patterns = self._load_patterns()
        
        logger.info(f"Loaded {len(self._patterns)} heuristic patterns")
    
    def _load_patterns(self) -> list[HeuristicPattern]:
        """Load heuristic patterns from config and defaults."""
        patterns = []
        
        patterns.append(HeuristicPattern(
            name="exfiltration_chain",
            description="New process accessing sensitive files and uploading data",
            risk_score=80.0,
            conditions={
                "process_age_minutes": 5,
                "min_sensitive_files": 1,
                "min_bytes_uploaded": 1024 * 1024,
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="credential_theft",
            description="Process accessing browser credential files",
            risk_score=90.0,
            conditions={
                "credential_file_patterns": [
                    "Login Data",
                    "cookies.sqlite",
                    "key4.db",
                    "logins.json",
                    "Cookies",
                ],
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="rapid_file_enumeration",
            description="Process rapidly accessing many files",
            risk_score=60.0,
            conditions={
                "min_file_accesses_per_min": 50,
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="staging_behavior",
            description="Process copying files to temp folder before network activity",
            risk_score=70.0,
            conditions={
                "temp_folder_writes": True,
                "followed_by_upload": True,
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="registry_persistence",
            description="New process modifying startup registry keys",
            risk_score=85.0,
            conditions={
                "process_age_minutes": 10,
                "registry_run_key_modified": True,
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="multi_destination_upload",
            description="Process uploading to multiple unique destinations",
            risk_score=65.0,
            conditions={
                "min_unique_destinations": 5,
                "min_bytes_uploaded": 512 * 1024,
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="ssh_key_access",
            description="Non-SSH process accessing SSH keys",
            risk_score=75.0,
            conditions={
                "ssh_key_patterns": [".ssh/id_", ".ssh/known_hosts"],
                "exclude_processes": ["ssh", "sshd", "ssh-agent", "git"],
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="trusted_process_anomaly",
            description="Trusted process exhibiting unusual behavior (potential hijacking/injection)",
            risk_score=70.0,
            conditions={
                "is_trusted": True,
                "anomaly_indicators": ["high_io", "many_connections", "unusual_network"],
            },
        ))
        
        patterns.append(HeuristicPattern(
            name="pid_hijack_attempt",
            description="Process identity changed or PID reused suspiciously",
            risk_score=95.0,
            conditions={
                "event_types": ["pid_hijack", "process_mutation"],
            },
        ))
        
        return patterns
    
    def _get_or_create_activity(self, pid: int, name: str) -> ProcessActivity:
        """Get or create activity tracker for a process."""
        if pid not in self._process_activities:
            self._process_activities[pid] = ProcessActivity(pid=pid, name=name)
        return self._process_activities[pid]
    
    def _cleanup_old_activities(self) -> None:
        """Remove stale process activities."""
        current_time = time.time()
        cutoff = current_time - self._activity_window.total_seconds() * 2
        
        stale_pids = [
            pid for pid, activity in self._process_activities.items()
            if activity.first_seen < cutoff
        ]
        
        for pid in stale_pids:
            del self._process_activities[pid]
    
    def _record_file_event(self, activity: ProcessActivity, event_data: dict) -> None:
        """Record a file access event."""
        activity.file_accesses.append({
            "path": event_data.get("file_path"),
            "type": event_data.get("event_type"),
            "timestamp": time.time(),
            "is_sensitive": event_data.get("is_sensitive", False),
        })
        
        if event_data.get("is_sensitive"):
            activity.sensitive_files_accessed += 1
        
        if len(activity.file_accesses) > 100:
            activity.file_accesses = activity.file_accesses[-100:]
    
    def _record_network_event(self, activity: ProcessActivity, event_data: dict) -> None:
        """Record a network event."""
        activity.network_events.append({
            "remote_address": event_data.get("remote_address"),
            "remote_port": event_data.get("remote_port"),
            "bytes_uploaded": event_data.get("bytes_uploaded", 0),
            "timestamp": time.time(),
        })
        
        if event_data.get("bytes_uploaded"):
            activity.bytes_uploaded += event_data["bytes_uploaded"]
        
        if event_data.get("remote_address"):
            activity.unique_destinations.add(event_data["remote_address"])
        
        if len(activity.network_events) > 100:
            activity.network_events = activity.network_events[-100:]
    
    def _record_registry_event(self, activity: ProcessActivity, event_data: dict) -> None:
        """Record a registry event."""
        activity.registry_events.append({
            "key_path": event_data.get("key_path"),
            "change_type": event_data.get("change_type"),
            "timestamp": time.time(),
        })
        
        if len(activity.registry_events) > 50:
            activity.registry_events = activity.registry_events[-50:]
    
    def _check_exfiltration_chain(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for exfiltration chain pattern."""
        conditions = pattern.conditions
        
        process_age = (time.time() - activity.first_seen) / 60
        if process_age > conditions.get("process_age_minutes", 5):
            return False
        
        if activity.sensitive_files_accessed < conditions.get("min_sensitive_files", 1):
            return False
        
        if activity.bytes_uploaded < conditions.get("min_bytes_uploaded", 1024 * 1024):
            return False
        
        return True
    
    def _check_credential_theft(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for credential theft pattern."""
        credential_patterns = pattern.conditions.get("credential_file_patterns", [])
        
        for file_access in activity.file_accesses:
            file_path = file_access.get("path", "").lower()
            for cred_pattern in credential_patterns:
                if cred_pattern.lower() in file_path:
                    return True
        
        return False
    
    def _check_rapid_enumeration(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for rapid file enumeration."""
        min_accesses = pattern.conditions.get("min_file_accesses_per_min", 50)
        
        current_time = time.time()
        cutoff = current_time - 60
        
        recent_accesses = [
            f for f in activity.file_accesses
            if f.get("timestamp", 0) > cutoff
        ]
        
        return len(recent_accesses) >= min_accesses
    
    def _check_staging_behavior(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for staging behavior (copy to temp, then upload)."""
        temp_patterns = ["/tmp/", "\\temp\\", "\\tmp\\", "/var/tmp/"]
        
        temp_writes = [
            f for f in activity.file_accesses
            if f.get("type") in ("created", "modified")
            and any(tp in f.get("path", "").lower() for tp in temp_patterns)
        ]
        
        if not temp_writes:
            return False
        
        latest_temp_write = max(f.get("timestamp", 0) for f in temp_writes)
        
        network_after_staging = [
            n for n in activity.network_events
            if n.get("timestamp", 0) > latest_temp_write
            and n.get("bytes_uploaded", 0) > 0
        ]
        
        return len(network_after_staging) > 0
    
    def _check_registry_persistence(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for registry persistence pattern."""
        process_age = (time.time() - activity.first_seen) / 60
        if process_age > pattern.conditions.get("process_age_minutes", 10):
            return False
        
        run_key_patterns = ["run", "runonce"]
        
        for reg_event in activity.registry_events:
            key_path = reg_event.get("key_path", "").lower()
            if any(pattern in key_path for pattern in run_key_patterns):
                return True
        
        return False
    
    def _check_multi_destination(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for multi-destination upload pattern."""
        conditions = pattern.conditions
        
        if len(activity.unique_destinations) < conditions.get("min_unique_destinations", 5):
            return False
        
        if activity.bytes_uploaded < conditions.get("min_bytes_uploaded", 512 * 1024):
            return False
        
        return True
    
    def _check_ssh_key_access(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Check for SSH key access by non-SSH process."""
        exclude_processes = pattern.conditions.get("exclude_processes", [])
        if activity.name.lower() in [p.lower() for p in exclude_processes]:
            return False
        
        ssh_patterns = pattern.conditions.get("ssh_key_patterns", [])
        
        for file_access in activity.file_accesses:
            file_path = file_access.get("path", "").lower()
            for ssh_pattern in ssh_patterns:
                if ssh_pattern.lower() in file_path:
                    return True
        
        return False
    
    def _evaluate_pattern(self, activity: ProcessActivity, pattern: HeuristicPattern) -> bool:
        """Evaluate a single pattern against process activity."""
        checkers = {
            "exfiltration_chain": self._check_exfiltration_chain,
            "credential_theft": self._check_credential_theft,
            "rapid_file_enumeration": self._check_rapid_enumeration,
            "staging_behavior": self._check_staging_behavior,
            "registry_persistence": self._check_registry_persistence,
            "multi_destination_upload": self._check_multi_destination,
            "ssh_key_access": self._check_ssh_key_access,
        }
        
        checker = checkers.get(pattern.name)
        if checker:
            return checker(activity, pattern)
        
        return False
    
    def _is_on_cooldown(self, pattern_name: str, pid: int) -> bool:
        """Check if pattern is on cooldown for this process."""
        key = f"{pattern_name}:{pid}"
        last_alert = self._alert_cooldowns.get(key, 0)
        return time.time() - last_alert < 60
    
    def _set_cooldown(self, pattern_name: str, pid: int) -> None:
        """Set cooldown for pattern/process combination."""
        key = f"{pattern_name}:{pid}"
        self._alert_cooldowns[key] = time.time()
    
    def analyze(self, event: Any) -> list[dict]:
        """
        Analyze an event and return any heuristic alerts.
        
        Args:
            event: MonitorEvent from one of the monitors
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        pid = event.data.get("pid")
        process_name = event.data.get("process_name", "unknown")
        
        if pid is None:
            return alerts
        
        activity = self._get_or_create_activity(pid, process_name)
        
        if event.source == "file_monitor":
            self._record_file_event(activity, event.data)
        elif event.source == "network_monitor":
            self._record_network_event(activity, event.data)
        elif event.source == "registry_monitor":
            self._record_registry_event(activity, event.data)
        
        for pattern in self._patterns:
            if self._is_on_cooldown(pattern.name, pid):
                continue
            
            try:
                if self._evaluate_pattern(activity, pattern):
                    severity = AlertSeverity.HIGH
                    if pattern.risk_score >= 90:
                        severity = AlertSeverity.CRITICAL
                    elif pattern.risk_score >= 70:
                        severity = AlertSeverity.HIGH
                    elif pattern.risk_score >= 50:
                        severity = AlertSeverity.MEDIUM
                    else:
                        severity = AlertSeverity.LOW
                    
                    alerts.append({
                        "severity": severity,
                        "source": f"heuristics:{pattern.name}",
                        "description": f"{pattern.description} (Process: {process_name})",
                    })
                    
                    self._set_cooldown(pattern.name, pid)
                    activity.risk_score = max(activity.risk_score, pattern.risk_score)
                    
                    logger.warning(f"Heuristic pattern matched: {pattern.name} for {process_name}")
            
            except Exception as e:
                logger.error(f"Error evaluating pattern {pattern.name}: {e}")
        
        self._cleanup_old_activities()
        
        return alerts
    
    def get_process_risk_score(self, pid: int) -> float:
        """Get cumulative risk score for a process."""
        activity = self._process_activities.get(pid)
        return activity.risk_score if activity else 0.0
    
    def get_activity_summary(self, pid: int) -> Optional[dict]:
        """Get activity summary for a process."""
        activity = self._process_activities.get(pid)
        if not activity:
            return None
        
        return {
            "pid": activity.pid,
            "name": activity.name,
            "age_seconds": time.time() - activity.first_seen,
            "file_accesses": len(activity.file_accesses),
            "sensitive_files": activity.sensitive_files_accessed,
            "network_events": len(activity.network_events),
            "bytes_uploaded": activity.bytes_uploaded,
            "unique_destinations": len(activity.unique_destinations),
            "registry_events": len(activity.registry_events),
            "risk_score": activity.risk_score,
        }
