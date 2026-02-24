"""Rules-based detection engine."""

from dataclasses import dataclass
from typing import Any, Optional
from enum import Enum

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..utils.database import AlertSeverity

logger = get_logger("rules_engine")


class RuleType(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"


@dataclass
class Rule:
    """Detection rule definition."""
    name: str
    rule_type: RuleType
    description: str
    severity: AlertSeverity
    enabled: bool = True
    conditions: dict = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = {}


@dataclass
class RuleMatch:
    """Result of a rule evaluation."""
    rule: Rule
    matched: bool
    details: dict = None


class RulesEngine:
    """Evaluate events against detection rules."""
    
    def __init__(self):
        self.config = get_config()
        self.rules: list[Rule] = []
        self._load_default_rules()
    
    def _load_default_rules(self) -> None:
        """Load built-in detection rules."""
        
        self.rules.append(Rule(
            name="suspicious_process_name",
            rule_type=RuleType.PROCESS,
            description="Process with known malicious name detected",
            severity=AlertSeverity.CRITICAL,
            conditions={
                "suspicious_names": self.config.suspicious_process_names,
            },
        ))
        
        self.rules.append(Rule(
            name="suspicious_port_connection",
            rule_type=RuleType.NETWORK,
            description="Connection to suspicious port detected",
            severity=AlertSeverity.HIGH,
            conditions={
                "suspicious_ports": self.config.suspicious_ports,
            },
        ))
        
        self.rules.append(Rule(
            name="high_upload_rate",
            rule_type=RuleType.NETWORK,
            description="Abnormally high data upload detected",
            severity=AlertSeverity.HIGH,
            conditions={
                "max_mb_per_min": self.config.max_upload_mb_per_min,
            },
        ))
        
        self.rules.append(Rule(
            name="sensitive_file_access",
            rule_type=RuleType.FILE,
            description="Access to sensitive file detected",
            severity=AlertSeverity.MEDIUM,
            conditions={
                "sensitive_extensions": self.config.sensitive_extensions,
            },
        ))
        
        self.rules.append(Rule(
            name="untrusted_process",
            rule_type=RuleType.PROCESS,
            description="New untrusted process started",
            severity=AlertSeverity.LOW,
            enabled=False,
            conditions={},
        ))
        
        self.rules.append(Rule(
            name="registry_run_key_modified",
            rule_type=RuleType.REGISTRY,
            description="Startup registry key modified",
            severity=AlertSeverity.HIGH,
            conditions={
                "key_patterns": ["Run", "RunOnce"],
            },
        ))
        
        self.rules.append(Rule(
            name="high_connection_count",
            rule_type=RuleType.PROCESS,
            description="Process has excessive network connections",
            severity=AlertSeverity.MEDIUM,
            conditions={
                "max_connections": 100,
            },
        ))
        
        self.rules.append(Rule(
            name="high_io_activity",
            rule_type=RuleType.PROCESS,
            description="Process has abnormally high I/O activity",
            severity=AlertSeverity.MEDIUM,
            conditions={
                "threshold_mb": 10,
            },
        ))
        
        logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule."""
        self.rules.append(rule)
        logger.info(f"Added rule: {rule.name}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                self.rules.pop(i)
                logger.info(f"Removed rule: {rule_name}")
                return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                return True
        return False
    
    def _evaluate_process_rule(self, rule: Rule, event_data: dict) -> Optional[RuleMatch]:
        """Evaluate a process-related rule."""
        process_name = event_data.get("process_name", "").lower()
        
        if rule.name == "suspicious_process_name":
            suspicious_names = [n.lower() for n in rule.conditions.get("suspicious_names", [])]
            if process_name in suspicious_names:
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={"process_name": process_name},
                )
        
        elif rule.name == "untrusted_process":
            if not event_data.get("is_trusted", True):
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "process_name": process_name,
                        "path": event_data.get("path"),
                    },
                )
        
        elif rule.name == "high_connection_count":
            num_connections = event_data.get("num_connections", 0)
            max_connections = rule.conditions.get("max_connections", 100)
            if num_connections > max_connections:
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "process_name": process_name,
                        "num_connections": num_connections,
                    },
                )
        
        elif rule.name == "high_io_activity":
            threshold_bytes = rule.conditions.get("threshold_mb", 10) * 1024 * 1024
            read_delta = event_data.get("read_bytes_delta", 0)
            write_delta = event_data.get("write_bytes_delta", 0)
            if read_delta > threshold_bytes or write_delta > threshold_bytes:
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "process_name": process_name,
                        "read_mb": round(read_delta / (1024 * 1024), 2),
                        "write_mb": round(write_delta / (1024 * 1024), 2),
                    },
                )
        
        return None
    
    def _evaluate_network_rule(self, rule: Rule, event_data: dict) -> Optional[RuleMatch]:
        """Evaluate a network-related rule."""
        
        if rule.name == "suspicious_port_connection":
            remote_port = event_data.get("remote_port", 0)
            suspicious_ports = rule.conditions.get("suspicious_ports", [])
            if remote_port in suspicious_ports:
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "remote_port": remote_port,
                        "remote_address": event_data.get("remote_address"),
                        "process_name": event_data.get("process_name"),
                    },
                )
        
        elif rule.name == "high_upload_rate":
            mb_uploaded = event_data.get("mb_uploaded", 0)
            threshold = rule.conditions.get("max_mb_per_min", 50)
            if mb_uploaded > threshold:
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "mb_uploaded": mb_uploaded,
                        "threshold": threshold,
                        "process_name": event_data.get("process_name"),
                    },
                )
        
        return None
    
    def _evaluate_file_rule(self, rule: Rule, event_data: dict) -> Optional[RuleMatch]:
        """Evaluate a file-related rule."""
        
        if rule.name == "sensitive_file_access":
            if event_data.get("is_sensitive", False):
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "file_path": event_data.get("file_path"),
                        "event_type": event_data.get("event_type"),
                    },
                )
        
        return None
    
    def _evaluate_registry_rule(self, rule: Rule, event_data: dict) -> Optional[RuleMatch]:
        """Evaluate a registry-related rule."""
        
        if rule.name == "registry_run_key_modified":
            key_path = event_data.get("key_path", "")
            key_patterns = rule.conditions.get("key_patterns", [])
            if any(pattern in key_path for pattern in key_patterns):
                return RuleMatch(
                    rule=rule,
                    matched=True,
                    details={
                        "key_path": key_path,
                        "value_name": event_data.get("value_name"),
                        "change_type": event_data.get("change_type"),
                    },
                )
        
        return None
    
    def evaluate(self, event: Any) -> list[dict]:
        """Evaluate an event against all enabled rules."""
        alerts = []
        
        event_source = event.source
        event_data = event.data
        
        source_to_type = {
            "process_monitor": RuleType.PROCESS,
            "network_monitor": RuleType.NETWORK,
            "file_monitor": RuleType.FILE,
            "registry_monitor": RuleType.REGISTRY,
        }
        
        event_rule_type = source_to_type.get(event_source)
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if rule.rule_type != event_rule_type:
                continue
            
            match = None
            
            if rule.rule_type == RuleType.PROCESS:
                match = self._evaluate_process_rule(rule, event_data)
            elif rule.rule_type == RuleType.NETWORK:
                match = self._evaluate_network_rule(rule, event_data)
            elif rule.rule_type == RuleType.FILE:
                match = self._evaluate_file_rule(rule, event_data)
            elif rule.rule_type == RuleType.REGISTRY:
                match = self._evaluate_registry_rule(rule, event_data)
            
            if match and match.matched:
                alerts.append({
                    "severity": rule.severity,
                    "source": f"rules_engine:{rule.name}",
                    "description": rule.description,
                    "details": match.details,
                })
                logger.info(f"Rule matched: {rule.name} - {rule.description}")
        
        return alerts
    
    def get_rules(self) -> list[Rule]:
        """Get all rules."""
        return self.rules.copy()
    
    def get_enabled_rules(self) -> list[Rule]:
        """Get only enabled rules."""
        return [r for r in self.rules if r.enabled]
