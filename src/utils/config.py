"""Configuration management for Leatt."""

from pathlib import Path
from typing import Any, Optional
import yaml

from .logger import get_logger

logger = get_logger("config")

_config: Optional["Config"] = None


class Config:
    """Application configuration loaded from YAML files."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = Path(__file__).parent.parent.parent / "config"
        
        self.config_dir = config_dir
        self._default: dict[str, Any] = {}
        self._rules: dict[str, Any] = {}
        
        self._load_configs()
    
    def _load_configs(self) -> None:
        """Load configuration files."""
        default_path = self.config_dir / "default.yaml"
        rules_path = self.config_dir / "rules.yaml"
        
        if default_path.exists():
            with open(default_path, "r", encoding="utf-8") as f:
                self._default = yaml.safe_load(f) or {}
            logger.info(f"Loaded default config from {default_path}")
        else:
            logger.warning(f"Default config not found at {default_path}")
        
        if rules_path.exists():
            with open(rules_path, "r", encoding="utf-8") as f:
                self._rules = yaml.safe_load(f) or {}
            logger.info(f"Loaded rules config from {rules_path}")
        else:
            logger.warning(f"Rules config not found at {rules_path}")
    
    def reload(self) -> None:
        """Reload configuration from files."""
        self._load_configs()
        logger.info("Configuration reloaded")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = key.split(".")
        value = self._default
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_rule(self, key: str, default: Any = None) -> Any:
        """Get a rule configuration value using dot notation."""
        keys = key.split(".")
        value = self._rules
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    @property
    def app_name(self) -> str:
        return self.get("app.name", "Leatt")
    
    @property
    def app_version(self) -> str:
        return self.get("app.version", "0.1.0")
    
    @property
    def learning_mode(self) -> bool:
        return self.get("app.learning_mode", True)
    
    @property
    def process_monitoring_enabled(self) -> bool:
        return self.get("monitoring.process.enabled", True)
    
    @property
    def process_interval(self) -> int:
        return self.get("monitoring.process.interval_seconds", 5)
    
    @property
    def file_monitoring_enabled(self) -> bool:
        return self.get("monitoring.file.enabled", True)
    
    @property
    def watched_folders(self) -> list[str]:
        return self.get("monitoring.file.watched_folders", [])
    
    @property
    def sensitive_extensions(self) -> list[str]:
        return self.get("monitoring.file.sensitive_extensions", [])
    
    @property
    def network_monitoring_enabled(self) -> bool:
        return self.get("monitoring.network.enabled", True)
    
    @property
    def network_interval(self) -> int:
        return self.get("monitoring.network.interval_seconds", 3)
    
    @property
    def registry_monitoring_enabled(self) -> bool:
        return self.get("monitoring.registry.enabled", True)
    
    @property
    def notifications_enabled(self) -> bool:
        return self.get("alerts.notifications_enabled", True)
    
    @property
    def web_enabled(self) -> bool:
        return self.get("web.enabled", False)
    
    @property
    def web_host(self) -> str:
        return self.get("web.host", "127.0.0.1")
    
    @property
    def web_port(self) -> int:
        return self.get("web.port", 8080)
    
    @property
    def ml_enabled(self) -> bool:
        return self.get("ml.enabled", False)
    
    @property
    def max_upload_mb_per_min(self) -> int:
        return self.get_rule("network.max_upload_mb_per_min", 50)
    
    @property
    def suspicious_ports(self) -> list[int]:
        return self.get_rule("network.suspicious_ports", [])
    
    @property
    def suspicious_process_names(self) -> list[str]:
        return self.get_rule("processes.suspicious_names", [])
    
    @property
    def low_risk_threshold(self) -> int:
        return self.get_rule("scoring.low_threshold", 30)
    
    @property
    def medium_risk_threshold(self) -> int:
        return self.get_rule("scoring.medium_threshold", 60)
    
    @property
    def high_risk_threshold(self) -> int:
        return self.get_rule("scoring.high_threshold", 80)
    
    @property
    def critical_risk_threshold(self) -> int:
        return self.get_rule("scoring.critical_threshold", 95)


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config
