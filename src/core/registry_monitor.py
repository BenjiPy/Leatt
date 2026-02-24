"""Windows Registry monitoring module."""

import threading
import time
from typing import Optional
from queue import Queue
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.platform import PlatformUtils
from ..utils.config import get_config
from ..utils.database import get_database

logger = get_logger("registry_monitor")


@dataclass
class RegistryChange:
    """Information about a registry change."""
    key_path: str
    value_name: Optional[str]
    old_value: Optional[str]
    new_value: Optional[str]
    change_type: str


class RegistryMonitor:
    """Monitor Windows Registry changes (Windows only)."""
    
    def __init__(
        self,
        event_queue: Queue,
        stop_event: threading.Event,
        interval: int = 10,
    ):
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.interval = interval
        
        self.config = get_config()
        self.db = get_database()
        
        self._watched_keys = self._parse_watched_keys()
        self._key_snapshots: dict[str, dict[str, str]] = {}
        
        self._available = PlatformUtils.registry_available()
        
        if not self._available:
            logger.warning("Registry monitoring not available (not Windows or winreg missing)")
    
    def _parse_watched_keys(self) -> list[tuple[int, str]]:
        """Parse watched registry keys from config."""
        if not PlatformUtils.is_windows():
            return []
        
        try:
            import winreg
        except ImportError:
            return []
        
        hkey_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        }
        
        watched_keys = self.config.get("monitoring.registry.watched_keys", [])
        parsed = []
        
        for key_path in watched_keys:
            parts = key_path.split("\\", 1)
            if len(parts) == 2:
                hkey_name, subkey = parts
                hkey = hkey_map.get(hkey_name.upper())
                if hkey is not None:
                    parsed.append((hkey, subkey))
        
        return parsed
    
    def _read_key_values(self, hkey: int, subkey: str) -> dict[str, str]:
        """Read all values from a registry key."""
        if not self._available:
            return {}
        
        try:
            import winreg
            
            values = {}
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            values[name] = str(value)
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except FileNotFoundError:
                pass
            except PermissionError:
                logger.debug(f"Permission denied reading registry key: {subkey}")
            
            return values
        
        except Exception as e:
            logger.debug(f"Error reading registry key {subkey}: {e}")
            return {}
    
    def _get_key_path(self, hkey: int, subkey: str) -> str:
        """Get full key path as string."""
        try:
            import winreg
            hkey_names = {
                winreg.HKEY_LOCAL_MACHINE: "HKLM",
                winreg.HKEY_CURRENT_USER: "HKCU",
            }
            return f"{hkey_names.get(hkey, 'UNKNOWN')}\\{subkey}"
        except ImportError:
            return subkey
    
    def _check_changes(self, hkey: int, subkey: str) -> list[RegistryChange]:
        """Check for changes in a registry key."""
        key_path = self._get_key_path(hkey, subkey)
        current_values = self._read_key_values(hkey, subkey)
        previous_values = self._key_snapshots.get(key_path, {})
        
        changes = []
        
        for name, value in current_values.items():
            if name not in previous_values:
                changes.append(RegistryChange(
                    key_path=key_path,
                    value_name=name,
                    old_value=None,
                    new_value=value,
                    change_type="added",
                ))
            elif previous_values[name] != value:
                changes.append(RegistryChange(
                    key_path=key_path,
                    value_name=name,
                    old_value=previous_values[name],
                    new_value=value,
                    change_type="modified",
                ))
        
        for name, value in previous_values.items():
            if name not in current_values:
                changes.append(RegistryChange(
                    key_path=key_path,
                    value_name=name,
                    old_value=value,
                    new_value=None,
                    change_type="deleted",
                ))
        
        self._key_snapshots[key_path] = current_values
        
        return changes
    
    def _report_change(self, change: RegistryChange) -> None:
        """Report a registry change as an event."""
        from .daemon import MonitorEvent
        
        risk_score = 50.0
        if "Run" in change.key_path:
            risk_score = 80.0
        
        event = MonitorEvent(
            source="registry_monitor",
            event_type=f"registry_{change.change_type}",
            data={
                "key_path": change.key_path,
                "value_name": change.value_name,
                "old_value": change.old_value,
                "new_value": change.new_value,
                "change_type": change.change_type,
            },
            risk_score=risk_score,
        )
        self.event_queue.put(event)
        
        logger.warning(
            f"Registry {change.change_type}: {change.key_path}\\{change.value_name}"
        )
    
    def _scan_registry(self) -> None:
        """Scan all watched registry keys for changes."""
        if not self._available:
            return
        
        for hkey, subkey in self._watched_keys:
            try:
                changes = self._check_changes(hkey, subkey)
                for change in changes:
                    self._report_change(change)
            except Exception as e:
                logger.debug(f"Error checking registry key {subkey}: {e}")
    
    def _initialize_snapshots(self) -> None:
        """Initialize snapshots of all watched keys."""
        if not self._available:
            return
        
        for hkey, subkey in self._watched_keys:
            key_path = self._get_key_path(hkey, subkey)
            self._key_snapshots[key_path] = self._read_key_values(hkey, subkey)
            logger.debug(f"Initialized snapshot for {key_path}")
    
    def start(self) -> None:
        """Start the registry monitor loop."""
        if not self._available:
            logger.info("Registry monitor skipped (not available on this platform)")
            while not self.stop_event.is_set():
                self.stop_event.wait(1.0)
            return
        
        logger.info("Registry monitor started")
        
        self._initialize_snapshots()
        
        while not self.stop_event.is_set():
            try:
                self._scan_registry()
            except Exception as e:
                logger.error(f"Error scanning registry: {e}")
            
            self.stop_event.wait(self.interval)
        
        logger.info("Registry monitor stopped")
    
    def stop(self) -> None:
        """Stop the registry monitor."""
        pass
