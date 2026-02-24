"""Notification management for Leatt."""

from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import threading

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger("notifications")


class NotificationPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Notification:
    """A notification to display to the user."""
    title: str
    message: str
    priority: NotificationPriority = NotificationPriority.NORMAL
    timestamp: datetime = None
    icon: Optional[str] = None
    action_callback: Optional[Callable] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class NotificationManager:
    """Manage and display notifications."""
    
    def __init__(self):
        self.config = get_config()
        self._enabled = self.config.notifications_enabled
        self._history: list[Notification] = []
        self._max_history = 100
        self._lock = threading.Lock()
        
        self._rate_limit_seconds = 5
        self._last_notification_time = 0.0
        self._pending_count = 0
        
        self._plyer_available = self._check_plyer()
    
    def _check_plyer(self) -> bool:
        """Check if plyer is available for notifications."""
        try:
            from plyer import notification
            return True
        except ImportError:
            logger.warning("plyer not available, notifications will be logged only")
            return False
    
    def notify(
        self,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        timeout: int = 10,
    ) -> bool:
        """
        Display a notification with rate limiting.
        
        Returns:
            True if notification was displayed, False otherwise.
        """
        import time
        
        if not self._enabled:
            logger.debug(f"Notifications disabled, skipping: {title}")
            return False
        
        notification = Notification(
            title=title,
            message=message,
            priority=priority,
        )
        
        with self._lock:
            self._history.append(notification)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
        
        log_level = {
            NotificationPriority.LOW: logger.debug,
            NotificationPriority.NORMAL: logger.info,
            NotificationPriority.HIGH: logger.warning,
            NotificationPriority.CRITICAL: logger.error,
        }.get(priority, logger.info)
        
        log_level(f"[NOTIFICATION] {title}: {message}")
        
        current_time = time.time()
        time_since_last = current_time - self._last_notification_time
        
        if time_since_last < self._rate_limit_seconds:
            self._pending_count += 1
            logger.debug(f"Rate limited, {self._pending_count} pending notifications")
            return False
        
        if self._plyer_available:
            if self._pending_count > 0:
                message = f"{message} (+{self._pending_count} autres alertes)"
                self._pending_count = 0
            
            self._last_notification_time = current_time
            return self._show_plyer_notification(title, message, timeout)
        
        return True
    
    def _show_plyer_notification(self, title: str, message: str, timeout: int) -> bool:
        """Show notification using plyer."""
        try:
            from plyer import notification
            
            notification.notify(
                title=title,
                message=message,
                app_name="Leatt",
                timeout=timeout,
            )
            return True
        
        except Exception as e:
            logger.error(f"Failed to show notification: {e}")
            return False
    
    def notify_alert(
        self,
        severity: str,
        description: str,
        process_name: Optional[str] = None,
    ) -> bool:
        """Send an alert notification."""
        priority_map = {
            "low": NotificationPriority.LOW,
            "medium": NotificationPriority.NORMAL,
            "high": NotificationPriority.HIGH,
            "critical": NotificationPriority.CRITICAL,
        }
        
        priority = priority_map.get(severity.lower(), NotificationPriority.NORMAL)
        
        title = f"Leatt Alert [{severity.upper()}]"
        message = description
        if process_name:
            message = f"[{process_name}] {description}"
        
        return self.notify(title, message, priority)
    
    def enable(self) -> None:
        """Enable notifications."""
        self._enabled = True
        logger.info("Notifications enabled")
    
    def disable(self) -> None:
        """Disable notifications."""
        self._enabled = False
        logger.info("Notifications disabled")
    
    @property
    def is_enabled(self) -> bool:
        """Check if notifications are enabled."""
        return self._enabled
    
    def get_history(self, limit: int = 50) -> list[Notification]:
        """Get notification history."""
        with self._lock:
            return self._history[-limit:]
    
    def clear_history(self) -> None:
        """Clear notification history."""
        with self._lock:
            self._history.clear()
        logger.debug("Notification history cleared")
