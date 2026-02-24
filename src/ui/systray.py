"""System tray interface for Leatt."""

import threading
from typing import Optional, Callable
from enum import Enum
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.config import get_config
from .notifications import NotificationManager, NotificationPriority

logger = get_logger("systray")


class TrayStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    WARNING = "warning"
    ERROR = "error"


class SystrayApp:
    """System tray application interface."""
    
    def __init__(
        self,
        on_pause: Optional[Callable] = None,
        on_resume: Optional[Callable] = None,
        on_quit: Optional[Callable] = None,
    ):
        self.config = get_config()
        self.notification_manager = NotificationManager()
        
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._on_quit = on_quit
        
        self._status = TrayStatus.RUNNING
        self._icon = None
        self._running = False
        
        self._pystray_available = self._check_pystray()
    
    def _check_pystray(self) -> bool:
        """Check if pystray is available."""
        try:
            import pystray
            from PIL import Image
            return True
        except ImportError:
            logger.warning("pystray or PIL not available, systray will be disabled")
            return False
    
    def _create_icon_image(self, status: TrayStatus):
        """Create an icon image for the current status."""
        from PIL import Image, ImageDraw
        
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        colors = {
            TrayStatus.RUNNING: "#22c55e",
            TrayStatus.PAUSED: "#f59e0b",
            TrayStatus.WARNING: "#ef4444",
            TrayStatus.ERROR: "#dc2626",
        }
        color = colors.get(status, "#22c55e")
        
        draw.ellipse([4, 4, size - 4, size - 4], fill=color)
        
        draw.ellipse([20, 20, size - 20, size - 20], fill="white")
        
        if status == TrayStatus.RUNNING:
            draw.polygon([(26, 22), (26, 42), (42, 32)], fill=color)
        elif status == TrayStatus.PAUSED:
            draw.rectangle([24, 22, 30, 42], fill=color)
            draw.rectangle([34, 22, 40, 42], fill=color)
        elif status in (TrayStatus.WARNING, TrayStatus.ERROR):
            draw.rectangle([30, 22, 34, 36], fill=color)
            draw.ellipse([29, 38, 35, 44], fill=color)
        
        return image
    
    def _create_menu(self):
        """Create the system tray menu."""
        import pystray
        
        def on_status(icon, item):
            pass
        
        def on_pause_resume(icon, item):
            if self._status == TrayStatus.RUNNING:
                if self._on_pause:
                    self._on_pause()
            else:
                if self._on_resume:
                    self._on_resume()
        
        def on_open_logs(icon, item):
            self._open_logs()
        
        def on_toggle_notifications(icon, item):
            if self.notification_manager.is_enabled:
                self.notification_manager.disable()
            else:
                self.notification_manager.enable()
        
        def on_quit(icon, item):
            import os
            import sys
            self._running = False
            if self._on_quit:
                self._on_quit()
            icon.stop()
            os._exit(0)
        
        def get_pause_text(item):
            return "Resume" if self._status == TrayStatus.PAUSED else "Pause"
        
        def get_notifications_text(item):
            return "Disable Notifications" if self.notification_manager.is_enabled else "Enable Notifications"
        
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: f"Leatt - {self._status.value.capitalize()}",
                on_status,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                get_pause_text,
                on_pause_resume,
            ),
            pystray.MenuItem(
                get_notifications_text,
                on_toggle_notifications,
            ),
            pystray.MenuItem(
                "View Logs",
                on_open_logs,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Quit",
                on_quit,
            ),
        )
        
        return menu
    
    def _open_logs(self) -> None:
        """Open the logs folder."""
        import subprocess
        import sys
        
        log_dir = Path(__file__).parent.parent.parent / "data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            if sys.platform == "win32":
                subprocess.run(["explorer", str(log_dir)])
            elif sys.platform == "darwin":
                subprocess.run(["open", str(log_dir)])
            else:
                subprocess.run(["xdg-open", str(log_dir)])
        except Exception as e:
            logger.error(f"Failed to open logs folder: {e}")
    
    def run(self) -> None:
        """Run the system tray application."""
        if not self._pystray_available:
            logger.info("Systray not available, running in background mode")
            self._running = True
            while self._running:
                import time
                time.sleep(1)
            return
        
        import pystray
        
        logger.info("Starting systray application")
        
        image = self._create_icon_image(self._status)
        menu = self._create_menu()
        
        self._icon = pystray.Icon(
            name="leatt",
            icon=image,
            title=f"Leatt - {self._status.value.capitalize()}",
            menu=menu,
        )
        
        self._running = True
        
        self.notify(
            title="Leatt Started",
            message="Data leak prevention is now active",
        )
        
        self._icon.run()
    
    def stop(self) -> None:
        """Stop the system tray application."""
        self._running = False
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
        logger.info("Systray stopped")
    
    def set_status(self, status: str) -> None:
        """Update the tray icon status."""
        try:
            new_status = TrayStatus(status)
        except ValueError:
            logger.warning(f"Invalid status: {status}")
            return
        
        self._status = new_status
        
        if self._icon and self._pystray_available:
            self._icon.icon = self._create_icon_image(new_status)
            self._icon.title = f"Leatt - {new_status.value.capitalize()}"
        
        logger.debug(f"Tray status changed to: {new_status.value}")
    
    def notify(
        self,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
    ) -> bool:
        """Send a notification."""
        return self.notification_manager.notify(title, message, priority)
    
    def flash_warning(self) -> None:
        """Temporarily show warning status."""
        original_status = self._status
        self.set_status(TrayStatus.WARNING.value)
        
        def restore():
            import time
            time.sleep(3)
            if self._status == TrayStatus.WARNING:
                self.set_status(original_status.value)
        
        threading.Thread(target=restore, daemon=True).start()
    
    @property
    def is_running(self) -> bool:
        """Check if systray is running."""
        return self._running
    
    @property
    def current_status(self) -> TrayStatus:
        """Get current status."""
        return self._status
