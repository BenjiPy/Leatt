"""Platform-specific utilities and OS abstraction."""

import os
import sys
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from .logger import get_logger

logger = get_logger("platform")


class OperatingSystem(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass
class SystemInfo:
    """System information."""
    os: OperatingSystem
    os_version: str
    hostname: str
    username: str
    home_dir: Path
    is_admin: bool


class PlatformUtils:
    """Cross-platform utility functions."""
    
    @staticmethod
    def get_os() -> OperatingSystem:
        """Get the current operating system."""
        if sys.platform == "win32":
            return OperatingSystem.WINDOWS
        elif sys.platform == "linux":
            return OperatingSystem.LINUX
        elif sys.platform == "darwin":
            return OperatingSystem.MACOS
        return OperatingSystem.UNKNOWN
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"
    
    @staticmethod
    def is_linux() -> bool:
        """Check if running on Linux."""
        return sys.platform == "linux"
    
    @staticmethod
    def get_system_info() -> SystemInfo:
        """Get system information."""
        import platform
        
        os_type = PlatformUtils.get_os()
        
        return SystemInfo(
            os=os_type,
            os_version=platform.version(),
            hostname=platform.node(),
            username=os.getlogin(),
            home_dir=Path.home(),
            is_admin=PlatformUtils.is_admin(),
        )
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with admin/root privileges."""
        if PlatformUtils.is_windows():
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def expand_path(path: str) -> Path:
        """Expand path with environment variables and user home."""
        expanded = os.path.expandvars(os.path.expanduser(path))
        return Path(expanded)
    
    @staticmethod
    def get_sensitive_folders() -> list[Path]:
        """Get list of sensitive folders to monitor based on OS."""
        home = Path.home()
        
        common_folders = [
            home / "Documents",
            home / "Downloads",
            home / "Desktop",
            home / ".ssh",
        ]
        
        if PlatformUtils.is_windows():
            appdata = Path(os.environ.get("APPDATA", ""))
            localappdata = Path(os.environ.get("LOCALAPPDATA", ""))
            
            return common_folders + [
                appdata,
                localappdata,
                appdata / "Microsoft" / "Credentials",
            ]
        else:
            return common_folders + [
                home / ".gnupg",
                home / ".aws",
                home / ".config",
            ]
    
    @staticmethod
    def get_temp_folder() -> Path:
        """Get the system temp folder."""
        if PlatformUtils.is_windows():
            return Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
        return Path("/tmp")
    
    @staticmethod
    def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> Optional[str]:
        """Compute hash of a file."""
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError) as e:
            logger.debug(f"Cannot hash file {file_path}: {e}")
            return None
    
    @staticmethod
    def get_process_executable_path(pid: int) -> Optional[Path]:
        """Get the executable path for a process."""
        try:
            import psutil
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            return Path(exe_path) if exe_path else None
        except Exception as e:
            logger.debug(f"Failed to get executable path for PID {pid}: {e}")
            return None
    
    @staticmethod
    def is_system_process(process_path: Optional[Path]) -> bool:
        """Check if a process is a system process based on its path."""
        if process_path is None:
            return False
        
        path_str = str(process_path).lower()
        
        if PlatformUtils.is_windows():
            system_paths = [
                "c:\\windows\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\",
            ]
        else:
            system_paths = [
                "/usr/bin/",
                "/usr/sbin/",
                "/bin/",
                "/sbin/",
                "/usr/lib/",
            ]
        
        return any(path_str.startswith(sp) for sp in system_paths)
    
    @staticmethod
    def get_known_browsers() -> list[str]:
        """Get list of known browser process names."""
        return [
            "chrome.exe", "chrome",
            "firefox.exe", "firefox",
            "msedge.exe", "msedge",
            "brave.exe", "brave",
            "opera.exe", "opera",
            "safari",
            "iexplore.exe",
        ]
    
    @staticmethod
    def registry_available() -> bool:
        """Check if Windows registry monitoring is available."""
        if not PlatformUtils.is_windows():
            return False
        try:
            import winreg
            return True
        except ImportError:
            return False
