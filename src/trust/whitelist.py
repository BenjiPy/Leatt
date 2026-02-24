"""Process whitelist management."""

from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.database import get_database, TrustedProcess
from ..utils.platform import PlatformUtils

logger = get_logger("whitelist")


@dataclass
class WhitelistEntry:
    """Entry in the process whitelist."""
    name: str
    path: Optional[str] = None
    hash_sha256: Optional[str] = None
    publisher: Optional[str] = None
    added_at: Optional[datetime] = None
    added_by: str = "system"
    reason: Optional[str] = None


class Whitelist:
    """Manage trusted process whitelist."""
    
    def __init__(self):
        self.db = get_database()
        self._cache: dict[str, WhitelistEntry] = {}
        self._system_processes: set[str] = set()
        
        self._load_system_defaults()
    
    def _load_system_defaults(self) -> None:
        """Load default system processes into whitelist."""
        if PlatformUtils.is_windows():
            system_processes = [
                # Windows core
                "System",
                "smss.exe",
                "csrss.exe",
                "wininit.exe",
                "services.exe",
                "lsass.exe",
                "svchost.exe",
                "explorer.exe",
                "taskhostw.exe",
                "dwm.exe",
                "conhost.exe",
                "RuntimeBroker.exe",
                "SearchHost.exe",
                "ShellExperienceHost.exe",
                "StartMenuExperienceHost.exe",
                "sihost.exe",
                "fontdrvhost.exe",
                "WmiPrvSE.exe",
                "dllhost.exe",
                "ctfmon.exe",
                "SecurityHealthService.exe",
                "MsMpEng.exe",
                "NisSrv.exe",
                "spoolsv.exe",
                "audiodg.exe",
                "SearchIndexer.exe",
                "TextInputHost.exe",
                "ApplicationFrameHost.exe",
                "SystemSettings.exe",
                "SettingSyncHost.exe",
                "backgroundTaskHost.exe",
                "CompPkgSrv.exe",
                "LockApp.exe",
                "Registry",
                "MemCompression",
                "Idle",
                # Browsers
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "brave.exe",
                "opera.exe",
                "vivaldi.exe",
                "duckduckgo.exe",
                # Dev tools
                "Code.exe",
                "cursor.exe",
                "Cursor.exe",
                "node.exe",
                "python.exe",
                "pythonw.exe",
                "git.exe",
                "WindowsTerminal.exe",
                "powershell.exe",
                "cmd.exe",
                "wsl.exe",
                "docker.exe",
                "Docker Desktop.exe",
                # Common apps
                "Spotify.exe",
                "Discord.exe",
                "slack.exe",
                "Teams.exe",
                "Zoom.exe",
                "OneDrive.exe",
                "Dropbox.exe",
                "Steam.exe",
                "EpicGamesLauncher.exe",
                "1Password.exe",
                "Bitwarden.exe",
                "KeePass.exe",
                "Notion.exe",
                "Obsidian.exe",
                "Postman.exe",
                "vlc.exe",
                "NVIDIA Share.exe",
                "nvcontainer.exe",
                "nvidia-smi.exe",
                "amdow.exe",
                "RadeonSoftware.exe",
            ]
        else:
            system_processes = [
                "systemd",
                "init",
                "kthreadd",
                "kworker",
                "ksoftirqd",
                "migration",
                "rcu_sched",
                "watchdog",
                "bash",
                "sh",
                "zsh",
                "fish",
                "sshd",
                "cron",
                "dbus-daemon",
                "NetworkManager",
                "pulseaudio",
                "pipewire",
                "Xorg",
                "gdm",
                "lightdm",
                "gnome-shell",
                "kwin",
            ]
        
        self._system_processes = {p.lower() for p in system_processes}
        logger.info(f"Loaded {len(self._system_processes)} default system processes")
    
    def is_trusted(
        self,
        name: str,
        path: Optional[str] = None,
        hash_sha256: Optional[str] = None,
    ) -> bool:
        """Check if a process is trusted."""
        name_lower = name.lower()
        
        if name_lower in self._system_processes:
            return True
        
        if path:
            path_obj = Path(path)
            if PlatformUtils.is_system_process(path_obj):
                return True
        
        cache_key = f"{name_lower}:{path or ''}:{hash_sha256 or ''}"
        if cache_key in self._cache:
            return True
        
        if self.db.is_process_trusted(name, path, hash_sha256):
            self._cache[cache_key] = WhitelistEntry(
                name=name,
                path=path,
                hash_sha256=hash_sha256,
            )
            return True
        
        return False
    
    def add(
        self,
        name: str,
        path: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        publisher: Optional[str] = None,
        added_by: str = "user",
        reason: Optional[str] = None,
    ) -> WhitelistEntry:
        """Add a process to the whitelist."""
        self.db.add_trusted_process(
            name=name,
            path=path,
            hash_sha256=hash_sha256,
            publisher=publisher,
            added_by=added_by,
            reason=reason,
        )
        
        entry = WhitelistEntry(
            name=name,
            path=path,
            hash_sha256=hash_sha256,
            publisher=publisher,
            added_at=datetime.utcnow(),
            added_by=added_by,
            reason=reason,
        )
        
        cache_key = f"{name.lower()}:{path or ''}:{hash_sha256 or ''}"
        self._cache[cache_key] = entry
        
        logger.info(f"Added to whitelist: {name} (by {added_by})")
        return entry
    
    def remove(self, name: str, path: Optional[str] = None) -> bool:
        """Remove a process from the whitelist."""
        with self.db.get_session() as session:
            query = session.query(TrustedProcess).filter_by(name=name)
            if path:
                query = query.filter_by(path=path)
            
            result = query.first()
            if result:
                session.delete(result)
                session.commit()
                
                keys_to_remove = [
                    k for k in self._cache.keys()
                    if k.startswith(f"{name.lower()}:")
                ]
                for key in keys_to_remove:
                    del self._cache[key]
                
                logger.info(f"Removed from whitelist: {name}")
                return True
        
        return False
    
    def get_all(self) -> list[WhitelistEntry]:
        """Get all whitelist entries."""
        entries = []
        
        for name in self._system_processes:
            entries.append(WhitelistEntry(
                name=name,
                added_by="system",
                reason="Default system process",
            ))
        
        with self.db.get_session() as session:
            for trusted in session.query(TrustedProcess).all():
                entries.append(WhitelistEntry(
                    name=trusted.name,
                    path=trusted.path,
                    hash_sha256=trusted.hash_sha256,
                    publisher=trusted.publisher,
                    added_at=trusted.added_at,
                    added_by=trusted.added_by,
                    reason=trusted.reason,
                ))
        
        return entries
    
    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        self._cache.clear()
        logger.debug("Whitelist cache cleared")
    
    def is_known_browser(self, name: str) -> bool:
        """Check if a process is a known browser."""
        browsers = PlatformUtils.get_known_browsers()
        return name.lower() in [b.lower() for b in browsers]
