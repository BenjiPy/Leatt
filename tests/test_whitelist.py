"""Tests for the whitelist module."""

import pytest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(__file__).rsplit('tests', 1)[0] + 'src')

from trust.whitelist import Whitelist, WhitelistEntry


class TestWhitelistEntry:
    """Tests for WhitelistEntry dataclass."""
    
    def test_entry_creation(self):
        """Test creating a WhitelistEntry."""
        entry = WhitelistEntry(
            name="notepad.exe",
            path="C:\\Windows\\System32\\notepad.exe",
            added_by="user",
        )
        
        assert entry.name == "notepad.exe"
        assert entry.added_by == "user"
        assert entry.hash_sha256 is None


class TestWhitelist:
    """Tests for Whitelist class."""
    
    @pytest.fixture
    def whitelist(self):
        """Create a Whitelist instance for testing."""
        with patch('trust.whitelist.get_database') as mock_db:
            mock_db.return_value = MagicMock()
            mock_db.return_value.is_process_trusted.return_value = False
            mock_db.return_value.get_session.return_value.__enter__ = MagicMock()
            mock_db.return_value.get_session.return_value.__exit__ = MagicMock()
            
            whitelist = Whitelist()
        
        return whitelist
    
    def test_whitelist_loads_system_defaults(self, whitelist):
        """Test that system processes are loaded by default."""
        assert len(whitelist._system_processes) > 0
    
    def test_system_process_is_trusted(self, whitelist):
        """Test that system processes are trusted."""
        assert whitelist.is_trusted("svchost.exe") or whitelist.is_trusted("systemd")
    
    def test_unknown_process_not_trusted(self, whitelist):
        """Test that unknown processes are not trusted."""
        assert whitelist.is_trusted("totally_unknown_process_xyz.exe") is False
    
    def test_add_to_whitelist(self, whitelist):
        """Test adding a process to whitelist."""
        whitelist.db.add_trusted_process.return_value = MagicMock()
        
        entry = whitelist.add(
            name="myapp.exe",
            path="C:\\MyApp\\myapp.exe",
            reason="User trusted",
        )
        
        assert entry.name == "myapp.exe"
        whitelist.db.add_trusted_process.assert_called_once()
    
    def test_is_known_browser(self, whitelist):
        """Test browser detection."""
        assert whitelist.is_known_browser("chrome.exe") is True
        assert whitelist.is_known_browser("firefox.exe") is True
        assert whitelist.is_known_browser("myapp.exe") is False
    
    def test_clear_cache(self, whitelist):
        """Test clearing the cache."""
        whitelist._cache["test"] = WhitelistEntry(name="test")
        
        whitelist.clear_cache()
        
        assert len(whitelist._cache) == 0
