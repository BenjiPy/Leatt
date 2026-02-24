"""Tests for the process monitor module."""

import pytest
import threading
from queue import Queue
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(__file__).rsplit('tests', 1)[0] + 'src')

from core.process_monitor import ProcessMonitor, ProcessInfo


class TestProcessInfo:
    """Tests for ProcessInfo dataclass."""
    
    def test_process_info_creation(self):
        """Test creating a ProcessInfo instance."""
        info = ProcessInfo(
            pid=1234,
            name="test.exe",
            path="C:\\test\\test.exe",
            user="testuser",
        )
        
        assert info.pid == 1234
        assert info.name == "test.exe"
        assert info.path == "C:\\test\\test.exe"
        assert info.user == "testuser"
        assert info.is_trusted is False
        assert info.risk_score == 0.0
    
    def test_process_info_defaults(self):
        """Test ProcessInfo default values."""
        info = ProcessInfo(pid=1, name="test")
        
        assert info.path is None
        assert info.user is None
        assert info.cpu_percent == 0.0
        assert info.memory_percent == 0.0
        assert info.num_connections == 0


class TestProcessMonitor:
    """Tests for ProcessMonitor class."""
    
    @pytest.fixture
    def monitor(self):
        """Create a ProcessMonitor instance for testing."""
        event_queue = Queue()
        stop_event = threading.Event()
        
        with patch('core.process_monitor.get_database') as mock_db:
            mock_db.return_value = MagicMock()
            monitor = ProcessMonitor(
                event_queue=event_queue,
                stop_event=stop_event,
                interval=1,
            )
        
        return monitor
    
    def test_monitor_initialization(self, monitor):
        """Test monitor initializes correctly."""
        assert monitor.interval == 1
        assert len(monitor._known_processes) == 0
    
    def test_get_process_by_pid_returns_none_for_unknown(self, monitor):
        """Test getting unknown process returns None."""
        result = monitor.get_process_by_pid(99999)
        assert result is None
    
    def test_get_all_processes_empty_initially(self, monitor):
        """Test all processes list is empty initially."""
        processes = monitor.get_all_processes()
        assert len(processes) == 0
    
    @patch('core.process_monitor.psutil')
    def test_scan_detects_new_process(self, mock_psutil, monitor):
        """Test that scanning detects new processes."""
        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_proc.name.return_value = "test.exe"
        mock_proc.exe.return_value = "C:\\test.exe"
        mock_proc.username.return_value = "user"
        mock_proc.cmdline.return_value = []
        mock_proc.create_time.return_value = 0.0
        mock_proc.cpu_percent.return_value = 1.0
        mock_proc.memory_percent.return_value = 2.0
        mock_proc.net_connections.return_value = []
        mock_proc.io_counters.return_value = MagicMock(read_bytes=0, write_bytes=0)
        
        mock_psutil.process_iter.return_value = [mock_proc]
        
        monitor.db.is_process_trusted.return_value = True
        
        monitor._scan_processes()
        
        assert 1234 in monitor._known_processes
