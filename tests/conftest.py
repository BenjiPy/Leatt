"""Pytest configuration and fixtures."""

import pytest
import sys
from pathlib import Path

src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    from unittest.mock import MagicMock
    
    config = MagicMock()
    config.app_name = "Leatt"
    config.app_version = "0.1.0"
    config.learning_mode = True
    config.process_monitoring_enabled = True
    config.file_monitoring_enabled = True
    config.network_monitoring_enabled = True
    config.registry_monitoring_enabled = True
    config.notifications_enabled = True
    config.ml_enabled = False
    config.process_interval = 5
    config.network_interval = 3
    config.suspicious_process_names = ["malware.exe"]
    config.suspicious_ports = [4444, 5555]
    config.max_upload_mb_per_min = 50
    config.sensitive_extensions = [".key", ".pem", ".env"]
    config.watched_folders = []
    
    return config


@pytest.fixture
def mock_database():
    """Create a mock database."""
    from unittest.mock import MagicMock
    
    db = MagicMock()
    db.is_process_trusted.return_value = False
    db.add_alert.return_value = MagicMock(id=1)
    db.add_process.return_value = MagicMock(id=1)
    db.get_recent_alerts.return_value = []
    db.get_unacknowledged_alerts.return_value = []
    
    return db


@pytest.fixture
def sample_process_event():
    """Create a sample process monitoring event."""
    from unittest.mock import MagicMock
    import time
    
    event = MagicMock()
    event.source = "process_monitor"
    event.event_type = "new_process"
    event.timestamp = time.time()
    event.data = {
        "pid": 1234,
        "process_name": "test.exe",
        "path": "C:\\test\\test.exe",
        "user": "testuser",
        "is_trusted": False,
    }
    event.risk_score = 0.0
    
    return event


@pytest.fixture
def sample_network_event():
    """Create a sample network monitoring event."""
    from unittest.mock import MagicMock
    import time
    
    event = MagicMock()
    event.source = "network_monitor"
    event.event_type = "suspicious_port"
    event.timestamp = time.time()
    event.data = {
        "pid": 1234,
        "process_name": "suspicious.exe",
        "remote_address": "192.168.1.100",
        "remote_port": 4444,
    }
    event.risk_score = 60.0
    
    return event


@pytest.fixture
def sample_file_event():
    """Create a sample file monitoring event."""
    from unittest.mock import MagicMock
    import time
    
    event = MagicMock()
    event.source = "file_monitor"
    event.event_type = "file_modified"
    event.timestamp = time.time()
    event.data = {
        "file_path": "C:\\Users\\test\\Documents\\secret.key",
        "event_type": "modified",
        "is_sensitive": True,
    }
    event.risk_score = 30.0
    
    return event
