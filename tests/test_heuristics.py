"""Tests for the heuristics engine module."""

import pytest
import time
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(__file__).rsplit('tests', 1)[0] + 'src')

from detection.heuristics import HeuristicsEngine, ProcessActivity, HeuristicPattern


class TestProcessActivity:
    """Tests for ProcessActivity dataclass."""
    
    def test_activity_creation(self):
        """Test creating a ProcessActivity."""
        activity = ProcessActivity(pid=1234, name="test.exe")
        
        assert activity.pid == 1234
        assert activity.name == "test.exe"
        assert activity.sensitive_files_accessed == 0
        assert activity.bytes_uploaded == 0
        assert len(activity.unique_destinations) == 0


class TestHeuristicsEngine:
    """Tests for HeuristicsEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create a HeuristicsEngine instance for testing."""
        with patch('detection.heuristics.get_config') as mock_config:
            mock_config.return_value = MagicMock()
            mock_config.return_value.get_rule.return_value = 60
            engine = HeuristicsEngine()
        
        return engine
    
    def test_engine_loads_patterns(self, engine):
        """Test that heuristic patterns are loaded."""
        assert len(engine._patterns) > 0
    
    def test_analyze_file_event(self, engine):
        """Test analyzing a file access event."""
        event = MagicMock()
        event.source = "file_monitor"
        event.data = {
            "pid": 1234,
            "process_name": "test.exe",
            "file_path": "/home/user/document.txt",
            "event_type": "modified",
            "is_sensitive": False,
        }
        
        alerts = engine.analyze(event)
        
        assert 1234 in engine._process_activities
    
    def test_analyze_network_event(self, engine):
        """Test analyzing a network event."""
        event = MagicMock()
        event.source = "network_monitor"
        event.data = {
            "pid": 1234,
            "process_name": "test.exe",
            "remote_address": "192.168.1.1",
            "bytes_uploaded": 1024,
        }
        
        engine.analyze(event)
        
        activity = engine._process_activities.get(1234)
        assert activity is not None
        assert activity.bytes_uploaded == 1024
        assert "192.168.1.1" in activity.unique_destinations
    
    def test_credential_theft_detection(self, engine):
        """Test credential theft pattern detection."""
        event = MagicMock()
        event.source = "file_monitor"
        event.data = {
            "pid": 1234,
            "process_name": "suspicious.exe",
            "file_path": "/home/user/.mozilla/firefox/profile/cookies.sqlite",
            "event_type": "read",
            "is_sensitive": True,
        }
        
        alerts = engine.analyze(event)
        
        credential_alerts = [a for a in alerts if "credential" in a["source"].lower()]
        assert len(credential_alerts) > 0
    
    def test_get_process_risk_score(self, engine):
        """Test getting risk score for unknown process."""
        score = engine.get_process_risk_score(99999)
        assert score == 0.0
    
    def test_get_activity_summary_unknown(self, engine):
        """Test getting summary for unknown process."""
        summary = engine.get_activity_summary(99999)
        assert summary is None
    
    def test_get_activity_summary_known(self, engine):
        """Test getting summary for known process."""
        engine._process_activities[1234] = ProcessActivity(
            pid=1234,
            name="test.exe",
        )
        engine._process_activities[1234].sensitive_files_accessed = 5
        
        summary = engine.get_activity_summary(1234)
        
        assert summary is not None
        assert summary["pid"] == 1234
        assert summary["sensitive_files"] == 5
