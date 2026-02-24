"""Tests for the rules engine module."""

import pytest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(__file__).rsplit('tests', 1)[0] + 'src')

from detection.rules_engine import RulesEngine, Rule, RuleType
from utils.database import AlertSeverity


class TestRule:
    """Tests for Rule dataclass."""
    
    def test_rule_creation(self):
        """Test creating a Rule instance."""
        rule = Rule(
            name="test_rule",
            rule_type=RuleType.PROCESS,
            description="Test rule",
            severity=AlertSeverity.HIGH,
        )
        
        assert rule.name == "test_rule"
        assert rule.rule_type == RuleType.PROCESS
        assert rule.severity == AlertSeverity.HIGH
        assert rule.enabled is True
        assert rule.conditions == {}


class TestRulesEngine:
    """Tests for RulesEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create a RulesEngine instance for testing."""
        with patch('detection.rules_engine.get_config') as mock_config:
            mock_config.return_value = MagicMock(
                suspicious_process_names=["malware.exe"],
                suspicious_ports=[4444],
                max_upload_mb_per_min=50,
                sensitive_extensions=[".key", ".pem"],
            )
            engine = RulesEngine()
        
        return engine
    
    def test_engine_loads_default_rules(self, engine):
        """Test that default rules are loaded."""
        assert len(engine.rules) > 0
    
    def test_add_rule(self, engine):
        """Test adding a custom rule."""
        initial_count = len(engine.rules)
        
        rule = Rule(
            name="custom_rule",
            rule_type=RuleType.FILE,
            description="Custom test rule",
            severity=AlertSeverity.LOW,
        )
        
        engine.add_rule(rule)
        
        assert len(engine.rules) == initial_count + 1
    
    def test_remove_rule(self, engine):
        """Test removing a rule."""
        rule = Rule(
            name="temp_rule",
            rule_type=RuleType.PROCESS,
            description="Temp rule",
            severity=AlertSeverity.LOW,
        )
        engine.add_rule(rule)
        
        result = engine.remove_rule("temp_rule")
        
        assert result is True
    
    def test_disable_rule(self, engine):
        """Test disabling a rule."""
        result = engine.disable_rule("suspicious_process_name")
        
        assert result is True
        
        disabled_rule = next(r for r in engine.rules if r.name == "suspicious_process_name")
        assert disabled_rule.enabled is False
    
    def test_enable_rule(self, engine):
        """Test enabling a rule."""
        engine.disable_rule("suspicious_process_name")
        
        result = engine.enable_rule("suspicious_process_name")
        
        assert result is True
        
        enabled_rule = next(r for r in engine.rules if r.name == "suspicious_process_name")
        assert enabled_rule.enabled is True
    
    def test_evaluate_suspicious_process(self, engine):
        """Test evaluating a suspicious process event."""
        event = MagicMock()
        event.source = "process_monitor"
        event.data = {
            "process_name": "malware.exe",
            "pid": 1234,
            "is_trusted": False,
        }
        
        alerts = engine.evaluate(event)
        
        assert len(alerts) > 0
        assert any(a["severity"] == AlertSeverity.CRITICAL for a in alerts)
    
    def test_evaluate_normal_process(self, engine):
        """Test evaluating a normal trusted process."""
        event = MagicMock()
        event.source = "process_monitor"
        event.data = {
            "process_name": "notepad.exe",
            "pid": 1234,
            "is_trusted": True,
        }
        
        alerts = engine.evaluate(event)
        
        critical_alerts = [a for a in alerts if a["severity"] == AlertSeverity.CRITICAL]
        assert len(critical_alerts) == 0
    
    def test_get_enabled_rules(self, engine):
        """Test getting only enabled rules."""
        engine.disable_rule("untrusted_process")
        
        enabled = engine.get_enabled_rules()
        
        assert all(r.enabled for r in enabled)
        assert not any(r.name == "untrusted_process" for r in enabled)
