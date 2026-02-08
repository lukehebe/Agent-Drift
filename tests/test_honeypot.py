"""
Tests for honeypot functionality.
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from src.honeypot import HoneypotMonitor, get_recommended_honeypots
from src.models import Severity


class TestHoneypotMonitor:
    """Test honeypot tool monitoring."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        d = tempfile.mkdtemp()
        yield d
        shutil.rmtree(d)
    
    @pytest.fixture
    def monitor(self, temp_dir):
        """Create honeypot monitor with temp storage."""
        return HoneypotMonitor(storage_dir=temp_dir)
    
    def test_add_honeypot(self, monitor):
        """Test adding a honeypot tool."""
        assert monitor.add_tool("dangerous_tool") == True
        assert monitor.is_honeypot("dangerous_tool") == True
        
        # Adding again should return False
        assert monitor.add_tool("dangerous_tool") == False
    
    def test_remove_honeypot(self, monitor):
        """Test removing a honeypot tool."""
        monitor.add_tool("test_tool")
        assert monitor.remove_tool("test_tool") == True
        assert monitor.is_honeypot("test_tool") == False
        
        # Removing non-existent should return False
        assert monitor.remove_tool("nonexistent") == False
    
    def test_list_tools(self, monitor):
        """Test listing honeypot tools."""
        monitor.add_tool("tool_a")
        monitor.add_tool("tool_b")
        monitor.add_tool("tool_c")
        
        tools = monitor.list_tools()
        assert len(tools) == 3
        assert "tool_a" in tools
        assert "tool_b" in tools
        assert "tool_c" in tools
    
    def test_clear_all(self, monitor):
        """Test clearing all honeypot tools."""
        monitor.add_tool("tool1")
        monitor.add_tool("tool2")
        assert len(monitor.list_tools()) == 2
        
        monitor.clear_all()
        assert len(monitor.list_tools()) == 0
    
    def test_check_tool_honeypot(self, monitor):
        """Test checking a honeypot tool triggers alert."""
        monitor.add_tool("secret_admin")
        
        alert = monitor.check_tool("secret_admin", "run-123", {"arg": "value"})
        
        assert alert is not None
        assert alert.tool_name == "secret_admin"
        assert alert.run_id == "run-123"
        assert alert.severity == Severity.CRITICAL
    
    def test_check_tool_normal(self, monitor):
        """Test checking a normal tool returns None."""
        monitor.add_tool("honeypot_tool")
        
        alert = monitor.check_tool("normal_tool", "run-123")
        assert alert is None
    
    def test_get_alerts(self, monitor):
        """Test retrieving honeypot alerts."""
        monitor.add_tool("trap1")
        monitor.add_tool("trap2")
        
        monitor.check_tool("trap1", "run-1")
        monitor.check_tool("trap2", "run-2")
        monitor.check_tool("trap1", "run-3")
        
        alerts = monitor.get_alerts()
        assert len(alerts) == 3
    
    def test_persistence(self, temp_dir):
        """Test that honeypot config persists across instances."""
        # Create and configure
        m1 = HoneypotMonitor(storage_dir=temp_dir)
        m1.add_tool("persistent_tool")
        
        # Create new instance
        m2 = HoneypotMonitor(storage_dir=temp_dir)
        assert m2.is_honeypot("persistent_tool") == True
    
    def test_get_status(self, monitor):
        """Test getting honeypot status."""
        monitor.add_tool("tool1")
        monitor.add_tool("tool2")
        monitor.check_tool("tool1", "run-1")
        
        status = monitor.get_status()
        
        assert status["tool_count"] == 2
        assert status["total_alerts"] == 1
        assert "tool1" in status["configured_tools"]
        assert "tool2" in status["configured_tools"]


class TestRecommendedHoneypots:
    """Test recommended honeypot list."""
    
    def test_get_recommended(self):
        """Test getting recommended honeypots."""
        recommended = get_recommended_honeypots()
        
        assert len(recommended) > 0
        assert "admin_override" in recommended
        assert "debug_mode" in recommended
