"""
Honeypot Tool Monitor for Agent Drift v0.1.2

Honeypot tools are decoy tools that should NEVER be called by a legitimate agent.
If accessed, it's a high-confidence indicator of compromise (IoC).

Features:
- Configure honeypot tools via CLI, API, or file
- Instant CRITICAL alerts on honeypot access
- Full trace capture for forensic analysis
- Persistent configuration storage
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from .models import HoneypotConfig, HoneypotAlert, Severity


class HoneypotMonitor:
    """
    Monitor for honeypot tool access.
    
    Honeypot tools are decoy/canary tools that should never be called
    during normal operation. Any access is a high-confidence indicator
    of agent compromise.
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else Path.home() / ".agent-drift"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_path = self.storage_dir / "honeypot_config.json"
        self.alerts_path = self.storage_dir / "honeypot_alerts.json"
        
        self.config = self._load_config()
        self.alerts: List[HoneypotAlert] = self._load_alerts()
    
    def _load_config(self) -> HoneypotConfig:
        """Load honeypot configuration from disk."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                return HoneypotConfig.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Create new config
        config = HoneypotConfig(
            tools=set(),
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
        )
        self._save_config(config)
        return config
    
    def _save_config(self, config: Optional[HoneypotConfig] = None):
        """Save honeypot configuration to disk."""
        config = config or self.config
        with open(self.config_path, "w") as f:
            json.dump(config.to_dict(), f, indent=2)
    
    def _load_alerts(self) -> List[HoneypotAlert]:
        """Load historical honeypot alerts."""
        if self.alerts_path.exists():
            try:
                with open(self.alerts_path) as f:
                    data = json.load(f)
                return [
                    HoneypotAlert(
                        tool_name=a["tool_name"],
                        timestamp=a["timestamp"],
                        run_id=a["run_id"],
                        severity=Severity.CRITICAL,
                        args=a.get("args"),
                    )
                    for a in data
                ]
            except (json.JSONDecodeError, KeyError):
                pass
        return []
    
    def _save_alerts(self):
        """Save honeypot alerts to disk."""
        with open(self.alerts_path, "w") as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
    
    # ========================================================================
    # Configuration Methods
    # ========================================================================
    
    def add_tool(self, tool_name: str) -> bool:
        """
        Add a tool as a honeypot.
        
        Args:
            tool_name: Name of the tool to mark as honeypot
            
        Returns:
            True if added, False if already existed
        """
        if tool_name in self.config.tools:
            return False
        
        self.config.add_tool(tool_name)
        self._save_config()
        return True
    
    def remove_tool(self, tool_name: str) -> bool:
        """
        Remove a tool from honeypot list.
        
        Args:
            tool_name: Name of the tool to remove
            
        Returns:
            True if removed, False if didn't exist
        """
        result = self.config.remove_tool(tool_name)
        if result:
            self._save_config()
        return result
    
    def clear_all(self):
        """Clear all honeypot tools."""
        self.config.clear()
        self._save_config()
    
    def list_tools(self) -> List[str]:
        """Get list of all honeypot tools."""
        return sorted(list(self.config.tools))
    
    def is_honeypot(self, tool_name: str) -> bool:
        """Check if a tool is configured as a honeypot."""
        return self.config.is_honeypot(tool_name)
    
    # ========================================================================
    # Monitoring Methods
    # ========================================================================
    
    def check_tool(
        self, 
        tool_name: str, 
        run_id: str,
        args: Optional[Dict] = None,
    ) -> Optional[HoneypotAlert]:
        """
        Check if a tool call is a honeypot access.
        
        Args:
            tool_name: Name of the tool being called
            run_id: Current session/run ID
            args: Tool arguments (for forensic logging)
            
        Returns:
            HoneypotAlert if honeypot accessed, None otherwise
        """
        if not self.config.is_honeypot(tool_name):
            return None
        
        alert = HoneypotAlert(
            tool_name=tool_name,
            timestamp=time.time(),
            run_id=run_id,
            severity=Severity.CRITICAL,
            args=args,
        )
        
        self.alerts.append(alert)
        self._save_alerts()
        
        return alert
    
    def get_alerts(
        self, 
        limit: int = 100,
        run_id: Optional[str] = None,
    ) -> List[HoneypotAlert]:
        """
        Get honeypot alerts.
        
        Args:
            limit: Maximum number of alerts to return
            run_id: Filter by run ID
            
        Returns:
            List of honeypot alerts
        """
        alerts = self.alerts
        
        if run_id:
            alerts = [a for a in alerts if a.run_id == run_id]
        
        return alerts[-limit:]
    
    def clear_alerts(self):
        """Clear all honeypot alerts."""
        self.alerts = []
        self._save_alerts()
    
    # ========================================================================
    # Status Methods
    # ========================================================================
    
    def get_status(self) -> Dict:
        """Get honeypot monitor status."""
        return {
            "configured_tools": self.list_tools(),
            "tool_count": len(self.config.tools),
            "total_alerts": len(self.alerts),
            "recent_alerts": len([a for a in self.alerts if time.time() - a.timestamp < 86400]),
            "config_created": self.config.created_at,
            "config_updated": self.config.updated_at,
        }
    
    def get_config_dict(self) -> Dict:
        """Get configuration as dictionary."""
        return self.config.to_dict()


# Default recommended honeypot tools for AI agents
RECOMMENDED_HONEYPOTS = [
    "admin_override",
    "debug_mode",
    "system_shell",
    "raw_sql_query",
    "bypass_auth",
    "delete_all_data",
    "export_secrets",
    "modify_system_prompt",
    "disable_safety",
    "unrestricted_exec",
]


def get_recommended_honeypots() -> List[str]:
    """Get list of recommended honeypot tool names."""
    return RECOMMENDED_HONEYPOTS.copy()
