"""
Agent Drift Dashboard - SIEM-like interface for drift monitoring.
"""

from .server import DriftDashboard, create_app

__all__ = ["DriftDashboard", "create_app"]
