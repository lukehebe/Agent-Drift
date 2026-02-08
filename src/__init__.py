"""
Agent Drift Detector v0.1.2

Runtime behavioral monitoring for AI agents.
Detects prompt injection, memory poisoning, behavioral drift,
and OWASP Top 10 LLM vulnerabilities in real-time.

Features:
- Behavioral drift detection
- OWASP Top 10 LLM threat scanning
- Honeypot tool monitoring
- Real-time SIEM dashboard
"""

__version__ = "0.1.2"
__author__ = "Luke Hebenstreit"

from .models import (
    BehaviorTrace,
    BehaviorVector,
    Baseline,
    DriftReport,
    Severity,
    OWASPCategory,
    HoneypotConfig,
    HoneypotAlert,
)
from .detector import DriftDetector
from .baseline import BaselineManager
from .vectorizer import BehaviorVectorizer
from .owasp import OWASPScanner, BehavioralOWASPAnalyzer
from .honeypot import HoneypotMonitor

__all__ = [
    # Models
    "BehaviorTrace",
    "BehaviorVector",
    "Baseline",
    "DriftReport",
    "Severity",
    "OWASPCategory",
    "HoneypotConfig",
    "HoneypotAlert",
    # Core
    "DriftDetector",
    "BaselineManager",
    "BehaviorVectorizer",
    # Security
    "OWASPScanner",
    "BehavioralOWASPAnalyzer",
    "HoneypotMonitor",
]
