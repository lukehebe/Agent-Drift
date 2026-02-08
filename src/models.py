"""
Data models for Agent Drift v0.1.2

Includes:
- Behavioral trace models
- OWASP Top 10 LLM threat classifications
- Honeypot configuration
- Drift report models
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from enum import Enum
import json


class Severity(Enum):
    """Severity levels for alerts and detections."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(Enum):
    """OWASP Top 10 for LLM Applications v1.1 categories."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM03_TRAINING_POISONING = "LLM03"
    LLM04_MODEL_DOS = "LLM04"
    LLM05_SUPPLY_CHAIN = "LLM05"
    LLM06_SENSITIVE_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"


@dataclass
class ToolInvocation:
    """Represents a single tool call by the agent."""
    tool_name: str
    timestamp: float
    duration_ms: float
    success: bool
    arg_count: int = 0
    arg_types: List[str] = field(default_factory=list)
    is_honeypot: bool = False


@dataclass
class FileAccess:
    """Represents a file system access event."""
    path: str
    operation: str  # read, write, delete, create
    timestamp: float
    size_bytes: Optional[int] = None


@dataclass
class NetworkCall:
    """Represents a network request (structure only)."""
    destination_class: str  # 'api', 'cdn', 'internal', 'external', 'unknown'
    method: str  # GET, POST, etc
    timestamp: float
    duration_ms: float
    status_class: str  # '2xx', '4xx', '5xx', 'timeout', 'error'


@dataclass 
class DecisionCycle:
    """Represents an agent decision boundary."""
    cycle_id: int
    start_time: float
    end_time: float
    tool_count: int
    retry_count: int
    self_corrections: int


@dataclass
class HoneypotConfig:
    """Configuration for honeypot tools."""
    tools: Set[str] = field(default_factory=set)
    created_at: str = ""
    updated_at: str = ""
    
    def add_tool(self, tool_name: str):
        """Add a honeypot tool."""
        self.tools.add(tool_name)
        self.updated_at = datetime.utcnow().isoformat()
    
    def remove_tool(self, tool_name: str) -> bool:
        """Remove a honeypot tool. Returns True if removed."""
        if tool_name in self.tools:
            self.tools.discard(tool_name)
            self.updated_at = datetime.utcnow().isoformat()
            return True
        return False
    
    def is_honeypot(self, tool_name: str) -> bool:
        """Check if a tool is a honeypot."""
        return tool_name in self.tools
    
    def clear(self):
        """Clear all honeypot tools."""
        self.tools.clear()
        self.updated_at = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tools": list(self.tools),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HoneypotConfig":
        return cls(
            tools=set(data.get("tools", [])),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class OWASPDetection:
    """Detection of an OWASP Top 10 LLM threat."""
    category: OWASPCategory
    name: str
    severity: Severity
    description: str
    matches: List[str] = field(default_factory=list)
    timestamp: float = 0.0
    source: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "matches": self.matches,
            "timestamp": self.timestamp,
            "source": self.source,
        }


@dataclass
class HoneypotAlert:
    """Alert triggered by honeypot tool access."""
    tool_name: str
    timestamp: float
    run_id: str
    severity: Severity = Severity.CRITICAL
    args: Optional[Dict] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "honeypot",
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "severity": self.severity.value,
            "args": self.args,
            "message": f"HONEYPOT ACCESS: Tool '{self.tool_name}' was called - high confidence compromise indicator",
        }


@dataclass
class BehaviorTrace:
    """Complete behavioral trace for a single agent run."""
    run_id: str
    start_time: float
    end_time: float
    tool_invocations: List[ToolInvocation] = field(default_factory=list)
    file_accesses: List[FileAccess] = field(default_factory=list)
    network_calls: List[NetworkCall] = field(default_factory=list)
    decision_cycles: List[DecisionCycle] = field(default_factory=list)
    honeypot_alerts: List[HoneypotAlert] = field(default_factory=list)
    owasp_detections: List[OWASPDetection] = field(default_factory=list)
    stdout_line_count: int = 0
    stderr_line_count: int = 0
    exit_code: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "run_id": self.run_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "tool_invocations": [
                {
                    "tool_name": t.tool_name,
                    "timestamp": t.timestamp,
                    "duration_ms": t.duration_ms,
                    "success": t.success,
                    "arg_count": t.arg_count,
                    "arg_types": t.arg_types,
                    "is_honeypot": t.is_honeypot,
                }
                for t in self.tool_invocations
            ],
            "file_accesses": [
                {
                    "path": f.path,
                    "operation": f.operation,
                    "timestamp": f.timestamp,
                    "size_bytes": f.size_bytes,
                }
                for f in self.file_accesses
            ],
            "network_calls": [
                {
                    "destination_class": n.destination_class,
                    "method": n.method,
                    "timestamp": n.timestamp,
                    "duration_ms": n.duration_ms,
                    "status_class": n.status_class,
                }
                for n in self.network_calls
            ],
            "decision_cycles": [
                {
                    "cycle_id": d.cycle_id,
                    "start_time": d.start_time,
                    "end_time": d.end_time,
                    "tool_count": d.tool_count,
                    "retry_count": d.retry_count,
                    "self_corrections": d.self_corrections,
                }
                for d in self.decision_cycles
            ],
            "honeypot_alerts": [h.to_dict() for h in self.honeypot_alerts],
            "owasp_detections": [o.to_dict() for o in self.owasp_detections],
            "stdout_line_count": self.stdout_line_count,
            "stderr_line_count": self.stderr_line_count,
            "exit_code": self.exit_code,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BehaviorTrace":
        """Deserialize from dictionary."""
        trace = cls(
            run_id=data["run_id"],
            start_time=data["start_time"],
            end_time=data["end_time"],
            stdout_line_count=data.get("stdout_line_count", 0),
            stderr_line_count=data.get("stderr_line_count", 0),
            exit_code=data.get("exit_code", 0),
        )
        
        trace.tool_invocations = [
            ToolInvocation(**t) for t in data.get("tool_invocations", [])
        ]
        trace.file_accesses = [
            FileAccess(**f) for f in data.get("file_accesses", [])
        ]
        trace.network_calls = [
            NetworkCall(**n) for n in data.get("network_calls", [])
        ]
        trace.decision_cycles = [
            DecisionCycle(**d) for d in data.get("decision_cycles", [])
        ]
        
        return trace


@dataclass
class BehaviorVector:
    """Structural vector representation of agent behavior."""
    # Tool sequence features
    tool_sequence: List[str] = field(default_factory=list)
    tool_frequency: Dict[str, int] = field(default_factory=dict)
    tool_transitions: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Timing features
    mean_tool_duration_ms: float = 0.0
    std_tool_duration_ms: float = 0.0
    mean_inter_tool_delay_ms: float = 0.0
    std_inter_tool_delay_ms: float = 0.0
    total_duration_ms: float = 0.0
    
    # Decision features
    total_cycles: int = 0
    mean_tools_per_cycle: float = 0.0
    total_retries: int = 0
    total_self_corrections: int = 0
    retry_rate: float = 0.0
    
    # File access features  
    file_op_frequency: Dict[str, int] = field(default_factory=dict)
    unique_paths_accessed: int = 0
    write_to_read_ratio: float = 0.0
    
    # Network features
    network_call_count: int = 0
    destination_class_freq: Dict[str, int] = field(default_factory=dict)
    error_rate: float = 0.0
    
    # Output features
    stdout_lines: int = 0
    stderr_lines: int = 0
    stderr_ratio: float = 0.0
    
    # Security features
    honeypot_access_count: int = 0
    owasp_detection_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "tool_sequence": self.tool_sequence,
            "tool_frequency": self.tool_frequency,
            "tool_transitions": self.tool_transitions,
            "mean_tool_duration_ms": self.mean_tool_duration_ms,
            "std_tool_duration_ms": self.std_tool_duration_ms,
            "mean_inter_tool_delay_ms": self.mean_inter_tool_delay_ms,
            "std_inter_tool_delay_ms": self.std_inter_tool_delay_ms,
            "total_duration_ms": self.total_duration_ms,
            "total_cycles": self.total_cycles,
            "mean_tools_per_cycle": self.mean_tools_per_cycle,
            "total_retries": self.total_retries,
            "total_self_corrections": self.total_self_corrections,
            "retry_rate": self.retry_rate,
            "file_op_frequency": self.file_op_frequency,
            "unique_paths_accessed": self.unique_paths_accessed,
            "write_to_read_ratio": self.write_to_read_ratio,
            "network_call_count": self.network_call_count,
            "destination_class_freq": self.destination_class_freq,
            "error_rate": self.error_rate,
            "stdout_lines": self.stdout_lines,
            "stderr_lines": self.stderr_lines,
            "stderr_ratio": self.stderr_ratio,
            "honeypot_access_count": self.honeypot_access_count,
            "owasp_detection_count": self.owasp_detection_count,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BehaviorVector":
        """Deserialize from dictionary."""
        return cls(**data)


@dataclass
class Baseline:
    """Stored baseline representing known-good behavior."""
    created_at: str
    updated_at: str
    run_count: int
    vector: BehaviorVector
    historical_vectors: List[Dict[str, Any]] = field(default_factory=list)
    variance_bounds: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "run_count": self.run_count,
            "vector": self.vector.to_dict(),
            "historical_vectors": self.historical_vectors,
            "variance_bounds": self.variance_bounds,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Baseline":
        return cls(
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            run_count=data["run_count"],
            vector=BehaviorVector.from_dict(data["vector"]),
            historical_vectors=data.get("historical_vectors", []),
            variance_bounds=data.get("variance_bounds", {}),
        )


@dataclass
class DriftReport:
    """Report of drift detection results."""
    run_id: str
    timestamp: str
    overall_drift_score: float
    component_scores: Dict[str, float] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)
    alert_level: str = "normal"  # normal, HIGH, CRITICAL
    behavioral_analysis: Optional[Dict[str, Any]] = None
    honeypot_alerts: List[Dict] = field(default_factory=list)
    owasp_detections: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "overall_drift_score": self.overall_drift_score,
            "component_scores": self.component_scores,
            "anomalies": self.anomalies,
            "alert_level": self.alert_level,
            "honeypot_alerts": self.honeypot_alerts,
            "owasp_detections": self.owasp_detections,
        }
        if self.behavioral_analysis:
            result["behavioral_analysis"] = self.behavioral_analysis
        return result
