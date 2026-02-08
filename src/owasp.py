"""
OWASP Top 10 for LLM Applications v1.1 Scanner

Provides detection capabilities for all 10 OWASP LLM threat categories:
- LLM01: Prompt Injection
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance
- LLM10: Model Theft
"""

import re
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from .models import OWASPCategory, Severity, OWASPDetection


@dataclass
class OWASPPattern:
    """Detection pattern for OWASP threats."""
    name: str
    category: OWASPCategory
    severity: Severity
    pattern: str
    description: str
    flags: int = re.IGNORECASE


# LLM01: Prompt Injection Patterns
PROMPT_INJECTION_PATTERNS = [
    OWASPPattern(
        name="Instruction Override",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?|guidelines?)',
        description="Attempts to override system instructions by asking agent to ignore previous prompts",
    ),
    OWASPPattern(
        name="Role Hijacking",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(you are now|act as|pretend to be|roleplay as|from now on you|your new (role|persona|identity))',
        description="Attempts to change the agent's identity or role to bypass restrictions",
    ),
    OWASPPattern(
        name="Jailbreak Attempt",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(DAN|do anything now|jailbreak|bypass|unlock|remove\s+(restrictions?|limits?|filters?)|no\s+restrictions?)',
        description="Known jailbreak techniques attempting to remove safety restrictions",
    ),
    OWASPPattern(
        name="Delimiter Injection",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=r'(\]\]|>>|---|```|<\/?system>|<\/?user>|<\/?assistant>|END\s*OF\s*PROMPT|BEGIN\s*NEW\s*CONVERSATION)',
        description="Uses delimiters or markers to trick the agent into treating injected text as system instructions",
    ),
    OWASPPattern(
        name="Encoded Payload",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(base64|rot13|hex|decode|encrypt|eval|exec)\s*[:\(]|[A-Za-z0-9+/]{40,}={0,2}',
        description="Contains encoded content that may hide malicious instructions",
    ),
    OWASPPattern(
        name="Indirect Injection Marker",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=r'(AI:|Assistant:|System:|IMPORTANT:|URGENT:|NOTE TO AI:|HIDDEN INSTRUCTION:)',
        description="Markers commonly used in indirect prompt injection attacks via external content",
    ),
]

# LLM02: Insecure Output Handling Patterns
INSECURE_OUTPUT_PATTERNS = [
    OWASPPattern(
        name="Code Execution Output",
        category=OWASPCategory.LLM02_INSECURE_OUTPUT,
        severity=Severity.CRITICAL,
        pattern=r'(eval\(|exec\(|subprocess\.|os\.system|shell_exec|`.*`)',
        description="Output contains code execution patterns that could be dangerous if not validated",
    ),
    OWASPPattern(
        name="SQL Injection Output",
        category=OWASPCategory.LLM02_INSECURE_OUTPUT,
        severity=Severity.CRITICAL,
        pattern=r"(;\s*(DROP|DELETE|UPDATE|INSERT)\s+|'\s*(OR|AND)\s+'?\d+'\s*=\s*'?\d+|UNION\s+SELECT)",
        description="Output contains SQL injection patterns",
    ),
    OWASPPattern(
        name="Path Traversal Output",
        category=OWASPCategory.LLM02_INSECURE_OUTPUT,
        severity=Severity.HIGH,
        pattern=r'(\.\./|\.\.\\|/etc/passwd|/etc/shadow|C:\\Windows\\)',
        description="Output contains path traversal patterns",
    ),
]

# LLM03: Training Data Poisoning (Memory Poisoning)
TRAINING_POISONING_PATTERNS = [
    OWASPPattern(
        name="Memory Poisoning",
        category=OWASPCategory.LLM03_TRAINING_POISONING,
        severity=Severity.CRITICAL,
        pattern=r'(remember|store|save|record|memorize)\s+(forever|permanently|always|from now on)',
        description="Attempts to inject persistent malicious content into agent memory",
    ),
    OWASPPattern(
        name="Context Manipulation",
        category=OWASPCategory.LLM03_TRAINING_POISONING,
        severity=Severity.HIGH,
        pattern=r'(update your (memory|knowledge|context)|add to your (training|learning))',
        description="Attempts to manipulate agent context or memory",
    ),
]

# LLM04: Model Denial of Service
DOS_PATTERNS = [
    OWASPPattern(
        name="Resource Exhaustion Request",
        category=OWASPCategory.LLM04_MODEL_DOS,
        severity=Severity.MEDIUM,
        pattern=r'(repeat\s+\d{3,}\s+times|generate\s+\d{4,}\s+(words|characters|tokens)|infinite\s+loop)',
        description="Requests designed to exhaust model resources",
    ),
    OWASPPattern(
        name="Recursive Task",
        category=OWASPCategory.LLM04_MODEL_DOS,
        severity=Severity.MEDIUM,
        pattern=r'(call yourself|recursively|infinite recursion|keep calling)',
        description="Attempts to trigger recursive or infinite operations",
    ),
]

# LLM05: Supply Chain Vulnerabilities
SUPPLY_CHAIN_PATTERNS = [
    OWASPPattern(
        name="Malicious Package Install",
        category=OWASPCategory.LLM05_SUPPLY_CHAIN,
        severity=Severity.HIGH,
        pattern=r'(pip install|npm install|curl.*\|.*sh|wget.*\|.*bash)',
        description="Attempts to install packages from potentially untrusted sources",
    ),
    OWASPPattern(
        name="External Script Execution",
        category=OWASPCategory.LLM05_SUPPLY_CHAIN,
        severity=Severity.HIGH,
        pattern=r'(curl|wget|fetch)\s+https?://[^\s]+\s*(\||;)\s*(sh|bash|python|node)',
        description="Downloads and executes external scripts",
    ),
]

# LLM06: Sensitive Information Disclosure
SENSITIVE_DISCLOSURE_PATTERNS = [
    OWASPPattern(
        name="Data Exfiltration",
        category=OWASPCategory.LLM06_SENSITIVE_DISCLOSURE,
        severity=Severity.CRITICAL,
        pattern=r'(send|upload|post|transmit|exfil|leak)\s+.*?(to|via)\s+.*(email|url|webhook|api|server|external)',
        description="Attempts to exfiltrate data to external services",
    ),
    OWASPPattern(
        name="Credential Access",
        category=OWASPCategory.LLM06_SENSITIVE_DISCLOSURE,
        severity=Severity.CRITICAL,
        pattern=r'(password|api.?key|secret|token|credential|private.?key)\s*[:=]',
        description="Attempts to access or expose credentials",
    ),
    OWASPPattern(
        name="PII Request",
        category=OWASPCategory.LLM06_SENSITIVE_DISCLOSURE,
        severity=Severity.HIGH,
        pattern=r'(give me|show me|list|extract)\s+(all\s+)?(ssn|social security|credit card|bank account|passwords?)',
        description="Requests for personally identifiable information",
    ),
]

# LLM07: Insecure Plugin Design
INSECURE_PLUGIN_PATTERNS = [
    OWASPPattern(
        name="Unauthorized Tool Chain",
        category=OWASPCategory.LLM07_INSECURE_PLUGIN,
        severity=Severity.CRITICAL,
        pattern=r'(call|invoke|execute|run)\s+(all|every|each)\s+(tool|function|plugin)',
        description="Attempts to trigger unauthorized tool execution chains",
    ),
    OWASPPattern(
        name="Plugin Bypass",
        category=OWASPCategory.LLM07_INSECURE_PLUGIN,
        severity=Severity.HIGH,
        pattern=r'(bypass|skip|ignore)\s+(tool|plugin|function)\s+(validation|check|security)',
        description="Attempts to bypass plugin security checks",
    ),
]

# LLM08: Excessive Agency
EXCESSIVE_AGENCY_PATTERNS = [
    OWASPPattern(
        name="Autonomy Expansion",
        category=OWASPCategory.LLM08_EXCESSIVE_AGENCY,
        severity=Severity.HIGH,
        pattern=r'(act independently|without (asking|confirmation|approval)|make (all|any) decisions?)',
        description="Attempts to expand agent autonomy beyond intended bounds",
    ),
    OWASPPattern(
        name="Permission Escalation",
        category=OWASPCategory.LLM08_EXCESSIVE_AGENCY,
        severity=Severity.HIGH,
        pattern=r'(admin|root|superuser|elevated|sudo|override\s+permissions?|bypass\s+auth)',
        description="Attempts to gain elevated privileges or bypass authentication",
    ),
]

# LLM09: Overreliance (harder to detect with patterns, more behavioral)
OVERRELIANCE_PATTERNS = [
    OWASPPattern(
        name="Blind Trust Request",
        category=OWASPCategory.LLM09_OVERRELIANCE,
        severity=Severity.MEDIUM,
        pattern=r"(don't verify|skip verification|trust (me|this)|no need to check)",
        description="Requests to skip verification or blindly trust input",
    ),
]

# LLM10: Model Theft
MODEL_THEFT_PATTERNS = [
    OWASPPattern(
        name="System Prompt Extraction",
        category=OWASPCategory.LLM10_MODEL_THEFT,
        severity=Severity.HIGH,
        pattern=r'(show|reveal|display|print|output|repeat|tell)\s+(me\s+)?(your|the)?\s*(system\s*prompt|instructions?|initial\s*prompt|hidden\s*prompt|secret\s*instructions?)',
        description="Attempts to extract the agent's system prompt or hidden instructions",
    ),
    OWASPPattern(
        name="Model Parameters Extraction",
        category=OWASPCategory.LLM10_MODEL_THEFT,
        severity=Severity.HIGH,
        pattern=r'(what (model|version)|reveal your (weights|parameters|architecture))',
        description="Attempts to extract model details or parameters",
    ),
]

# Combine all patterns
ALL_OWASP_PATTERNS: List[OWASPPattern] = (
    PROMPT_INJECTION_PATTERNS +
    INSECURE_OUTPUT_PATTERNS +
    TRAINING_POISONING_PATTERNS +
    DOS_PATTERNS +
    SUPPLY_CHAIN_PATTERNS +
    SENSITIVE_DISCLOSURE_PATTERNS +
    INSECURE_PLUGIN_PATTERNS +
    EXCESSIVE_AGENCY_PATTERNS +
    OVERRELIANCE_PATTERNS +
    MODEL_THEFT_PATTERNS
)


class OWASPScanner:
    """
    Scanner for OWASP Top 10 LLM threats.
    
    Scans text content for patterns matching known LLM vulnerabilities.
    """
    
    def __init__(
        self,
        patterns: Optional[List[OWASPPattern]] = None,
        custom_patterns: Optional[List[OWASPPattern]] = None,
    ):
        self.patterns = patterns or ALL_OWASP_PATTERNS
        if custom_patterns:
            self.patterns = self.patterns + custom_patterns
        
        # Compile patterns for performance
        self._compiled: List[Tuple[OWASPPattern, re.Pattern]] = []
        for pattern in self.patterns:
            try:
                compiled = re.compile(pattern.pattern, pattern.flags)
                self._compiled.append((pattern, compiled))
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{pattern.name}': {e}")
    
    def scan(self, text: str, source: str = "unknown") -> List[OWASPDetection]:
        """
        Scan text for OWASP LLM threats.
        
        Args:
            text: Content to scan
            source: Source identifier (e.g., "user_input", "tool_args")
            
        Returns:
            List of detected OWASP threats
        """
        if not text:
            return []
        
        detections = []
        timestamp = time.time()
        
        for pattern, compiled in self._compiled:
            matches = compiled.findall(text)
            if matches:
                # Flatten tuple matches
                flat_matches = []
                for m in matches[:5]:  # Limit to first 5 matches
                    if isinstance(m, tuple):
                        flat_matches.append(m[0] if m else "")
                    else:
                        flat_matches.append(m)
                
                detections.append(OWASPDetection(
                    category=pattern.category,
                    name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    matches=flat_matches,
                    timestamp=timestamp,
                    source=source,
                ))
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        detections.sort(key=lambda d: severity_order.get(d.severity, 99))
        
        return detections
    
    def has_critical(self, detections: List[OWASPDetection]) -> bool:
        """Check if any detections are CRITICAL severity."""
        return any(d.severity == Severity.CRITICAL for d in detections)
    
    def has_high_or_above(self, detections: List[OWASPDetection]) -> bool:
        """Check if any detections are HIGH or CRITICAL severity."""
        return any(d.severity in (Severity.CRITICAL, Severity.HIGH) for d in detections)
    
    def get_by_category(
        self, 
        detections: List[OWASPDetection], 
        category: OWASPCategory
    ) -> List[OWASPDetection]:
        """Filter detections by OWASP category."""
        return [d for d in detections if d.category == category]
    
    def add_pattern(self, pattern: OWASPPattern):
        """Add a custom detection pattern."""
        try:
            compiled = re.compile(pattern.pattern, pattern.flags)
            self._compiled.append((pattern, compiled))
            self.patterns.append(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
    
    def get_summary(self, detections: List[OWASPDetection]) -> Dict[str, int]:
        """Get summary count by category."""
        summary: Dict[str, int] = {}
        for detection in detections:
            key = detection.category.value
            summary[key] = summary.get(key, 0) + 1
        return summary


class BehavioralOWASPAnalyzer:
    """
    Behavioral analysis for OWASP threats that can't be detected by pattern matching alone.
    
    Analyzes:
    - LLM04: Model DoS via tool usage patterns
    - LLM07: Insecure Plugin Design via tool chains
    - LLM08: Excessive Agency via autonomy metrics
    - LLM09: Overreliance via decision patterns
    """
    
    def __init__(
        self,
        max_tools_per_session: int = 50,
        max_consecutive_same_tool: int = 5,
        suspicious_tool_chains: Optional[Set[Tuple[str, str]]] = None,
    ):
        self.max_tools_per_session = max_tools_per_session
        self.max_consecutive_same_tool = max_consecutive_same_tool
        self.suspicious_tool_chains = suspicious_tool_chains or {
            ("read", "curl"),
            ("read", "web_fetch"),
            ("memory_search", "curl"),
            ("exec", "curl"),
            ("exec", "wget"),
        }
    
    def analyze_tool_sequence(
        self,
        tool_sequence: List[str],
    ) -> List[OWASPDetection]:
        """
        Analyze tool sequence for behavioral OWASP threats.
        
        Args:
            tool_sequence: List of tool names in order
            
        Returns:
            List of detected OWASP threats
        """
        detections = []
        timestamp = time.time()
        
        # LLM04: Check for DoS patterns
        if len(tool_sequence) > self.max_tools_per_session:
            detections.append(OWASPDetection(
                category=OWASPCategory.LLM04_MODEL_DOS,
                name="Excessive Tool Usage",
                severity=Severity.MEDIUM,
                description=f"Session used {len(tool_sequence)} tools (threshold: {self.max_tools_per_session})",
                matches=[f"tool_count={len(tool_sequence)}"],
                timestamp=timestamp,
                source="behavioral_analysis",
            ))
        
        # Check consecutive same-tool calls
        if tool_sequence:
            max_consecutive = 1
            current_count = 1
            current_tool = tool_sequence[0]
            
            for tool in tool_sequence[1:]:
                if tool == current_tool:
                    current_count += 1
                    max_consecutive = max(max_consecutive, current_count)
                else:
                    current_tool = tool
                    current_count = 1
            
            if max_consecutive > self.max_consecutive_same_tool:
                detections.append(OWASPDetection(
                    category=OWASPCategory.LLM04_MODEL_DOS,
                    name="Repetitive Tool Pattern",
                    severity=Severity.MEDIUM,
                    description=f"Tool called {max_consecutive}x consecutively (threshold: {self.max_consecutive_same_tool})",
                    matches=[f"tool={current_tool}", f"count={max_consecutive}"],
                    timestamp=timestamp,
                    source="behavioral_analysis",
                ))
        
        # LLM07: Check for suspicious tool chains
        for i in range(len(tool_sequence) - 1):
            chain = (tool_sequence[i].lower(), tool_sequence[i + 1].lower())
            if chain in self.suspicious_tool_chains:
                detections.append(OWASPDetection(
                    category=OWASPCategory.LLM07_INSECURE_PLUGIN,
                    name="Suspicious Tool Chain",
                    severity=Severity.HIGH,
                    description=f"Detected suspicious tool sequence: {chain[0]} -> {chain[1]}",
                    matches=[f"{chain[0]}->{chain[1]}"],
                    timestamp=timestamp,
                    source="behavioral_analysis",
                ))
        
        # LLM08: Check for excessive agency (long autonomous chains)
        if len(tool_sequence) > 20:
            detections.append(OWASPDetection(
                category=OWASPCategory.LLM08_EXCESSIVE_AGENCY,
                name="Long Autonomous Chain",
                severity=Severity.MEDIUM,
                description=f"Agent executed {len(tool_sequence)} tools without checkpoint",
                matches=[f"chain_length={len(tool_sequence)}"],
                timestamp=timestamp,
                source="behavioral_analysis",
            ))
        
        return detections
    
    def analyze_transitions(
        self,
        tool_transitions: Dict[str, Dict[str, int]],
    ) -> List[OWASPDetection]:
        """
        Analyze tool transition patterns for OWASP threats.
        
        Args:
            tool_transitions: Dict of {from_tool: {to_tool: count}}
            
        Returns:
            List of detected OWASP threats
        """
        detections = []
        timestamp = time.time()
        
        # Check for data exfiltration patterns (read -> network)
        read_tools = {"read", "read_file", "memory_search", "memory_get"}
        network_tools = {"curl", "wget", "web_fetch", "http_request"}
        
        for from_tool, to_tools in tool_transitions.items():
            if from_tool.lower() in read_tools:
                for to_tool in to_tools:
                    if to_tool.lower() in network_tools:
                        detections.append(OWASPDetection(
                            category=OWASPCategory.LLM06_SENSITIVE_DISCLOSURE,
                            name="Potential Data Exfiltration",
                            severity=Severity.CRITICAL,
                            description=f"Data read ({from_tool}) followed by network call ({to_tool})",
                            matches=[f"{from_tool}->{to_tool}"],
                            timestamp=timestamp,
                            source="behavioral_analysis",
                        ))
        
        return detections
