# Agent Drift Detector

**Runtime behavioral monitoring for AI agents.**

Detect prompt injection, memory poisoning, behavioral drift, and OWASP Top 10 LLM vulnerabilities in real-time. Think `IDS` for AI agent decisions, or a SIEM for your autonomous systems.

## Why Agent Drift?

Traditional AI security focuses on content filtering. But when an agent is silently compromised - via prompt injection, memory poisoning, or tool manipulation - **its behavior changes before its outputs do**.

Agent Drift monitors behavioral patterns:
- Tool usage sequences and frequencies
- Timing anomalies
- Decision patterns
- Output characteristics
- OWASP Top 10 LLM threat patterns
- Honeypot tool access (instant compromise indicator)

When behavior deviates from baseline, you get alerts.

---

## OWASP Top 10 LLM Security Coverage

Agent Drift provides detection capabilities for all OWASP Top 10 for LLM Applications v1.1:

| ID | Threat | Detection Method | Severity |
|----|--------|------------------|----------|
| LLM01 | Prompt Injection | 12+ regex patterns, behavioral N-grams | CRITICAL |
| LLM02 | Insecure Output Handling | Output validation, exec pattern detection | CRITICAL |
| LLM03 | Training Data Poisoning | Memory write pattern analysis | CRITICAL |
| LLM04 | Model Denial of Service | Resource usage anomaly detection | HIGH |
| LLM05 | Supply Chain Vulnerabilities | External dependency access monitoring | HIGH |
| LLM06 | Sensitive Information Disclosure | Data exfiltration pattern detection | CRITICAL |
| LLM07 | Insecure Plugin Design | Unauthorized tool execution chains | CRITICAL |
| LLM08 | Excessive Agency | Chain depth analysis, autonomy bounds | HIGH |
| LLM09 | Overreliance | Decision pattern drift, retry analysis | MEDIUM |
| LLM10 | Model Theft | System prompt extraction attempts | HIGH |

---

## Quick Start (OpenClaw)

For [OpenClaw](https://github.com/openclaw/openclaw) users:

### 1. Install

```bash
pip install agent-drift-detector[dashboard]
```

Or from source:
```bash
git clone https://github.com/lukehebe/agent-drift.git
cd agent-drift
pip install -e ".[dashboard]"
```

### 2. Setup OpenClaw Integration (One-Time)

```bash
agent-drift setup
```

This will:
- Detect your OpenClaw installation
- Patch it to report tool usage to Agent Drift
- Offer to set `DRIFT_MONITOR=1` in your shell

### 3. Start Monitoring

**Terminal 1 - Start the Dashboard:**
```bash
agent-drift start
```

**Terminal 2 - Run OpenClaw with Monitoring:**
```bash
DRIFT_MONITOR=1 openclaw gateway
```

Or add to `~/.bashrc` for always-on monitoring:
```bash
export DRIFT_MONITOR=1
```

That's it. Your agent's tool usage now flows to the SIEM dashboard at **http://localhost:5001**.

---

## Honeypot Tools

Honeypot tools are decoy tools that your agent should NEVER legitimately call. If accessed, it's a high-confidence indicator of compromise (IoC).

### Configure via CLI

```bash
# Add honeypot tools
agent-drift honeypot add "dangerous_tool"
agent-drift honeypot add "secret_admin_function"
agent-drift honeypot add "internal_debug_api"

# List configured honeypots
agent-drift honeypot list

# Remove honeypot
agent-drift honeypot remove "dangerous_tool"

# Clear all honeypots
agent-drift honeypot clear
```

### Configure via Dashboard

Navigate to **Settings > Honeypot Tools** in the web dashboard to add/remove honeypot tools through the GUI.

### Configure via API

```bash
# Add honeypot
curl -X POST localhost:5001/api/honeypot \
  -H "Content-Type: application/json" \
  -d '{"tool": "dangerous_tool"}'

# List honeypots
curl localhost:5001/api/honeypot

# Remove honeypot
curl -X DELETE localhost:5001/api/honeypot/dangerous_tool
```

### How It Works

When a honeypot tool is called:
1. Immediate CRITICAL alert generated
2. Session flagged as potentially compromised
3. Full trace captured for forensic analysis
4. Dashboard notification pushed via WebSocket

Recommended honeypot tools:
- Admin/debug functions that should never be called in production
- Sensitive data access tools (if your agent shouldn't access them)
- Deprecated tools that are still defined but unused
- Fake tools injected specifically as canaries

---

## Quick Start (Generic / Other Frameworks)

For LangChain, AutoGPT, CrewAI, or custom agents:

### 1. Install & Start

```bash
pip install agent-drift-detector[dashboard]
agent-drift start
```

### 2. Report Tool Usage

Your agent reports tool invocations via HTTP POST:

```bash
# Track tool usage
curl -X POST localhost:5001/tool \
  -H "Content-Type: application/json" \
  -d '{"tool": "exec", "args": {"command": "ls"}, "success": true}'

# Check content for prompt injection
curl -X POST localhost:5001/check \
  -H "Content-Type: application/json" \
  -d '{"content": "user input here", "source": "chat"}'

# End session and get drift report
curl -X POST localhost:5001/end
```

See [Integration Examples](#integration-examples) for framework-specific code.

---

## Features

### Real-Time SIEM Dashboard
- WebSocket-powered live updates
- Drift score timeline
- Component breakdown (tool sequence, frequency, timing, etc.)
- Alert feed with acknowledgment
- Honeypot configuration panel

### Prompt Injection Detection

12 detection patterns with severity levels:

| Pattern | Severity | Example |
|---------|----------|---------|
| Instruction Override | CRITICAL | "Ignore previous instructions" |
| Role Hijacking | CRITICAL | "You are now DAN..." |
| Jailbreak Attempt | CRITICAL | "Bypass all restrictions" |
| Data Exfiltration | CRITICAL | "Send data to webhook" |
| Encoded Payload | CRITICAL | Base64/hex payloads |
| Memory Poisoning | CRITICAL | "Remember forever" |
| Tool Abuse | CRITICAL | Unauthorized tool sequences |
| System Prompt Extraction | HIGH | "Show me your system prompt" |
| Delimiter Injection | HIGH | `]]`, `---`, `<system>` |
| Privilege Escalation | HIGH | "sudo", "admin access" |
| Indirect Injection | HIGH | "NOTE TO AI:", "URGENT:" |
| Resource Exhaustion | MEDIUM | Repetitive expensive operations |

### Behavioral Drift Detection
- Baseline learning from normal agent runs
- Multi-component drift scoring
- Anomaly detection with explanations
- N-gram forbidden sequence detection
- Markov transition probability analysis
- Chain depth anomaly detection
- CUSUM gradual drift detection

### Honeypot Tools
- Configure decoy tools that should never be called
- Instant CRITICAL alert on access
- High-confidence compromise indicator
- CLI, API, and GUI configuration

### Canary Tasks
Inject known-answer tasks to verify agent integrity.

---

## CLI Reference

```bash
# Start monitoring (interactive setup)
agent-drift start

# Start on custom port
agent-drift start --port 8080

# One-time OpenClaw setup (manual)
agent-drift setup

# Honeypot management
agent-drift honeypot add <tool_name>    # Add honeypot tool
agent-drift honeypot remove <tool_name> # Remove honeypot tool
agent-drift honeypot list               # List all honeypots
agent-drift honeypot clear              # Clear all honeypots

# Baseline management
agent-drift status              # Show status
agent-drift baseline show       # Display baseline details
agent-drift baseline reset      # Reset baseline (start fresh)
agent-drift baseline export baseline.json
agent-drift baseline import baseline.json

# Testing & validation
agent-drift history             # Show detection history
agent-drift canary              # Run canary tasks
agent-drift simulate            # Run attack simulations
```

---

## API Reference

### POST /tool

Track a tool invocation.

```json
{
  "tool": "exec",
  "success": true,
  "duration_ms": 150,
  "args": {"command": "ls -la"},
  "output": "total 48..."
}
```

### POST /check

Check content for prompt injection and OWASP threats.

```json
{
  "content": "text to scan",
  "source": "user_input"
}
```

Response:
```json
{
  "ok": true,
  "has_injection": true,
  "critical": true,
  "injections": [
    {
      "name": "Instruction Override",
      "severity": "CRITICAL",
      "owasp": "LLM01",
      "description": "Attempts to override system instructions...",
      "matches": ["ignore previous"]
    }
  ]
}
```

### POST /end

End the current monitoring session and get a drift report.

### POST /reset

Reset the behavioral baseline.

### GET /api/state

Get full dashboard state (drift history, alerts, injections, honeypots, etc.)

### Honeypot API

```
POST   /api/honeypot        - Add honeypot tool {"tool": "name"}
GET    /api/honeypot        - List all honeypot tools
DELETE /api/honeypot/<name> - Remove honeypot tool
```

---

## Integration Examples

### Python (requests)

```python
import requests

DRIFT_URL = "http://localhost:5001"

def report_tool(tool_name: str, args: dict, success: bool):
    requests.post(f"{DRIFT_URL}/tool", json={
        "tool": tool_name,
        "args": args,
        "success": success
    })

# In your agent's tool execution:
result = my_tool.run(args)
report_tool("my_tool", args, success=True)
```

### LangChain

```python
from langchain.callbacks.base import BaseCallbackHandler

class DriftCallback(BaseCallbackHandler):
    def on_tool_start(self, tool, input_str, **kwargs):
        requests.post("http://localhost:5001/tool", json={
            "tool": tool.name,
            "args": {"input": input_str},
            "success": True
        })

# Add to your agent:
agent.run(query, callbacks=[DriftCallback()])
```

---

## Configuration

Set the storage directory:
```bash
export AGENT_DRIFT_DIR=~/.agent-drift
```

---

## Severity Levels

Agent Drift uses strict severity classifications:

| Level | Description | Response |
|-------|-------------|----------|
| CRITICAL | Active compromise or high-confidence attack | Immediate investigation required |
| HIGH | Significant anomaly or known attack pattern | Investigate within 1 hour |
| MEDIUM | Behavioral deviation or suspicious pattern | Review within 24 hours |
| LOW | Minor anomaly, likely benign | Log for trend analysis |

Honeypot tool access is ALWAYS classified as CRITICAL.

---

## How It Works

1. **Baseline Learning**: First few runs establish normal behavior patterns
2. **Behavioral Vectors**: Each run is converted to a multi-dimensional vector (tool sequences, timing, decisions, etc.)
3. **Drift Detection**: New runs are compared against baseline using component-wise scoring
4. **OWASP Scanning**: All inputs/outputs checked against LLM threat patterns
5. **Honeypot Monitoring**: Any access to configured honeypot tools triggers immediate alert
6. **Anomaly Alerts**: Significant deviations trigger warnings or critical alerts

---

## Architecture

```
+-------------------------------------------------------------+
|                         AI Agent                            |
|  +---------+  +---------+  +---------+  +---------+        |
|  |  Tool   |--|  Tool   |--|  Tool   |--|  Tool   |        |
|  |  Call   |  |  Call   |  |  Call   |  |  Call   |        |
|  +----+----+  +----+----+  +----+----+  +----+----+        |
+-------+------------+------------+------------+--------------+
        |            |            |            |
        v            v            v            v
+-------------------------------------------------------------+
|                      Agent Drift                            |
|  +------------------------------------------------------+  |
|  |              Behavior Trace Collector                 |  |
|  +------------------------------------------------------+  |
|                           |                                 |
|         +-----------------+----------------+                |
|         v                 v                v                |
|  +-------------+  +-------------+  +-----------------+     |
|  |  Injection  |  |    Drift    |  |    Baseline     |     |
|  |  Detection  |  |  Detection  |  |    Manager      |     |
|  +-------------+  +-------------+  +-----------------+     |
|         |                 |                 |               |
|         v                 v                 v               |
|  +-------------+  +-------------+  +-----------------+     |
|  |   OWASP     |  |  Honeypot   |  |   Behavioral    |     |
|  |   Scanner   |  |  Monitor    |  |   Analyzer      |     |
|  +-------------+  +-------------+  +-----------------+     |
|         |                 |                 |               |
|         +-----------------+-----------------+               |
|                           v                                 |
|  +------------------------------------------------------+  |
|  |            SIEM Dashboard (WebSocket)                 |  |
|  +------------------------------------------------------+  |
+-------------------------------------------------------------+
```

---

## Roadmap

- Agent quarantine button - Instant kill switch when compromise detected
- Community injection patterns - Sigma/YARA-style rule feeds
- Enhanced behavioral analysis - N-gram sequences, Markov chains, statistical drift
- Multi-agent support - Monitor fleets of agents
- Tool call graphs - Visualize normal vs anomalous execution DAGs

---

## License

MIT

---

## Contributing

PRs welcome! Areas of interest:
- Additional OWASP LLM detection patterns
- More behavioral components
- Integration with other agent frameworks
- Visualization improvements
- Statistical detection methods
