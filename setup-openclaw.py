#!/usr/bin/env python3
"""
Agent Drift Detector - OpenClaw Integration Setup

This patches OpenClaw to report tool usage to the drift monitor.
Run once after installing agent-drift-detector.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

PATCH_CODE = '''
        // === Drift Monitor Hook ===
        if (process.env.DRIFT_MONITOR) {
            const http = require("http");
            const req = http.request({
                hostname: "localhost",
                port: process.env.DRIFT_MONITOR_PORT || 5001,
                path: "/tool",
                method: "POST",
                headers: { "Content-Type": "application/json" }
            }, () => {});
            req.on("error", () => {});
            req.write(JSON.stringify({ tool: toolCall.name, success: !isError }));
            req.end();
        }
        // === End Drift Monitor Hook ==='''

def find_openclaw():
    """Find OpenClaw installation path."""
    # Try global npm
    try:
        result = subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True)
        global_path = Path(result.stdout.strip()) / 'openclaw'
        if global_path.exists():
            return global_path
    except:
        pass
    
    # Try local npm
    try:
        result = subprocess.run(['npm', 'root'], capture_output=True, text=True)
        local_path = Path(result.stdout.strip()) / 'openclaw'
        if local_path.exists():
            return local_path
    except:
        pass
    
    # Common paths
    common = [
        Path.home() / '.npm-global/lib/node_modules/openclaw',
        Path('/usr/local/lib/node_modules/openclaw'),
        Path('/usr/lib/node_modules/openclaw'),
    ]
    for p in common:
        if p.exists():
            return p
    
    return None

def patch_openclaw(openclaw_path: Path):
    """Apply the drift monitor patch to OpenClaw."""
    target = openclaw_path / 'dist/agents/steerable-agent-loop.js'
    
    if not target.exists():
        print(f"❌ Target file not found: {target}")
        return False
    
    # Read current content
    content = target.read_text()
    
    # Check if already patched
    if 'Drift Monitor Hook' in content:
        print(" OpenClaw is already patched!")
        return True
    
    # Create backup
    backup = target.with_suffix('.js.backup')
    if not backup.exists():
        shutil.copy(target, backup)
        print(f" Created backup: {backup}")
    
    # Find insertion point: after "type: "tool_execution_end"" block closes
    marker = 'type: "tool_execution_end"'
    
    if marker not in content:
        print(f" Could not find insertion point in {target}")
        return False
    
    # Find the position after the stream.push block
    pos = content.find(marker)
    # Find the closing }); after this
    depth = 0
    started = False
    insert_pos = pos
    
    for i in range(pos, len(content)):
        if content[i] == '{':
            depth += 1
            started = True
        elif content[i] == '}':
            depth -= 1
            if started and depth == 0:
                # Find the end of this statement (after });)
                j = i + 1
                while j < len(content) and content[j] in ' \t\n;)':
                    j += 1
                insert_pos = j
                break
    
    # Insert the patch
    new_content = content[:insert_pos] + PATCH_CODE + content[insert_pos:]
    
    target.write_text(new_content)
    print(" Patched OpenClaw!")
    return True

def main():
    print()
    print("    Agent Drift Detector - OpenClaw Setup")
    print("  " + "=" * 45)
    print()
    
    openclaw = find_openclaw()
    
    if not openclaw:
        print("   Could not find OpenClaw installation")
        print()
        print("  Make sure OpenClaw is installed:")
        print("    npm install -g openclaw")
        print()
        sys.exit(1)
    
    print(f"   Found OpenClaw: {openclaw}")
    print()
    
    if patch_openclaw(openclaw):
        print()
        print("  " + "=" * 45)
        print("   Setup complete!")
        print()
        print("  USAGE:")
        print("    Terminal 1:  agent-drift start")
        print("    Terminal 2:  DRIFT_MONITOR=1 npx openclaw gateway")
        print()
        print("  For always-on monitoring, add to ~/.bashrc:")
        print("    export DRIFT_MONITOR=1")
        print("  " + "=" * 45)
        print()
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
