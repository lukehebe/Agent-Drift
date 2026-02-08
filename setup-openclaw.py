#!/usr/bin/env python3
"""
OpenClaw Integration Setup for Agent Drift Detector

This script patches OpenClaw to automatically report tool usage to Agent Drift.
Run once after installing Agent Drift.
"""

import os
import sys
import subprocess
from pathlib import Path


HOOK_CODE = '''
// === Agent Drift Monitor Hook (v0.1.2) ===
// Automatically reports tool usage to Agent Drift when DRIFT_MONITOR=1
if (process.env.DRIFT_MONITOR === '1') {
    const http = require('http');
    const DRIFT_PORT = process.env.DRIFT_PORT || 5001;
    
    const originalToolCall = this.callTool?.bind(this) || (() => {});
    this.callTool = async function(tool, args) {
        const start = Date.now();
        let success = true;
        let result;
        try {
            result = await originalToolCall(tool, args);
        } catch (e) {
            success = false;
            throw e;
        } finally {
            const duration = Date.now() - start;
            const payload = JSON.stringify({
                tool: tool,
                success: success,
                duration_ms: duration,
                args: args ? Object.keys(args) : []
            });
            
            const req = http.request({
                hostname: 'localhost',
                port: DRIFT_PORT,
                path: '/tool',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload)
                }
            });
            req.on('error', () => {}); // Silently ignore errors
            req.write(payload);
            req.end();
        }
        return result;
    };
}
// === End Agent Drift Hook ===
'''


def find_openclaw_path() -> Path | None:
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
    
    # Try npx cache locations
    npx_paths = list(Path.home().glob('.npm/_npx/*/node_modules/openclaw'))
    if npx_paths:
        return npx_paths[0]
    
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


def is_already_patched(content: str) -> bool:
    """Check if the file is already patched."""
    return 'Agent Drift Monitor Hook' in content


def patch_openclaw(openclaw_path: Path) -> bool:
    """Patch OpenClaw's steerable-agent-loop.js to report tool usage."""
    target_file = openclaw_path / 'dist/agents/steerable-agent-loop.js'
    
    if not target_file.exists():
        print(f"[ERROR] Target file not found: {target_file}")
        return False
    
    content = target_file.read_text()
    
    if is_already_patched(content):
        print("[OK] OpenClaw is already patched for Agent Drift")
        return True
    
    # Find injection point - after class initialization
    # Look for the constructor or initialization code
    injection_markers = [
        'constructor(',
        'async run(',
        'this.tools',
    ]
    
    injection_point = -1
    for marker in injection_markers:
        pos = content.find(marker)
        if pos != -1:
            # Find the opening brace after the marker
            brace_pos = content.find('{', pos)
            if brace_pos != -1:
                injection_point = brace_pos + 1
                break
    
    if injection_point == -1:
        # Fallback: inject at the start of the file after 'use strict' if present
        if "'use strict'" in content:
            injection_point = content.find("'use strict'") + len("'use strict';") + 1
        else:
            injection_point = 0
    
    # Create backup
    backup_file = target_file.with_suffix('.js.bak')
    if not backup_file.exists():
        target_file.rename(backup_file)
        backup_file.with_name(target_file.name).write_text(content)
        target_file = backup_file.with_name(target_file.name)
        content = target_file.read_text()
    
    # Inject hook code
    patched = content[:injection_point] + '\n' + HOOK_CODE + '\n' + content[injection_point:]
    target_file.write_text(patched)
    
    print("[OK] OpenClaw patched successfully")
    return True


def setup_env_var():
    """Offer to add DRIFT_MONITOR=1 to shell rc file."""
    rc_files = [
        Path.home() / '.bashrc',
        Path.home() / '.zshrc',
    ]
    
    for rc_file in rc_files:
        if rc_file.exists():
            content = rc_file.read_text()
            if 'DRIFT_MONITOR=1' in content:
                print(f"[OK] DRIFT_MONITOR already in {rc_file.name}")
                return
    
    print("\n[TIP] Add DRIFT_MONITOR=1 to your shell for always-on monitoring")
    response = input("     Add 'export DRIFT_MONITOR=1' to ~/.bashrc? [y/N] ")
    
    if response.lower() == 'y':
        bashrc = Path.home() / '.bashrc'
        with open(bashrc, 'a') as f:
            f.write('\n# Agent Drift Monitor - auto-report tool usage\nexport DRIFT_MONITOR=1\n')
        print(f"[OK] Added to {bashrc}")
        print("     Run 'source ~/.bashrc' or restart terminal to activate")


def main():
    print()
    print("  Agent Drift - OpenClaw Integration Setup")
    print("  " + "=" * 45)
    print()
    
    # Find OpenClaw
    openclaw_path = find_openclaw_path()
    
    if not openclaw_path:
        print("[ERROR] OpenClaw installation not found")
        print()
        print("  Make sure OpenClaw is installed:")
        print("    npm install -g openclaw")
        print("    # or")
        print("    npx openclaw --version")
        print()
        sys.exit(1)
    
    print(f"[FOUND] OpenClaw at: {openclaw_path}")
    
    # Check if already patched
    target = openclaw_path / 'dist/agents/steerable-agent-loop.js'
    if target.exists():
        content = target.read_text()
        if is_already_patched(content):
            print("[OK] Already patched - no changes needed")
            setup_env_var()
            print()
            print("  Setup complete! Run with:")
            print("    agent-drift start")
            print("    DRIFT_MONITOR=1 openclaw gateway")
            print()
            return
    
    # Patch
    print()
    response = input("  Patch OpenClaw to report tool usage? [Y/n] ")
    if response.lower() == 'n':
        print("  Cancelled.")
        sys.exit(0)
    
    success = patch_openclaw(openclaw_path)
    
    if success:
        setup_env_var()
        print()
        print("  " + "=" * 45)
        print("  Setup complete!")
        print()
        print("  To start monitoring:")
        print("    Terminal 1: agent-drift start")
        print("    Terminal 2: DRIFT_MONITOR=1 openclaw gateway")
        print()
    else:
        print()
        print("[ERROR] Setup failed - see errors above")
        sys.exit(1)


if __name__ == '__main__':
    main()
