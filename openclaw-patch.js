/**
 * OpenClaw Drift Monitor Patch
 * 
 * This adds a hook to report tool usage to the Agent Drift Detector.
 * 
 * INSTALLATION:
 * 1. Find your OpenClaw installation:
 *    npm root -g  (then look for openclaw/dist/agents/steerable-agent-loop.js)
 * 
 * 2. In steerable-agent-loop.js, find the line (around line 278):
 *    stream.push({ type: "tool_execution_end", ...
 * 
 * 3. Add this code RIGHT AFTER that stream.push block:
 */

// === ADD THIS CODE ===
// Drift Monitor Hook - report tool usage
if (process.env.DRIFT_MONITOR) {
    const http = require('http');
    const data = JSON.stringify({ 
        tool: toolCall.name, 
        success: !isError 
    });
    const req = http.request({
        hostname: 'localhost',
        port: process.env.DRIFT_MONITOR_PORT || 5001,
        path: '/tool',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, () => {});
    req.on('error', () => {}); // Silent fail
    req.write(data);
    req.end();
}
// === END CODE ===

/**
 * That's it! Now run OpenClaw with:
 *   DRIFT_MONITOR=1 npx openclaw gateway
 * 
 * Or for permanent enable, add to your shell profile:
 *   export DRIFT_MONITOR=1
 */
