#!/bin/bash
# Agent Drift Detector - OpenClaw Integration Setup
# This patches OpenClaw to report tool usage to the drift monitor.

set -e

echo "🛡️  Agent Drift Detector - OpenClaw Setup"
echo "==========================================="

# Find OpenClaw
OPENCLAW_PATH=$(npm root -g 2>/dev/null)/openclaw
if [ ! -d "$OPENCLAW_PATH" ]; then
    OPENCLAW_PATH=$(npm root)/openclaw
fi

TARGET="$OPENCLAW_PATH/dist/agents/steerable-agent-loop.js"

if [ ! -f "$TARGET" ]; then
    echo "❌ Could not find OpenClaw at: $TARGET"
    echo "   Make sure OpenClaw is installed: npm install -g openclaw"
    exit 1
fi

echo "📍 Found OpenClaw: $OPENCLAW_PATH"

# Check if already patched
if grep -q "DRIFT_MONITOR" "$TARGET"; then
    echo "✅ OpenClaw is already patched!"
else
    # Create backup
    cp "$TARGET" "$TARGET.backup"
    echo "📦 Created backup: $TARGET.backup"
    
    # The patch - insert after tool_execution_end stream.push
    PATCH='
        // Drift Monitor Hook
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
        }'
    
    # Insert after: stream.push({ type: "tool_execution_end"
    sed -i '/type: "tool_execution_end"/,/});/{/});/a\
        // Drift Monitor Hook\
        if (process.env.DRIFT_MONITOR) {\
            const http = require("http");\
            const req = http.request({\
                hostname: "localhost",\
                port: process.env.DRIFT_MONITOR_PORT || 5001,\
                path: "/tool",\
                method: "POST",\
                headers: { "Content-Type": "application/json" }\
            }, () => {});\
            req.on("error", () => {});\
            req.write(JSON.stringify({ tool: toolCall.name, success: !isError }));\
            req.end();\
        }
}' "$TARGET"
    
    echo "✅ Patched OpenClaw!"
fi

echo ""
echo "==========================================="
echo "✨ Setup complete!"
echo ""
echo "USAGE:"
echo "  Terminal 1:  agent-drift start"
echo "  Terminal 2:  DRIFT_MONITOR=1 npx openclaw gateway"
echo ""
echo "Or add to ~/.bashrc for always-on monitoring:"
echo "  echo 'export DRIFT_MONITOR=1' >> ~/.bashrc"
echo "==========================================="
