#!/bin/bash
set -e

WEBHOOK_URL="${WEBHOOK_URL:-http://host.docker.internal:23001/webhook/http-interactions}"
LOG_DIR="/var/log/railmon"

echo "[railmon] Starting RailMon container"

# Ensure Claude Code binary is downloaded
echo "[railmon] Ensuring Claude Code is ready..."
CLAUDE_VERSION=$(claude --version 2>/dev/null || echo "unknown")
echo "[railmon] Claude Code: $CLAUDE_VERSION"

# npm-installed Claude Code uses Node.js which statically links OpenSSL.
# sslsniff needs --binary-path to hook Node.js's embedded SSL functions.
NODE_PATH=$(which node)
echo "[railmon] Node.js path: $NODE_PATH"

# Start collector (sslsniff + HTTP parser + webhook forwarder)
echo "[railmon] Starting collector → $WEBHOOK_URL"
python3 /opt/collector/collector.py \
    --webhook "$WEBHOOK_URL" \
    --output "$LOG_DIR/captured.jsonl" \
    --sslsniff /usr/local/bin/sslsniff \
    --binary-path "$NODE_PATH" \
    --agent-version "$CLAUDE_VERSION" \
    --mode http \
    2>"$LOG_DIR/collector.log" &
COLLECTOR_PID=$!
echo "[railmon] Collector PID: $COLLECTOR_PID"

# MCP config
cat > /workdir/.mcp.json << 'EOF'
{
  "mcpServers": {
    "delivery-tracking": {
      "command": "node",
      "args": ["/opt/mcp-server/dist/index.js"]
    }
  }
}
EOF

echo ""
echo "============================================"
echo "  RailMon is ready!"
echo ""
echo "  Connect with:"
echo "    docker exec -it railmon claude"
echo ""
echo "  Webhook: $WEBHOOK_URL"
echo "  Logs:    $LOG_DIR/"
echo "============================================"
echo ""

# Keep container alive
wait $COLLECTOR_PID 2>/dev/null || tail -f /dev/null
