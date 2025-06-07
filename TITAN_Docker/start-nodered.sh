#!/bin/bash

# Check if /data/flows.json exists and contains the default template flow
if grep -q "Flow 1" /data/flows.json 2>/dev/null; then
  echo "👉 Detected default flow, replacing with custom flow..."
  cp /opt/titan/flows/titan_NR_Flow.json /data/flows.json
fi

# Install additional modules if not done before
if [ ! -f /data/.npm_installed ]; then
  echo "📦 Installing Node-RED additional nodes..."

  npm install \
    node-red-dashboard \
    node-red-contrib-fs-ops \
    node-red-contrib-watchdirectory \
    node-red-contrib-simple-message-queue \
    node-red-contrib-slack \
    @flowfuse/node-red-dashboard \
    node-red-contrib-slack-files

  echo "✅ Node-RED modules installed."
  touch /data/.npm_installed

  echo "♻️ Restarting container to start Node-RED with new modules..."
  exit 1
fi

# Start Node-RED normally
echo "🚀 Starting Node-RED..."
exec npm start -- --userDir /data

