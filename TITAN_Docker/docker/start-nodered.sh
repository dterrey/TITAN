#!/bin/bash

# Run npm install only on first boot
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

  # Mark install complete
  touch /data/.npm_installed

if [ ! -f /data/flows.json ]; then
    echo "👉 Copying default flow into /data"
    cp /opt/titan/flows/titan_NR_Flow.json /data/flows.json
fi

  # Exit intentionally to trigger container restart
  echo "♻️ Restarting container to start Node-RED with new modules..."
  exit 1
fi

# Start Node-RED normally
echo "🚀 Starting Node-RED..."
exec npm start -- --userDir /data

