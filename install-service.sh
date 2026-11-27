#!/usr/bin/env bash
# Install Token Limit Explorer as a systemd service (start on boot + restart on crash). Needs root:
#   sudo ./install-service.sh
set -e
DIR="$(dirname "$(readlink -f "$0")")"
RUN_USER="${SUDO_USER:-$(id -un)}"
NODE="$(command -v node)"
mkdir -p "$DIR/logs"
cat > /etc/systemd/system/token-explorer.service <<UNIT
[Unit]
Description=Token Limit Explorer (usage dashboard + rotating proxy)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$DIR
ExecStart=$NODE $DIR/server.js
Environment=PORT=8740
Restart=always
RestartSec=2
StartLimitIntervalSec=0
Nice=10
CPUQuota=40%
MemoryMax=384M
StandardOutput=append:$DIR/logs/server.log
StandardError=append:$DIR/logs/server.log

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now token-explorer
systemctl --no-pager status token-explorer | head -6
echo "Done. Manage: sudo systemctl {status,restart,stop} token-explorer  | logs: $DIR/logs/server.log"
