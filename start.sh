#!/usr/bin/env bash
# Start Token Limit Explorer if it is not already running. Idempotent and safe to run every minute
# (a watchdog): if the server is up it does nothing, if it is down it brings it back.
# PORT=xxxx ./start.sh to change the port (default 8740).
cd "$(dirname "$(readlink -f "$0")")" || exit 1
mkdir -p logs

# One starter at a time (the per-minute watchdog and @reboot can fire together).
exec 9>>logs/.start.lock
flock -n 9 || exit 0

SERVER="$(pwd)/server.js"
if pgrep -f "node $SERVER" >/dev/null 2>&1; then
  [ -t 1 ] && echo "Already running (pid $(pgrep -f "node $SERVER" | head -1))."
  exit 0
fi

nohup node "$SERVER" >> logs/server.log 2>&1 &
PID=$!
sleep 1
if kill -0 "$PID" 2>/dev/null; then
  [ -t 1 ] && echo "Started (pid $PID) on port ${PORT:-8740}. Log: $(pwd)/logs/server.log"
  exit 0
fi
echo "Failed to start — see $(pwd)/logs/server.log" >&2
[ -t 1 ] && tail -5 logs/server.log >&2
exit 1
