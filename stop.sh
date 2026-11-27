#!/usr/bin/env bash
cd "$(dirname "$(readlink -f "$0")")"
pkill -f "node $(pwd)/server.js" && echo "Stopped." || echo "Not running."
