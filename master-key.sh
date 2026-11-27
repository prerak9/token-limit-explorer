#!/usr/bin/env bash
# Prints the current master token (for Claude Code's apiKeyHelper). Read live from data/tokens.json.
DIR="$(dirname "$(readlink -f "$0")")"
exec python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['master']['token'])" "$DIR/data/tokens.json"
