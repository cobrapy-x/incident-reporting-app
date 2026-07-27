#!/usr/bin/env bash
# Start the Flet app window. Make sure the server is running first (run_server.sh).
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi
exec flet run main.py
