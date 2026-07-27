#!/usr/bin/env bash
# Start the backend API at http://127.0.0.1:8000  (press Ctrl+C to stop)
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi
exec uvicorn server:app --reload
