#!/usr/bin/env bash
# Start the Flet app window. Needs firebase_config.json (see DEPLOY_FIREBASE.md),
# or run against local emulators with:  FIREBASE_EMULATOR_HOST=127.0.0.1 bash run_app.sh
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi
exec flet run main.py
