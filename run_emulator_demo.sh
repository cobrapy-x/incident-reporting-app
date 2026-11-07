#!/usr/bin/env bash
# Runs demo.py against the REAL Firebase emulators (Auth + Firestore), which
# enforce the real firestore.rules. Needs: Node.js, Java 11+, and
#   npm install -g firebase-tools
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi
exec firebase emulators:exec --only auth,firestore --project demo-incident \
  "python demo.py --emulator"
