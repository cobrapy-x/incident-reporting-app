#!/usr/bin/env bash
# One-time setup: create a private virtual environment and install everything.
set -e
cd "$(dirname "$0")"

echo "==> Creating a private environment (venv)..."
python3 -m venv venv

echo "==> Installing packages (this can take a minute)..."
./venv/bin/pip install --upgrade pip >/dev/null
./venv/bin/pip install -r requirements.txt

echo ""
echo "Done. Next steps:"
echo "  source venv/bin/activate && python demo.py       # prove encryption + org isolation (offline)"
echo "  cp firebase_config.example.json firebase_config.json   # then fill it in (DEPLOY_FIREBASE.md)"
echo "  source venv/bin/activate && bash run_app.sh      # start the app"
