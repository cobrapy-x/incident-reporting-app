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
echo "Done. Next steps (each in its own Terminal tab):"
echo "  source venv/bin/activate && python demo.py       # prove encryption"
echo "  source venv/bin/activate && bash run_server.sh   # start the backend"
echo "  source venv/bin/activate && bash run_app.sh      # start the app"
