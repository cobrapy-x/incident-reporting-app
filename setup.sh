#!/usr/bin/env bash
# One-time setup: create a private virtual environment and install everything.
# Needs Python 3.10+ (3.12 recommended). macOS's built-in python3 is 3.9 — too old.
set -e
cd "$(dirname "$0")"

PY=""
for cand in python3.12 python3.13 python3.11 python3.10 python3; do
  if command -v "$cand" >/dev/null 2>&1 && \
     "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10+ not found. Install Python 3.12 from https://www.python.org/downloads/"
  echo "(or: brew install python@3.12), then run this again."
  exit 1
fi

if [ -d venv ] && ! ./venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  echo "==> Old venv uses Python < 3.10 — replacing it"
  rm -rf venv
fi

echo "==> Creating a private environment (venv) with $($PY --version)..."
"$PY" -m venv venv

echo "==> Installing packages (this can take a minute)..."
./venv/bin/pip install --upgrade pip >/dev/null
./venv/bin/pip install -r requirements.txt

echo ""
echo "Done. Next steps:"
echo "  source venv/bin/activate && python demo.py       # prove encryption + org isolation (offline)"
echo "  cp firebase_config.example.json firebase_config.json   # then fill it in (DEPLOY_FIREBASE.md)"
echo "  source venv/bin/activate && bash run_app.sh      # start the app on this computer"
echo "  see BUILD_MOBILE.md                              # build the Android + iPhone apps"
