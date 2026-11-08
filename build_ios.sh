#!/usr/bin/env bash
# Build the iPhone app (macOS only; needs Xcode + an Apple Developer account).
#   bash build_ios.sh              -> build/ipa/  (upload to App Store Connect / TestFlight)
#   bash build_ios.sh simulator    -> runs-in-Simulator build, no Apple account needed
set -e
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi
if [ ! -f firebase_config.json ]; then
  echo "firebase_config.json is missing — the app wouldn't know your Firebase project."
  exit 1
fi
if [ "${1:-}" = "simulator" ]; then
  exec flet build ios-simulator --yes
fi
exec flet build ipa --yes
