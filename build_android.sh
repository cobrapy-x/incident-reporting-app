#!/usr/bin/env bash
# Build the Android app, signed with your release key.
#   bash build_android.sh          -> build/apk/  (.apk to share directly)
#   bash build_android.sh aab      -> build/aab/  (.aab to upload to Google Play)
# First time? Create the key (see BUILD_MOBILE.md, step A2).
set -e
cd "$(dirname "$0")"
if [ -d venv ] && [ -z "$VIRTUAL_ENV" ]; then source venv/bin/activate; fi

TARGET="${1:-apk}"
export FLET_ANDROID_SIGNING_KEY_STORE="${FLET_ANDROID_SIGNING_KEY_STORE:-$HOME/keys/facilis-relatio.jks}"
if [ ! -f "$FLET_ANDROID_SIGNING_KEY_STORE" ]; then
  echo "No signing key at $FLET_ANDROID_SIGNING_KEY_STORE — create it first (BUILD_MOBILE.md, step A2)."
  exit 1
fi
if [ ! -f firebase_config.json ]; then
  echo "firebase_config.json is missing — the app wouldn't know your Firebase project."
  exit 1
fi
if [ -z "$FLET_ANDROID_SIGNING_KEY_STORE_PASSWORD" ]; then
  read -r -s -p "Keystore password: " FLET_ANDROID_SIGNING_KEY_STORE_PASSWORD; echo
  export FLET_ANDROID_SIGNING_KEY_STORE_PASSWORD
fi
exec flet build "$TARGET" --yes
