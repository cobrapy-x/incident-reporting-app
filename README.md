# Facilis Relatio — incident reporting, Firebase + end-to-end encrypted

A free incident reporting app for site teams. Employers set up an
**organisation** and **groups**; employees join with their email, phone and a
password. Each group has encrypted chat (text + photos) and incident reports
with assignments, target dates, updates and a PDF export with a signature panel.

Every message, photo and report is **end-to-end encrypted** on the phone. Firebase
only ever stores ciphertext, and an employer can never see another
organisation's groups.

- **App:** Flet 1.x (Python) — Android, iOS and desktop from one codebase
- **Backend:** Firebase Auth + Cloud Firestore on the **free Spark plan** —
  no server to run. `firestore.rules` is the whole backend.
- **Encryption:** libsodium / PyNaCl; passwords stretched with Argon2id on-device

## Who can do what

| | Employee | Employer |
|---|---|---|
| Sign up with name, email, phone, password | ✓ | ✓ |
| Create organisations | | ✓ |
| Create groups in their org, add/remove people (by email or phone) | | ✓ |
| Chat, report and update incidents in groups they're in | ✓ | ✓ |
| See another organisation's groups | ✗ | ✗ |

An employer creates the group, so they're a member of it and can read it — that's
what lets them hand the group key to new people. They **can't** read, list, join,
post to, or create groups in anyone else's organisation: the security rules refuse
it, and they don't hold those groups' keys anyway. (They can read a rival's chat
only if someone hands them an unlocked phone — no app can stop that.)

## The files

| File | What it is |
|---|---|
| `main.py` | The Flet phone app (all the screens). |
| `client_api.py` | Accounts, orgs, groups, members, chat, incidents — encrypts before sending. |
| `e2e.py` | The encryption library (runs on the device). |
| `firebase_rest.py` | Tiny Firebase Auth + Firestore client over HTTPS. |
| `firestore.rules` | **The backend**: who can read/write what. |
| `firebase.json`, `.firebaserc`, `firestore.indexes.json` | Firebase CLI config. |
| `firebase_config.example.json` | Copy to `firebase_config.json` and fill in. |
| `demo.py` | Runnable proof: encryption, org isolation, key rotation, no plaintext. |
| `fake_firebase.py` | Offline stand-in for Firebase used by `demo.py` (tests only). |
| `SECURITY.md` | Threat model and crypto, in plain words. |
| `DEPLOY_FIREBASE.md` | Step-by-step Firebase setup. |
| `BUILD_MOBILE.md` | Building and sharing the Android + iPhone apps. |
| `pyproject.toml`, `assets/icon.png` | Phone-app name, bundle id, version, icon, permissions. |
| `build_android.sh`, `build_ios.sh` | Signed phone builds. |

## Quick start (Mac / Linux)

Needs Python 3.10+ (3.12 recommended — macOS's built-in `python3` is 3.9).

```bash
bash setup.sh                      # makes a venv and installs everything
source venv/bin/activate
python demo.py                     # should end with: ALL CHECKS PASSED
```

Then follow **[DEPLOY_FIREBASE.md](DEPLOY_FIREBASE.md)** (≈10 minutes) to create
your Firebase project, deploy the rules and run the app:

```bash
cp firebase_config.example.json firebase_config.json   # fill in apiKey + projectId
firebase deploy --only firestore:rules,firestore:indexes
bash run_app.sh
```

## Phone apps

See **[BUILD_MOBILE.md](BUILD_MOBILE.md)**: `flet build apk` for Android,
`bash build_ios.sh` for iPhone (Mac + Apple Developer account).

### Windows

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python demo.py
flet run main.py
```

## What `demo.py` proves

It crashes loudly if any of these is false:

1. Employees and employers sign up; Firebase never receives the real password.
2. An employer creates an org + group and adds people by email **and** phone.
3. Chat (incl. a 1.5 MB photo) and incident reports round-trip encrypted.
4. A rival employer can't read, list, join, post to, or create groups in
   another org; employees can't add people or post as someone else; nobody can
   browse the user directory.
5. Removing a member rotates the group key and locks them out.
6. Logging in on a new phone restores your key from its encrypted backup;
   password change works; wrong passwords fail.
7. The database contains no messages, incident text, photos, passwords or
   private keys.

`python demo.py` runs offline. `bash run_emulator_demo.sh` runs the same checks
against the real Firebase emulators and the real `firestore.rules`.

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model and the honest limits.
