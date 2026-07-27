# Incident Reporting App — connected + end-to-end encrypted

A free, self-hostable incident reporting app for site engineers. Work in groups
(max 50), chat with encrypted messages and photos, file incident reports with
assignments and target dates, and export a PDF with a signature panel. Every
message, photo, and report is **end-to-end encrypted** — the server only ever
stores ciphertext.

- **Phone app:** Flet (Python) — Android, iOS, and desktop
- **Backend:** FastAPI + SQLite (one file, no paid database)
- **Encryption:** libsodium / PyNaCl; passwords hashed with Argon2

## The files

| File | What it is |
|---|---|
| `server.py` | The backend API. Stores only ciphertext, checks logins. |
| `e2e.py` | The encryption library. Runs on the device. |
| `client_api.py` | Network + crypto bridge the app uses. |
| `main.py` | The Flet phone app (all the screens). |
| `demo.py` | Runnable proof the whole thing is encrypted. |
| `requirements.txt` | Everything you need to install. |
| `Dockerfile` | For free 24/7 hosting of the backend. |
| `SECURITY.md` | Threat model and crypto, in plain words. |

---

## Quick start (Mac / Linux)

Open Terminal, `cd` into this folder, then:

```bash
bash setup.sh          # makes a private environment and installs everything
```

Now you have three things you can run. **Each needs its own Terminal tab**, and
each must first turn on the environment with `source venv/bin/activate`.

**1. Prove the encryption works (do this first):**
```bash
source venv/bin/activate
python demo.py         # should end with: ALL CHECKS PASSED
```

**2. Start the backend server:**
```bash
source venv/bin/activate
bash run_server.sh     # serves at http://127.0.0.1:8000  (Ctrl+C to stop)
```

**3. Start the app (new tab, leave the server running):**
```bash
source venv/bin/activate
bash run_app.sh
```
On the sign-in screen keep the server as `http://127.0.0.1:8000`, pick a
username + password, and press **Create account**. Then create a group and open
the Chat / Incidents tabs.

> **See two people talk:** run `bash run_app.sh` a second time in another tab,
> make a different account, and add that username to a group. Because each app
> copy holds its own private key, they can read each other's messages but the
> server never can.

---

## Windows

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python demo.py
uvicorn server:app --reload      REM in one window
flet run main.py                 REM in another (after activate)
```

---

## What `demo.py` proves

Running it checks, and crashes loudly if any is false:

1. Two users register (password) and exchange an encrypted chat + photo.
2. An incident report round-trips: created by one user, updated by another.
3. The server's database file contains **no plaintext**.
4. A non-member is refused by the API.

## Put it on GitHub

```bash
git init
git add .
git commit -m "Encrypted incident-reporting app + backend"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

`.gitignore` already blocks databases, keys, and `.env` files.

## Deploy the backend free, 24/7

One container. Fly.io is simplest for always-on + a persistent SQLite volume:

```bash
fly launch
fly volumes create data --size 1   # holds incident.db (mounted at /data)
fly deploy
```

Other free options: **Render** (sleeps when idle, wakes on request) and
**Oracle Cloud "Always Free" VM** (on 24/7, more setup). Always serve over
**HTTPS** in production. Once deployed, put your real address (e.g.
`https://your-app.fly.dev`) on the app's sign-in screen.

## Build the mobile apps

```bash
flet build apk      # Android  -> build/apk/
flet build ipa      # iOS (needs a Mac + Xcode + Apple Developer account)
```

## Security

See [`SECURITY.md`](SECURITY.md) for the full threat model and the honest limits
(a compromised phone, metadata, key backup, and the upgrade path to a
Signal/MLS-style ratchet).
