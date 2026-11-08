# Building Facilis Relatio for Android and iPhone

The phone apps are built from this same Python code with **Flet 1.1.2**
(`flet build`). The phones talk to the same Firebase project as the desktop app,
so the security rules from `DEPLOY_FIREBASE.md` must already be deployed.

What's already set up in this repo:

| Thing | Where |
|---|---|
| App name **Facilis Relatio**, bundle id `io.github.cobrapyx.facilisrelatio`, version | `pyproject.toml` |
| App icon + splash screen (from `assets/icon.png`) | `assets/` |
| iPhone photo/camera permission texts | `pyproject.toml` → `[tool.flet.ios.info]` |
| Phone-ready Python packages (PyNaCl 1.6.2, Pillow 12.3.0 have Android + iOS builds) | `pyproject.toml` → `dependencies` |
| Test tools, docs, logs left out of the app | `pyproject.toml` → `[tool.flet.app] exclude` |
| PDF and photo "Share" opens the phone's share sheet (Files, WhatsApp, email…) | `main.py` |

> **Choose the bundle id once.** `io.github.cobrapyx.facilisrelatio` is what the
> stores use to recognise the app. Change it in `pyproject.toml` *before* the
> first upload if you want something else; after that it's permanent.

---

## 0. One-time computer setup (Mac)

1. **Python 3.12** — macOS's built-in `python3` is 3.9, which Flet 1.x can't use.
   Install 3.12 from <https://www.python.org/downloads/> (or `brew install python@3.12`).
2. Recreate the environment with it (the script picks 3.12 automatically):
   ```bash
   cd ~/Desktop/Incident-Reporting-app
   bash setup.sh
   source venv/bin/activate
   python demo.py                    # ALL CHECKS PASSED
   bash run_app.sh                   # the desktop app still works
   ```
3. `firebase_config.json` must exist in this folder — it gets packed into the
   phone app so it knows your Firebase project.

Flet installs **Flutter**, **Java 17** and the **Android SDK** by itself the first
time you build (several GB, 10–30 min once). iPhone builds additionally need
**Xcode** (Mac App Store, then open it once and accept the licence) and
**CocoaPods** (`brew install cocoapods`).

---

## A. Android

### A1. Quick test build
```bash
flet build apk --yes
```
The result is in `build/apk/`. Copy the `.apk` to an Android phone (USB, Google
Drive, WhatsApp-to-yourself), tap it, and allow "Install unknown apps" when asked.

### A2. Create your release key (once — and back it up!)
Every update must be signed with the **same key**, or phones refuse to install it
over the old version. Make it once:
```bash
mkdir -p ~/keys
keytool -genkey -v -keystore ~/keys/facilis-relatio.jks -keyalg RSA -keysize 2048 \
        -validity 10000 -alias facilis
```
(`keytool` comes with Java; if Terminal can't find it, run the A1 build first —
Flet installs Java into `~/java/`.) Pick a strong password and **save the `.jks`
file + password somewhere safe** (password manager + a USB stick). Never put it
in the repo — `.gitignore` already blocks `*.jks`.

### A3. Signed builds
```bash
bash build_android.sh          # signed .apk  -> build/apk/   (share directly)
bash build_android.sh aab      # signed .aab  -> build/aab/   (Google Play)
```

### A4. Sharing the APK with your team
Put the `.apk` on Google Drive / a GitHub Release and send the link. People
install it like in A1. For each update: bump `version` (and `build_number`) in
`pyproject.toml`, rebuild, share the new file — it installs over the old one.

### A5. Google Play (optional, later)
1. <https://play.google.com/console> → pay the one-time **$25** fee.
2. Create the app → upload `build/aab/*.aab` to **Testing → Internal testing**.
3. New personal developer accounts must first run a **closed test** (at the time
   of writing: 12+ testers for 14 days) before going to Production.
4. Play also requires a **privacy policy URL** and the **Data safety** form.
   Honest answers for this app: it collects name, email, phone number; messages
   and photos are end-to-end encrypted; data is stored in Google Firebase.

---

## B. iPhone

### B1. Try it in the iPhone Simulator (free, no Apple account)
```bash
bash build_ios.sh simulator
```
Then open the built `.app` from `build/ios-simulator/` in Simulator (Xcode →
Open Developer Tool → Simulator, drag the `.app` onto it).

### B2. Get it onto other people's iPhones
Apple only allows this through a paid **Apple Developer Program** membership
(**$99/year**, <https://developer.apple.com/programs/>). Then:

1. **App ID:** developer.apple.com → Certificates, IDs & Profiles → Identifiers →
   **+** → App IDs → Bundle ID `io.github.cobrapyx.facilisrelatio`.
2. **Certificate:** in Xcode → Settings → Accounts → add your Apple ID → Manage
   Certificates → **+** → *Apple Distribution*.
3. **Provisioning profile:** Profiles → **+** → *App Store Connect* → pick the App
   ID and certificate → download and double-click it.
4. Put your **Team ID** (developer.apple.com → Membership) into `pyproject.toml`:
   ```toml
   [tool.flet.ios]
   export_method = "app-store-connect"
   team_id = "ABCDE12345"
   provisioning_profile = "<the profile's name>"
   ```
5. Build: `bash build_ios.sh` → `build/ipa/*.ipa`.
6. **App Store Connect** (<https://appstoreconnect.apple.com>) → My Apps → **+** →
   New App with the same bundle id. Upload the `.ipa` with Apple's free
   **Transporter** app (Mac App Store).
7. **TestFlight** tab → add testers by email (up to 10,000; first external build
   gets a quick Apple review). Testers install the TestFlight app and tap the
   invite. This is the easiest way to give the app to your team.
8. For the public App Store: fill in screenshots, description, privacy policy URL
   and the **App Privacy** questions, then *Submit for Review*. You'll also be
   asked about **encryption** (export compliance): the app uses standard
   encryption (libsodium: X25519, XSalsa20-Poly1305, Argon2id) for end-to-end
   messaging. Read Apple's guidance for that question before answering.

For every update: bump `version` / `build_number` in `pyproject.toml`, rebuild,
upload again.

---

## Things to know

- **Same Firebase, same accounts.** Phone users sign in with the same
  email + password; keys come from the encrypted backup, so desktop and phone
  can be used side by side.
- **Free tier still applies.** Each open chat checks for new messages every 15 s
  (1 Firestore read when nothing changed). With ~50 people active all day you're
  still well within 50K reads/day; raise `POLL_SECONDS` in `main.py` if needed.
- **`flet run --android` with the Flet companion app won't work** for this
  project — that app doesn't include PyNaCl. Use a real build (A1) to test on a
  phone.
- **If a build fails**, run it again with `-v` (e.g. `flet build apk --yes -v`)
  and look at the first red error; most first-time failures are a missing
  Xcode licence, CocoaPods, or disk space.
