# Deploying on Firebase (free Spark plan)

There is **no server to host any more**. The app talks straight to two
Firebase products, both free on the Spark plan:

| Firebase product | What it does here | Free (Spark) limit |
|---|---|---|
| **Authentication** (email/password) | Accounts and sign-in | Plenty for a team app |
| **Cloud Firestore** | Stores ciphertext, sealed keys, public keys | 1 GiB stored, 50K reads / 20K writes / 20K deletes per day |
| **Security rules** (`firestore.rules`) | Replaces `server.py`: who can read/write what | Free |

Not used, because they need the paid Blaze plan: Cloud Functions, Cloud
Storage (photos are stored as encrypted chunks in Firestore instead), and SMS
phone verification (phone numbers are stored but not SMS-verified).

---

## 1. Create the project (5 minutes, in the browser)

1. Go to <https://console.firebase.google.com> → **Create a project**. Any
   name. You can turn Google Analytics off. Stay on the **Spark** plan.
2. **Build → Authentication → Get started → Sign-in method →
   Email/Password → Enable → Save.** Leave "Email link" off.
   - Do **not** turn on a password policy (uppercase/symbol rules). The app
     sends Firebase a long password-derived secret, not the real password,
     so those rules would block sign-up. The app enforces its own minimum.
3. **Build → Firestore Database → Create database.** Pick a location close to
   your users (e.g. `asia-south1` Mumbai). Start in **production mode** (we
   deploy real rules in step 3, so the default "deny everything" is fine).
4. **Project settings (gear) → General → Your apps → Add app → Web (`</>`).**
   Give it a nickname, skip Hosting, and register. Copy the `apiKey` and
   `projectId` it shows you.

## 2. Point the app at your project

```bash
cp firebase_config.example.json firebase_config.json
```
Fill in `apiKey` and `projectId`. These two values are **not secrets** — every
Firebase app ships them. Security comes from the rules + end-to-end encryption.
(`firebase_config.json` is git-ignored anyway, so each developer keeps their own.)

## 3. Deploy the security rules (one command)

You need Node.js. Then:

```bash
npm install -g firebase-tools
firebase login
firebase use --add            # pick your project; or edit .firebaserc
firebase deploy --only firestore:rules,firestore:indexes
```

**Re-run that deploy every time you change `firestore.rules`.**

## 4. Run the app

```bash
source venv/bin/activate
bash run_app.sh
```

1. Create an **Employer** account → create an organisation → create a group.
2. Create **Employee** accounts (another device, or sign out and back in).
3. As the employer, open the group → **Members** → add people by email or
   phone (with country code, e.g. `+91 98765 43210`).

## 5. Build the phone apps

```bash
flet build apk      # Android  -> build/apk/
flet build ipa      # iOS (needs a Mac + Xcode + Apple Developer account)
```
`firebase_config.json` sits next to `main.py`, so it's bundled automatically.

---

## Testing locally with the Firebase emulators (optional, recommended)

`python demo.py` runs offline against `fake_firebase.py`, a Python copy of the
rules. The **authoritative** test is the real emulator, which runs the actual
`firestore.rules`. It needs Java 11+ and `firebase-tools`:

```bash
bash run_emulator_demo.sh          # should end with: ALL CHECKS PASSED
```

To click around the app against emulators instead of the real project:

```bash
firebase emulators:start --only auth,firestore --project demo-incident
# in another terminal:
FIREBASE_EMULATOR_HOST=127.0.0.1 bash run_app.sh
```
The emulator UI at <http://127.0.0.1:4000> lets you browse what's stored —
you'll see only ciphertext.

## Staying inside the free tier

- Chat auto-refresh asks only for **new** items since the last check (1 read
  when nothing changed) every 15 s while a group is open. Change
  `POLL_SECONDS` in `main.py` to trade freshness for reads.
- Photos are shrunk to ≤1600 px JPEG before encryption and split into
  ~700 KB encrypted chunks (Firestore's per-document cap is 1 MiB).
- 1 GiB of Firestore storage is roughly a few thousand photos. Watch
  **Firestore → Usage** in the console. On Spark, going over a daily quota
  just pauses that operation until midnight Pacific — you are never billed.

## Optional hardening

- In Google Cloud Console → **APIs & Services → Credentials**, restrict the
  web API key to: Identity Toolkit API, Token Service API, Cloud Firestore API.
- Authentication → Settings → keep **Email enumeration protection** on.
- **Don't send Firebase "reset password" emails.** A reset sets a password the
  app didn't derive, and the encrypted key backup can't be opened with it.
  (A future "reset identity" flow could create fresh keys; old messages would
  stay unreadable by design.)
