# Security & Encryption Design

How the app keeps group chat, media and incident reports private — and, just
as important, what it does **not** protect against.

## One-sentence version

Everything is encrypted **on the phone** before it is sent, with keys Firebase
never sees, so Firebase (and anyone who breaks into it) only ever holds
unreadable ciphertext — and Firestore security rules additionally stop anyone
outside a group, including other organisations' employers, from even fetching it.

## Two walls

1. **Crypto (the main wall).** Content is encrypted with a per-group key that
   only members hold. Even with full database access you get ciphertext.
2. **Firestore security rules (`firestore.rules`).** Only members can read a
   group's items; only admins of *that group's* organisation can change its
   membership; each person can read only their own sealed key; the user
   directory can't be browsed. This stops cross-organisation snooping on
   metadata and ciphertext too.

## Building blocks (libsodium via PyNaCl)

| Purpose | What we use | Why |
|---|---|---|
| User identity | X25519 key pair | Private key never leaves the device unencrypted |
| Sharing the group key | Sealed box (`crypto_box_seal`) | Only one member's private key can open it |
| Chat, media, incidents | XSalsa20-Poly1305 (`SecretBox`) | Secret **and** tamper-proof |
| Password stretching | Argon2id (64 MiB, interactive) | Slows password guessing |
| Auth secret / backup key | BLAKE2b with separate personalisation | Two unrelated secrets from one password |
| Accounts & sessions | Firebase Auth (ID tokens, ~1 h, auto-refreshed) | Managed, free |

## Passwords and the key backup

Your password is never sent anywhere. On the phone it goes through Argon2id
(salted by your email) and is split into:

- an **auth secret** — this is what Firebase Auth receives as "the password";
- a **backup key** — encrypts your private key. The encrypted backup lives in
  your own `users/{uid}` document (only you can read it).

So you can sign in on a new phone and get your history back, while Firebase
(which only sees the auth secret) can't compute the backup key.

## How a message travels

1. Sign-up: keys are made on the device. Uploaded: public key, encrypted
   private-key backup, profile (name, email, phone, role), and hashed
   email/phone directory entries so employers can find you.
2. An employer creates a group: their phone makes a random 256-bit group key and
   **seals** it to each member's public key (`groups/{id}/keys/{uid}_{version}`).
3. To send, the phone encrypts text / photo / the whole incident with the group
   key and uploads `nonce + ciphertext` (photos split into ~700 KB chunks).
4. To read, a member opens their sealed copy of the key and decrypts locally.
5. When someone is **removed**, the rules *require* a new key version; the
   employer's phone seals a fresh key to everyone who remains. The removed
   person can't read anything sent afterwards (and the rules block them anyway).
   New members get the current key, so they can read history since the last removal.

## Threat model — what IS protected

- **Firebase / Google, or a database leak:** only ciphertext, sealed keys, public
  keys, encrypted key backups. Content stays unreadable.
- **A rival employer (another organisation):** can't read, list, join, post to,
  or create groups in your org — rules refuse it, and they hold no keys.
- **Employees:** can't add/remove people or post as someone else.
- **Tampering:** any modified message fails to decrypt.
- **A network eavesdropper:** HTTPS + ciphertext.

## Threat model — what is NOT (yet) protected — be aware

- **The employer of your own group can read it.** They created it and hold the
  key (that's how they add people). Groups are for work conversations.
- **A compromised or unlocked phone.** Whoever holds it can read what that
  person can read.
- **Weak passwords.** Someone with database access could try to guess your
  password offline against your key backup. Argon2id slows this down; a long
  password stops it.
- **Forgotten password = lost history.** Firebase's "reset password" email
  doesn't help — the backup is locked with your real password.
- **Metadata.** Firebase sees who is in which group, when items are sent, and
  plaintext **names** of people, organisations and groups. Phone numbers and
  emails are stored in your private profile; the directory stores only SHA-256
  hashes of them (phone-number hashes can be brute-forced, so treat phone numbers
  as visible to Firebase).
- **Phone numbers aren't verified** (SMS needs the paid Blaze plan). A number is
  first-come-first-served. Employers see the person's name and safety number
  before adding them — check it.
- **Key substitution.** A malicious server could swap a public key. Compare
  **safety numbers** (Members tab / "My safety number") in person for high
  assurance.
- **Forward secrecy.** Keys rotate on removal, not per message. Signal/MLS-style
  ratchets are the upgrade path.

## Rules for contributors

- **Never** send a private key, group key, real password or plaintext to Firebase.
- **Never** ship `firebase-admin` or a service-account key in the app — it
  bypasses the rules.
- Change `firestore.rules` and `fake_firebase.py` together, then run
  `bash run_emulator_demo.sh` (real rules) and `python demo.py`.
- Deploy rules after every change: `firebase deploy --only firestore:rules`.
- Keep crypto in `e2e.py`, Firebase calls in `firebase_rest.py`/`client_api.py`.
