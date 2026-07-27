# Security & Encryption Design

How the app keeps group chat, media, and incident reports private — and, just
as important, what it does **not** protect against.

## One-sentence version

Everything is encrypted **on the phone** before it is sent, with a key the
server never sees, so the server (and anyone who steals its database) only ever
holds unreadable ciphertext.

## Building blocks (libsodium via PyNaCl, plus Argon2 for passwords)

| Purpose | What we use | Why |
|---|---|---|
| User identity | X25519 key pair | Private key stays on device |
| Sharing the group key | Sealed box (`crypto_box_seal`) | Only one member's private key can open it |
| Chat, media, incidents | XSalsa20-Poly1305 (`SecretBox`) | Secret **and** tamper-proof |
| Passwords | Argon2id (`argon2-cffi`) | Winner of the Password Hashing Competition |
| Login sessions | Random 256-bit bearer tokens | Checked per request |

## How a message travels

1. Each user registers: keys are generated on the device; only the **public**
   key and an **Argon2 hash** of the password are uploaded.
2. A group has one random 256-bit **group key**, created on a member's device.
3. That group key is **sealed** to each member's public key and stored as an
   opaque blob. The server cannot open it.
4. To send, the phone encrypts the chat text / photo / whole incident report
   with the group key and uploads only `nonce + ciphertext`.
5. To read, a member downloads their sealed group key, opens it with their
   private key, then decrypts locally.

## How this maps to "the best available"

The state of the art for group end-to-end encryption is the **Signal Protocol**
and **MLS (RFC 9420)**. This project deliberately does **not** re-implement
those from scratch — hand-rolling ratchets is how real apps get breached.
Instead it uses the **same primitives and the same "seal the group key to each
member" pattern**, via a library used in production by many apps.

## Threat model — what IS protected

- **A stolen server / database:** only ciphertext, sealed keys, public keys, and
  Argon2 password hashes. Content stays unreadable. (`demo.py` proves the
  plaintext is nowhere in the database file.)
- **A curious or malicious server operator:** cannot read content.
- **A network eavesdropper:** sees only ciphertext (run behind HTTPS too).
- **Tampering:** any modified message fails to decrypt.
- **An outsider not in the group:** has no group key and is refused by the API.

## Threat model — what is NOT (yet) protected — be aware

- **A compromised phone.** If someone unlocks a member's device they can read
  that member's data. Encryption cannot fix a stolen, unlocked phone.
- **Full forward secrecy / post-compromise security.** Signal/MLS rotate keys on
  *every message* (the "double ratchet"). Here the group key rotates only when
  **membership changes** (`rotate_group_key`). A reasonable middle ground, not
  the maximum. Moving to a ratchet/MLS library is the upgrade path.
- **Metadata.** The server learns who is in a group and when messages are sent,
  though not their contents.
- **Key verification.** For highest assurance, members should verify each
  other's public-key fingerprints out-of-band (a future "safety number" screen).
- **Private-key backup.** The private key lives on one device. If a user loses
  the phone they lose access to old messages. Add an encrypted key-backup flow
  before real-world use.

## Rules for contributors

- **Never** send a private key, group key, or plaintext password to the server.
- **Never** commit a real database or any `.key`/`.env` file (see `.gitignore`).
- Always run behind **HTTPS** in production.
- Keep encryption in `e2e.py` and network calls in `client_api.py`; keep the
  server "dumb" (storage + auth only).
