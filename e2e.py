"""
e2e.py  —  End-to-end encryption for the Incident Reporting App
================================================================
This module runs ON THE USER'S DEVICE (inside the Flet app). The server never
imports or uses it, and never sees any of the secrets it produces.

The gold standard for GROUP end-to-end encryption is the Signal Protocol / MLS.
You should never hand-write those. Instead we use the SAME proven building
blocks they are made of, via libsodium (the audited `PyNaCl` library):

  1. Every user has an identity KEY PAIR (X25519). The PRIVATE key never leaves
     the device. Only the PUBLIC key is uploaded to the server.
  2. Each group has one random 256-bit GROUP KEY. All messages, media and
     incident reports are encrypted with it using authenticated encryption
     (XSalsa20-Poly1305 via `SecretBox`).
  3. The group key is handed to each member by SEALING it to their public key.
     Only that member's private key can open it. The server just stores the
     sealed blobs; it can never open them.
  4. When someone LEAVES, we make a NEW group key and re-seal it for the
     remaining members (`rotate_group_key`).
  5. Your PASSWORD never leaves the device either. It is stretched with
     Argon2id into two independent secrets (`derive_secrets`):
       - an AUTH password that is what Firebase Auth actually receives, and
       - a BACKUP key that encrypts your private key so you can log in on a
         new phone. Firebase only ever sees the encrypted backup.

Result: the server only ever stores ciphertext and sealed key blobs.
"""

import base64
import json

from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.hash import blake2b
from nacl.pwhash import argon2id
from nacl import utils


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


# ---------------------------------------------------------------------------
# 1) IDENTITY  — one key pair per user, made once on their device
# ---------------------------------------------------------------------------
def generate_identity():
    """Return (private_key, public_key) as base64 strings.

    Keep `private_key` on the device only. Upload `public_key` to the server.
    """
    sk = PrivateKey.generate()
    return (sk.encode(Base64Encoder).decode(),
            sk.public_key.encode(Base64Encoder).decode())


# ---------------------------------------------------------------------------
# 2) GROUP KEY  — one random secret shared by everyone in the group
# ---------------------------------------------------------------------------
def new_group_key() -> str:
    """Create a fresh random 256-bit group key (base64)."""
    return _b64(utils.random(SecretBox.KEY_SIZE))


def wrap_group_key(group_key_b64: str, recipient_public_key_b64: str) -> str:
    """Seal the group key FOR one member using their public key."""
    pub = PublicKey(recipient_public_key_b64.encode(), encoder=Base64Encoder)
    return _b64(SealedBox(pub).encrypt(_unb64(group_key_b64)))


def unwrap_group_key(wrapped_b64: str, my_private_key_b64: str) -> str:
    """Open a sealed group key with YOUR private key. Returns the group key."""
    sk = PrivateKey(my_private_key_b64.encode(), encoder=Base64Encoder)
    return _b64(SealedBox(sk).decrypt(_unb64(wrapped_b64)))


def wrap_for_members(group_key_b64: str, members: dict) -> dict:
    """Wrap one group key for many members. `members` = {username: public_key}."""
    return {name: wrap_group_key(group_key_b64, pub) for name, pub in members.items()}


def rotate_group_key(remaining_members: dict):
    """Make a NEW group key and wrap it for the members who are still in.

    Returns (new_group_key_b64, {username: wrapped_key_b64}).
    """
    gk = new_group_key()
    return gk, wrap_for_members(gk, remaining_members)


# ---------------------------------------------------------------------------
# 3) ENCRYPT / DECRYPT  — with the group key (authenticated)
# ---------------------------------------------------------------------------
def encrypt(plaintext: bytes, group_key_b64: str):
    """Encrypt bytes. Returns (nonce_b64, ciphertext_b64). Works for text or media."""
    box = SecretBox(_unb64(group_key_b64))
    nonce = utils.random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)
    return _b64(nonce), _b64(encrypted.ciphertext)


def decrypt(nonce_b64: str, ciphertext_b64: str, group_key_b64: str) -> bytes:
    """Reverse of encrypt(). Raises if the key is wrong or data was tampered."""
    box = SecretBox(_unb64(group_key_b64))
    return box.decrypt(_unb64(ciphertext_b64), _unb64(nonce_b64))


def encrypt_text(text: str, group_key_b64: str):
    return encrypt(text.encode("utf-8"), group_key_b64)


def decrypt_text(nonce_b64: str, ciphertext_b64: str, group_key_b64: str) -> str:
    return decrypt(nonce_b64, ciphertext_b64, group_key_b64).decode("utf-8")


def encrypt_json(obj, group_key_b64: str):
    """Encrypt a Python dict/list (used for whole incident reports)."""
    return encrypt(json.dumps(obj).encode("utf-8"), group_key_b64)


def decrypt_json(nonce_b64: str, ciphertext_b64: str, group_key_b64: str):
    return json.loads(decrypt(nonce_b64, ciphertext_b64, group_key_b64).decode("utf-8"))


# ---------------------------------------------------------------------------
# 4) PASSWORD -> (auth password for Firebase, key-backup encryption key)
# ---------------------------------------------------------------------------
# Argon2id "interactive" limits: ~64 MiB RAM, fine on phones.
_KDF_OPS = argon2id.OPSLIMIT_INTERACTIVE
_KDF_MEM = argon2id.MEMLIMIT_INTERACTIVE


def normalize_email(email: str) -> str:
    return email.strip().lower()


def derive_secrets(email: str, password: str):
    """Stretch the password ON THE DEVICE into two unrelated secrets.

    Returns (auth_password, backup_key_b64):
      auth_password  -> sent to Firebase Auth instead of the real password
      backup_key_b64 -> encrypts the private key backup; never leaves device
    Because Firebase only sees `auth_password`, it can't recompute the backup
    key (the two are separate one-way hashes of the Argon2id output).
    """
    salt = blake2b(b"incident-app/v1/" + normalize_email(email).encode(),
                   digest_size=argon2id.SALTBYTES, encoder=RawEncoder)
    master = argon2id.kdf(32, password.encode("utf-8"), salt,
                          opslimit=_KDF_OPS, memlimit=_KDF_MEM)
    auth = blake2b(master, digest_size=32, person=b"fb-auth-password",
                   encoder=RawEncoder)
    backup = blake2b(master, digest_size=32, person=b"key-backup-enc-k",
                     encoder=RawEncoder)
    return base64.urlsafe_b64encode(auth).decode().rstrip("="), _b64(backup)


def backup_private_key(private_key_b64: str, backup_key_b64: str) -> dict:
    """Encrypt the private key for storage in your own Firestore profile."""
    nonce, cipher = encrypt(private_key_b64.encode(), backup_key_b64)
    return {"v": 1, "nonce": nonce, "ciphertext": cipher}


def restore_private_key(backup: dict, backup_key_b64: str) -> str:
    """Reverse of backup_private_key(). Raises if the password was wrong."""
    return decrypt(backup["nonce"], backup["ciphertext"], backup_key_b64).decode()


def public_key_of(private_key_b64: str) -> str:
    sk = PrivateKey(private_key_b64.encode(), encoder=Base64Encoder)
    return sk.public_key.encode(Base64Encoder).decode()


def fingerprint(public_key_b64: str) -> str:
    """Short 'safety number' to compare in person (e.g. 3F2A 91C0 ...)."""
    h = blake2b(_unb64(public_key_b64), digest_size=10, encoder=RawEncoder).hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))
