"""
client_api.py  —  the bridge between the phone app and Firebase
===============================================================
Runs ON THE DEVICE. It does two jobs together:
  1. Talks to Firebase (Auth + Firestore) as the signed-in user (firebase_rest).
  2. Encrypts everything BEFORE sending and decrypts AFTER receiving (e2e).

The Flet UI (main.py) only calls the friendly methods here.

Golden rule: Firebase only ever receives ciphertext, sealed keys, public keys,
an *encrypted* private-key backup, and a password-derived auth secret (never
the password itself). Private keys and group keys stay in this object.

Firestore layout (enforced by firestore.rules)
----------------------------------------------
users/{uid}                 private profile: name, email, phone, role, keyBackup
publicKeys/{uid}            displayName + X25519 public key (anyone signed in)
lookup/{email_<sha256> | phone_<sha256>}  -> {uid}   (exact-match directory)
orgs/{orgId}                name, ownerUid, admins[]            (employers)
groups/{gid}                orgId, orgName, name, members[], keyVersion
groups/{gid}/keys/{uid}_{v} group key v sealed to that member
groups/{gid}/items/{id}     chat | incident, ciphertext (+ chunks/ for photos)
"""

import base64
import hashlib
import json
import re
import uuid

import e2e
from firebase_rest import (FirebaseConfig, FirebaseError, FirebaseSession,
                           SERVER_TIMESTAMP, Timestamp, ts_key, ts_local)

__all__ = ["Client", "FirebaseError", "normalize_phone", "lookup_id"]

MAX_MEMBERS = 50
CHUNK_BYTES = 700_000          # keep each Firestore doc well under its 1 MiB cap
MAX_KEYS_PER_COMMIT = 9        # stay inside rules' get()/getAfter() budget


def normalize_phone(phone: str) -> str:
    """'+91 98765-43210' -> '+919876543210'. Must include the country code."""
    p = re.sub(r"[\s\-().]", "", phone or "")
    if not re.fullmatch(r"\+[1-9]\d{6,14}", p):
        raise ValueError("Phone must include the country code, e.g. +91 98765 43210")
    return p


def lookup_id(identifier: str) -> str:
    """Directory doc id for an email or phone (hashed, so it can't be browsed)."""
    identifier = identifier.strip()
    if "@" in identifier:
        return "email_" + hashlib.sha256(e2e.normalize_email(identifier).encode()).hexdigest()
    return "phone_" + hashlib.sha256(normalize_phone(identifier).encode()).hexdigest()


class Client:
    def __init__(self, config: FirebaseConfig = None, http=None):
        self.cfg = config or FirebaseConfig.load()
        self.fb = FirebaseSession(self.cfg, http=http)
        self.uid = None
        self.profile = {}                 # users/{uid}
        self.private_key = None           # stays on this device, in memory
        self._group_keys = {}             # (gid, version) -> group key
        self._names = {}                  # uid -> publicKeys doc
        self._items = {}                  # gid -> {item_id: decrypted item}
        self._cursor = {}                 # gid -> last updatedAt seen

    # convenience
    @property
    def username(self):
        return self.profile.get("displayName", "")

    @property
    def role(self):
        return self.profile.get("role", "employee")

    @property
    def is_employer(self):
        return self.role == "employer"

    # =====================================================================
    # Accounts
    # =====================================================================
    def register(self, display_name, email, phone, password, role="employee"):
        """Create an account.

        Keys are generated here; Firebase gets the public key, an encrypted
        backup of the private key, and a password-DERIVED auth secret.
        """
        if role not in ("employee", "employer"):
            raise ValueError("role must be employee or employer")
        if len(password) < 8:
            raise ValueError("Use a password of at least 8 characters.")
        if not display_name.strip():
            raise ValueError("Enter your name.")
        email = e2e.normalize_email(email)
        phone = normalize_phone(phone)

        auth_pw, backup_key = e2e.derive_secrets(email, password)
        self.uid = self.fb.sign_up(email, auth_pw)
        try:
            # phone numbers aren't SMS-verified on the free plan, so first
            # come first served; refuse a number someone already registered.
            if self.fb.get(f"lookup/{lookup_id(phone)}") is not None:
                raise ValueError("That phone number is already registered.")
            self.private_key, public_key = e2e.generate_identity()
            self.profile = {
                "displayName": display_name.strip(), "email": email,
                "phone": phone, "role": role,
                "keyBackup": e2e.backup_private_key(self.private_key, backup_key),
            }
            self.fb.commit([
                self.fb.w_set(f"users/{self.uid}",
                              {**self.profile, "createdAt": SERVER_TIMESTAMP}, exists=False),
                self.fb.w_set(f"publicKeys/{self.uid}",
                              {"publicKey": public_key,
                               "displayName": display_name.strip()}, exists=False),
                self.fb.w_set(f"lookup/{lookup_id(email)}", {"uid": self.uid}, exists=False),
                self.fb.w_set(f"lookup/{lookup_id(phone)}", {"uid": self.uid}, exists=False),
            ])
        except Exception:
            # don't leave a half-made account behind
            try:
                self.fb.delete_account()
            except Exception:
                pass
            self.uid = None
            raise
        self.fb.send_email_verification()
        return self.uid

    def login(self, email, password):
        """Sign in on ANY device: the private key is restored from its backup."""
        email = e2e.normalize_email(email)
        auth_pw, backup_key = e2e.derive_secrets(email, password)
        self.uid = self.fb.sign_in(email, auth_pw)
        self.profile = self.fb.get(f"users/{self.uid}") or {}
        if not self.profile.get("keyBackup"):
            raise RuntimeError("This account has no key backup (incomplete sign-up).")
        self.private_key = e2e.restore_private_key(self.profile["keyBackup"], backup_key)
        # sanity check: the public key on file must match our private key
        pub = self.fb.get(f"publicKeys/{self.uid}") or {}
        if pub.get("publicKey") != e2e.public_key_of(self.private_key):
            raise RuntimeError("Your public key on the server doesn't match this "
                               "account's private key. Contact your admin.")
        return self.uid

    def change_password(self, old_password, new_password):
        if len(new_password) < 8:
            raise ValueError("Use a password of at least 8 characters.")
        email = self.profile["email"]
        _, old_backup = e2e.derive_secrets(email, old_password)
        e2e.restore_private_key(self.profile["keyBackup"], old_backup)   # verifies old pw
        new_auth, new_backup = e2e.derive_secrets(email, new_password)
        backup = e2e.backup_private_key(self.private_key, new_backup)
        # update the backup first: if the auth change then fails, the old
        # password still signs in and we just retry.
        self.fb.commit([self.fb.w_set(f"users/{self.uid}", {"keyBackup": backup},
                                      exists=True, merge_fields=["keyBackup"])])
        try:
            self.fb.change_password(new_auth)
        except Exception:
            old = self.profile["keyBackup"]
            self.fb.commit([self.fb.w_set(f"users/{self.uid}", {"keyBackup": old},
                                          exists=True, merge_fields=["keyBackup"])])
            raise
        self.profile["keyBackup"] = backup

    def my_fingerprint(self):
        return e2e.fingerprint(e2e.public_key_of(self.private_key))

    # =====================================================================
    # People
    # =====================================================================
    def person(self, uid):
        """{'displayName', 'publicKey'} for a user (cached)."""
        if uid not in self._names:
            self._names[uid] = self.fb.get(f"publicKeys/{uid}") or {
                "displayName": "(unknown)", "publicKey": None}
        return self._names[uid]

    def name_of(self, uid):
        return self.person(uid).get("displayName", "(unknown)")

    def find_user(self, email_or_phone):
        """Exact lookup by email or phone. Returns {'uid','displayName','fingerprint'}."""
        hit = self.fb.get(f"lookup/{lookup_id(email_or_phone)}")
        if not hit:
            raise LookupError(f"No account found for {email_or_phone.strip()}")
        p = self.person(hit["uid"])
        return {"uid": hit["uid"], "displayName": p.get("displayName"),
                "fingerprint": e2e.fingerprint(p["publicKey"]) if p.get("publicKey") else "-"}

    # =====================================================================
    # Organisations (employers)
    # =====================================================================
    def create_org(self, name):
        if not self.is_employer:
            raise PermissionError("Only employer accounts can create organisations.")
        org_id = "o-" + uuid.uuid4().hex[:16]
        self.fb.commit([self.fb.w_set(f"orgs/{org_id}", {
            "name": name.strip(), "ownerUid": self.uid, "admins": [self.uid],
            "createdAt": SERVER_TIMESTAMP}, exists=False)])
        return org_id

    def my_orgs(self):
        """Orgs I administer: [{'id','name'}] (empty for employees)."""
        if not self.is_employer:
            return []
        rows = self.fb.query(None, "orgs", where=[("admins", "array-contains", self.uid)])
        return sorted(({"id": i, **d} for i, d in rows), key=lambda o: o["name"].lower())

    # =====================================================================
    # Groups
    # =====================================================================
    def create_group(self, org_id, name, member_identifiers=()):
        """Employer: create a group in one of your orgs and seal its key to members.

        member_identifiers: emails and/or phone numbers of people to add.
        """
        try:
            org = self.fb.get(f"orgs/{org_id}")
        except FirebaseError:
            org = None
        if not org:
            raise PermissionError("You are not an admin of that organisation.")
        people = [self.find_user(x)["uid"] for x in member_identifiers if x.strip()]
        members = list(dict.fromkeys([self.uid] + people))
        if len(members) > MAX_MEMBERS:
            raise ValueError(f"A group can have at most {MAX_MEMBERS} members.")
        gid = "g-" + uuid.uuid4().hex[:16]
        group_key = e2e.new_group_key()
        group_doc = {"orgId": org_id, "orgName": org["name"], "name": name.strip(),
                     "createdBy": self.uid, "members": members, "keyVersion": 1,
                     "createdAt": SERVER_TIMESTAMP}
        key_writes = [self._w_key(gid, uid, 1, group_key) for uid in members]
        first, rest = key_writes[:MAX_KEYS_PER_COMMIT], key_writes[MAX_KEYS_PER_COMMIT:]
        self.fb.commit([self.fb.w_set(f"groups/{gid}", group_doc, exists=False)] + first)
        self._commit_in_batches(rest)
        self._group_keys[(gid, 1)] = group_key
        return gid

    def my_groups(self):
        """Groups I'm a member of, with org name and whether I can manage them."""
        admin_orgs = {o["id"] for o in self.my_orgs()}
        rows = self.fb.query(None, "groups", where=[("members", "array-contains", self.uid)])
        out = [{"id": gid, "name": g["name"], "orgId": g["orgId"],
                "orgName": g.get("orgName", ""), "members": len(g["members"]),
                "isAdmin": g["orgId"] in admin_orgs} for gid, g in rows]
        return sorted(out, key=lambda g: (g["orgName"].lower(), g["name"].lower()))

    def group(self, gid):
        try:
            g = self.fb.get(f"groups/{gid}")
        except FirebaseError as e:
            if e.code == "PERMISSION_DENIED":
                raise PermissionError("You are not a member of this group.") from e
            raise
        if g is None:
            raise PermissionError("You are not a member of this group.")
        return g

    def group_members(self, gid):
        g = self.group(gid)
        out = []
        for uid in g["members"]:
            p = self.person(uid)
            out.append({"uid": uid, "displayName": p.get("displayName"),
                        "fingerprint": e2e.fingerprint(p["publicKey"]) if p.get("publicKey") else "-",
                        "isMe": uid == self.uid})
        return out

    def add_member(self, gid, email_or_phone):
        """Org admin: add someone by email or phone. They get the CURRENT key,
        so they can read history sent under it (same as before the port)."""
        return self.add_member_uid(gid, self.find_user(email_or_phone)["uid"])

    def add_member_uid(self, gid, uid):
        g = self.group(gid)
        if uid in g["members"]:
            return uid
        if len(g["members"]) >= MAX_MEMBERS:
            raise ValueError(f"Group is full (max {MAX_MEMBERS} members).")
        v = g["keyVersion"]
        key = self._key(gid, v)
        self.fb.commit([
            self.fb.w_set(f"groups/{gid}", {"members": g["members"] + [uid]},
                          exists=True, merge_fields=["members"]),
            self._w_key(gid, uid, v, key),
        ])
        return uid

    def remove_member(self, gid, uid):
        """Org admin: remove someone and ROTATE the group key so they can't
        read anything sent afterwards."""
        g = self.group(gid)
        if uid not in g["members"]:
            return
        if uid == self.uid:
            raise ValueError("You can't remove yourself.")
        remaining = [m for m in g["members"] if m != uid]
        new_v = g["keyVersion"] + 1
        new_key = e2e.new_group_key()
        key_writes = [self._w_key(gid, m, new_v, new_key) for m in remaining]
        first, rest = key_writes[:MAX_KEYS_PER_COMMIT], key_writes[MAX_KEYS_PER_COMMIT:]
        self.fb.commit([self.fb.w_set(f"groups/{gid}", {"members": remaining, "keyVersion": new_v},
                                      exists=True, merge_fields=["members", "keyVersion"])] + first)
        self._commit_in_batches(rest)
        self._group_keys[(gid, new_v)] = new_key

    def _w_key(self, gid, uid, version, group_key):
        pub = self.person(uid).get("publicKey")
        if not pub:
            raise LookupError("That user has no public key.")
        return self.fb.w_set(f"groups/{gid}/keys/{uid}_{version}", {
            "uid": uid, "version": version, "wrappedBy": self.uid,
            "wrapped": e2e.wrap_group_key(group_key, pub)}, exists=False)

    def _commit_in_batches(self, writes):
        for i in range(0, len(writes), MAX_KEYS_PER_COMMIT):
            self.fb.commit(writes[i:i + MAX_KEYS_PER_COMMIT])

    def _key(self, gid, version):
        """Fetch + unwrap my sealed copy of group key `version`, cache it."""
        k = (gid, version)
        if k not in self._group_keys:
            try:
                doc = self.fb.get(f"groups/{gid}/keys/{self.uid}_{version}")
            except FirebaseError as e:
                if e.code != "PERMISSION_DENIED":   # missing key doc reads as denied
                    raise
                doc = None
            if not doc:
                raise KeyError(f"no key v{version} for you in this group")
            self._group_keys[k] = e2e.unwrap_group_key(doc["wrapped"], self.private_key)
        return self._group_keys[k]

    def _current_version(self, gid):
        return self.group(gid)["keyVersion"]

    # =====================================================================
    # Ciphertext storage (inline if small, chunked if large)
    # =====================================================================
    def _blob_fields(self, gid, item_id, rev, ciphertext: bytes, prefix):
        """Return (inline_bytes_or_None, n_chunks, writes)."""
        if len(ciphertext) <= CHUNK_BYTES and prefix == "b":
            return ciphertext, 0, []
        writes = []
        parts = [ciphertext[i:i + CHUNK_BYTES] for i in range(0, len(ciphertext), CHUNK_BYTES)] or [b""]
        for n, part in enumerate(parts):
            writes.append(self.fb.w_set(
                f"groups/{gid}/items/{item_id}/chunks/{rev}_{prefix}{n}", {"d": part}, exists=False))
        return None, len(parts), writes

    def _read_chunks(self, gid, item_id, rev, prefix, n):
        data = b""
        for i in range(n):
            doc = self.fb.get(f"groups/{gid}/items/{item_id}/chunks/{rev}_{prefix}{i}")
            data += doc["d"]
        return data

    def _encrypt_item(self, gid, item_id, rev, payload: dict, media: bytes = None):
        """Encrypt payload (+ optional media) → (fields, chunk_writes)."""
        v = self._current_version(gid)
        key = self._key(gid, v)
        nonce, cipher = e2e.encrypt(json.dumps(payload).encode(), key)
        inline, n, writes = self._blob_fields(gid, item_id, rev, base64.b64decode(cipher), "b")
        fields = {"keyVersion": v, "nonce": nonce, "body": inline, "chunks": n,
                  "media": None, "rev": rev}
        if media is not None:
            m_nonce, m_cipher = e2e.encrypt(media, key)
            _, mn, mwrites = self._blob_fields(gid, item_id, rev, base64.b64decode(m_cipher), "m")
            fields["media"] = {"nonce": m_nonce, "chunks": mn}
            writes += mwrites
        return fields, writes

    def _decrypt_item(self, gid, item_id, doc):
        key = self._key(gid, doc["keyVersion"])
        rev = doc.get("rev", 0)
        body = doc["body"] if doc.get("body") is not None else \
            self._read_chunks(gid, item_id, rev, "b", doc["chunks"])
        payload = json.loads(e2e.decrypt(doc["nonce"], base64.b64encode(body).decode(), key))
        media = None
        if doc.get("media"):
            raw = self._read_chunks(gid, item_id, rev, "m", doc["media"]["chunks"])
            media = e2e.decrypt(doc["media"]["nonce"], base64.b64encode(raw).decode(), key)
        return payload, media

    # =====================================================================
    # Sync: fetch only what changed since last time (saves free-tier reads)
    # =====================================================================
    def sync(self, gid):
        where = []
        if self._cursor.get(gid):
            where = [("updatedAt", ">", Timestamp(self._cursor[gid]))]
        rows = self.fb.query(f"groups/{gid}", "items", where=where, order_by="updatedAt")
        cache = self._items.setdefault(gid, {})
        for item_id, doc in rows:
            entry = {"id": item_id, "kind": doc["kind"], "sender": doc["sender"],
                     "senderName": self.name_of(doc["sender"]),
                     "createdAt": doc["createdAt"], "at": ts_local(doc["createdAt"]),
                     "updatedAt": doc["updatedAt"], "rev": doc.get("rev", 0)}
            try:
                entry["payload"], entry["media"] = self._decrypt_item(gid, item_id, doc)
                entry["locked"] = False
            except KeyError:
                # sent under a key version from before you joined
                entry["payload"], entry["media"], entry["locked"] = {}, None, True
            cache[item_id] = entry
            if not self._cursor.get(gid) or ts_key(doc["updatedAt"]) > ts_key(self._cursor[gid]):
                self._cursor[gid] = doc["updatedAt"]
        return cache

    def _sorted(self, gid, kind):
        return sorted((i for i in self._items.get(gid, {}).values() if i["kind"] == kind),
                      key=lambda i: ts_key(i["createdAt"]))

    # =====================================================================
    # Chat
    # =====================================================================
    def send_chat(self, gid, text, media_bytes=None, media_name=None):
        item_id = "i-" + uuid.uuid4().hex[:20]
        payload = {"text": text, "mediaName": media_name if media_bytes is not None else None}
        fields, chunk_writes = self._encrypt_item(gid, item_id, 0, payload, media_bytes)
        doc = {"kind": "chat", "sender": self.uid, **fields,
               "createdAt": SERVER_TIMESTAMP, "updatedAt": SERVER_TIMESTAMP}
        # item first (rules check membership via the group), then its chunks
        self.fb.commit([self.fb.w_set(f"groups/{gid}/items/{item_id}", doc, exists=False)])
        self._commit_in_batches(chunk_writes)
        return {"ok": True, "id": item_id}

    def read_chat(self, gid, refresh=True):
        if refresh:
            self.sync(gid)
        out = []
        for i in self._sorted(gid, "chat"):
            p = i["payload"]
            out.append({
                "id": i["id"], "sender": i["senderName"], "senderUid": i["sender"],
                "at": i["at"], "locked": i["locked"],
                "text": p.get("text", "🔒 sent before you joined") if not i["locked"]
                else "🔒 sent before you joined",
                "media": {"name": p.get("mediaName") or "image", "bytes": i["media"]}
                if i["media"] is not None else None,
            })
        return out

    # =====================================================================
    # Incidents (whole report encrypted as one JSON blob)
    # =====================================================================
    def create_incident(self, gid, incident: dict, photo_bytes=None, photo_name=None):
        item_id = "i-" + uuid.uuid4().hex[:20]
        payload = dict(incident)
        if photo_bytes is not None:
            payload["photoName"] = photo_name
        fields, chunk_writes = self._encrypt_item(gid, item_id, 0, payload, photo_bytes)
        doc = {"kind": "incident", "sender": self.uid, **fields,
               "createdAt": SERVER_TIMESTAMP, "updatedAt": SERVER_TIMESTAMP}
        self.fb.commit([self.fb.w_set(f"groups/{gid}/items/{item_id}", doc, exists=False)])
        self._commit_in_batches(chunk_writes)
        return {"ok": True, "id": item_id}

    def read_incidents(self, gid, refresh=True):
        if refresh:
            self.sync(gid)
        out = []
        for i in self._sorted(gid, "incident"):
            if i["locked"]:
                continue
            data = dict(i["payload"])
            data["_id"] = i["id"]
            data["_rev"] = i["rev"]
            data["_photo"] = ({"name": data.get("photoName") or "photo", "bytes": i["media"]}
                              if i["media"] is not None else None)
            out.append(data)
        return out

    def update_incident(self, gid, item_id, incident: dict):
        """Save changes (new timestamped update, status, photos). Re-encrypted
        with the group's current key; old chunks are cleaned up afterwards."""
        old = self._items.get(gid, {}).get(item_id)
        if old is None:
            old = self.sync(gid).get(item_id)
        old_doc = self.fb.get(f"groups/{gid}/items/{item_id}")
        if old_doc is None:
            raise LookupError("incident not found")
        rev = old_doc.get("rev", 0) + 1
        media = old["media"] if old else None
        fields, chunk_writes = self._encrypt_item(gid, item_id, rev, incident, media)
        # write new chunks first, then point the item at them
        self._commit_in_batches(chunk_writes)
        fields.update(updatedAt=SERVER_TIMESTAMP, editedBy=self.uid)
        self.fb.commit([self.fb.w_set(f"groups/{gid}/items/{item_id}", fields, exists=True,
                                      merge_fields=list(fields))])
        # delete the previous revision's chunks
        stale = []
        if old_doc.get("chunks"):
            stale += [f"{old_doc.get('rev', 0)}_b{n}" for n in range(old_doc["chunks"])]
        if old_doc.get("media"):
            stale += [f"{old_doc.get('rev', 0)}_m{n}" for n in range(old_doc["media"]["chunks"])]
        self._commit_in_batches([self.fb.w_delete(f"groups/{gid}/items/{item_id}/chunks/{c}")
                                 for c in stale])
        return {"ok": True}
