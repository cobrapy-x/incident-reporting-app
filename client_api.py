"""
client_api.py  —  the bridge between the phone app and the encrypted backend
============================================================================
This runs ON THE DEVICE. It does two jobs together:
  1. Talks to the FastAPI server over HTTP (requests).
  2. Encrypts everything BEFORE sending and decrypts AFTER receiving (via e2e).

The Flet UI (main.py) only calls the friendly methods here — it never touches
raw crypto or HTTP. That also makes this file easy to test on its own.

Golden rule: the server only ever receives ciphertext, sealed keys, public
keys, and password hashes. Private keys and group keys stay in this object,
in memory on the device.
"""

import uuid
import requests

import e2e


class Client:
    def __init__(self, server_url: str):
        self.server = server_url.rstrip("/")
        self.token = None
        self.username = None
        self.private_key = None            # stays on this device only
        self._group_keys = {}              # group_id -> group_key (decrypted, in memory)

    # -- internal http helpers ------------------------------------------------
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _get(self, path, **kw):
        r = requests.get(self.server + path, headers=self._headers(), **kw)
        r.raise_for_status()
        return r.json()

    def _post(self, path, json=None):
        r = requests.post(self.server + path, json=json, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def _put(self, path, json=None):
        r = requests.put(self.server + path, json=json, headers=self._headers())
        r.raise_for_status()
        return r.json()

    # -- accounts -------------------------------------------------------------
    def register(self, username: str, password: str):
        """Create an account: makes keys on the device, uploads only the public key."""
        self.private_key, public_key = e2e.generate_identity()
        data = self._post("/register", {
            "username": username, "password": password, "public_key": public_key,
        })
        self.token, self.username = data["token"], data["username"]
        return data

    def login(self, username: str, password: str, private_key: str):
        """Log back in. You must supply the private key saved on THIS device."""
        self.private_key = private_key
        data = self._post("/login", {"username": username, "password": password})
        self.token, self.username = data["token"], data["username"]
        return data

    # -- groups ---------------------------------------------------------------
    def create_group(self, name: str, member_usernames: list) -> str:
        """Create a group, generate its key, and seal that key to every member."""
        group_id = "g-" + uuid.uuid4().hex[:12]
        self._post("/groups", {"id": group_id, "name": name})

        group_key = e2e.new_group_key()
        self._group_keys[group_id] = group_key

        for member in dict.fromkeys([self.username] + member_usernames):  # include self
            pub = self._get(f"/users/{member}/public_key")["public_key"]
            wrapped = e2e.wrap_group_key(group_key, pub)
            self._post(f"/groups/{group_id}/members",
                       {"username": member, "wrapped_group_key": wrapped})
        return group_id

    def add_member(self, group_id: str, username: str):
        pub = self._get(f"/users/{username}/public_key")["public_key"]
        wrapped = e2e.wrap_group_key(self._key(group_id), pub)
        self._post(f"/groups/{group_id}/members",
                   {"username": username, "wrapped_group_key": wrapped})

    def my_groups(self):
        return self._get("/groups")

    def _key(self, group_id: str) -> str:
        """Fetch + unwrap the group key once, then cache it in memory."""
        if group_id not in self._group_keys:
            wrapped = self._get(f"/groups/{group_id}/my-key")["wrapped_group_key"]
            self._group_keys[group_id] = e2e.unwrap_group_key(wrapped, self.private_key)
        return self._group_keys[group_id]

    # -- chat -----------------------------------------------------------------
    def send_chat(self, group_id: str, text: str,
                  media_bytes: bytes = None, media_name: str = None):
        key = self._key(group_id)
        nonce, cipher = e2e.encrypt_text(text, key)
        body = {"kind": "chat", "key_version": 1, "nonce": nonce, "ciphertext": cipher}
        if media_bytes is not None:
            m_nonce, m_cipher = e2e.encrypt(media_bytes, key)
            body.update(media_nonce=m_nonce, media_ciphertext=m_cipher,
                        media_name=media_name)
        return self._post(f"/groups/{group_id}/items", body)

    def read_chat(self, group_id: str):
        """Return chat messages as readable dicts (decrypted on this device)."""
        key = self._key(group_id)
        out = []
        for row in self._get(f"/groups/{group_id}/items", params={"kind": "chat"}):
            msg = {
                "id": row["id"], "sender": row["sender"], "at": row["created_at"],
                "text": e2e.decrypt_text(row["nonce"], row["ciphertext"], key),
                "media": None,
            }
            if row["media_ciphertext"]:
                msg["media"] = {
                    "name": row["media_name"],
                    "bytes": e2e.decrypt(row["media_nonce"],
                                         row["media_ciphertext"], key),
                }
            out.append(msg)
        return out

    # -- incidents (whole report encrypted as one JSON blob) ------------------
    def create_incident(self, group_id: str, incident: dict,
                         photo_bytes: bytes = None, photo_name: str = None):
        key = self._key(group_id)
        nonce, cipher = e2e.encrypt_json(incident, key)
        body = {"kind": "incident", "key_version": 1, "nonce": nonce,
                "ciphertext": cipher}
        if photo_bytes is not None:
            m_nonce, m_cipher = e2e.encrypt(photo_bytes, key)
            body.update(media_nonce=m_nonce, media_ciphertext=m_cipher,
                        media_name=photo_name)
        return self._post(f"/groups/{group_id}/items", body)

    def read_incidents(self, group_id: str):
        key = self._key(group_id)
        out = []
        for row in self._get(f"/groups/{group_id}/items", params={"kind": "incident"}):
            data = e2e.decrypt_json(row["nonce"], row["ciphertext"], key)
            data["_id"] = row["id"]
            data["_photo"] = None
            if row["media_ciphertext"]:
                data["_photo"] = {
                    "name": row["media_name"],
                    "bytes": e2e.decrypt(row["media_nonce"],
                                         row["media_ciphertext"], key),
                }
            out.append(data)
        return out

    def update_incident(self, group_id: str, item_id: int, incident: dict):
        """Save changes to an incident (e.g. a new timestamped update)."""
        key = self._key(group_id)
        nonce, cipher = e2e.encrypt_json(incident, key)
        return self._put(f"/groups/{group_id}/items/{item_id}",
                         {"kind": "incident", "key_version": 1,
                          "nonce": nonce, "ciphertext": cipher})
