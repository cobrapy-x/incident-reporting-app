"""
firebase_rest.py  —  tiny Firebase client (Auth + Firestore) over plain HTTPS
=============================================================================
There is no official Firebase *client* SDK for Python (firebase-admin is for
servers and bypasses security rules, so it must never ship in an app). Instead
this file speaks Firebase's public REST APIs with `requests`, as the signed-in
user, so every read/write is checked by `firestore.rules`.

Works against:
  * the real Firebase project (free Spark plan is enough), or
  * the local Firebase Emulator Suite (`firebase emulators:start`), or
  * the offline test double in fake_firebase.py (used by demo.py).

Only this file knows about URLs and Firestore's JSON value format.
"""

import base64
import json
import os
import time
from datetime import datetime, timezone

import requests

SERVER_TIMESTAMP = object()     # sentinel: "set this field to the server's time"


class Timestamp(str):
    """An RFC3339 string that should be sent as a Firestore timestamp."""


class FirebaseError(Exception):
    """A Firebase REST error with a short code (e.g. PERMISSION_DENIED)."""

    def __init__(self, code, message, status=None):
        super().__init__(f"{code}: {message}" if message and message != code else code)
        self.code = code
        self.status = status


FRIENDLY = {
    "EMAIL_EXISTS": "An account with this email already exists.",
    "EMAIL_NOT_FOUND": "Wrong email or password.",
    "INVALID_PASSWORD": "Wrong email or password.",
    "INVALID_LOGIN_CREDENTIALS": "Wrong email or password.",
    "USER_DISABLED": "This account has been disabled.",
    "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Try again later.",
    "INVALID_EMAIL": "That email address doesn't look right.",
    "PERMISSION_DENIED": "You don't have permission to do that.",
    "ALREADY_EXISTS": "That already exists.",
    "NOT_FOUND": "Not found.",
}


def friendly(err: Exception) -> str:
    if isinstance(err, FirebaseError):
        return FRIENDLY.get(err.code.split(" ")[0], str(err))
    return str(err)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
class FirebaseConfig:
    """apiKey + projectId from the Firebase console (Project settings → Web app).

    These two values are NOT secrets — every Firebase web/mobile app ships
    them. Security comes from firestore.rules + end-to-end encryption.
    """

    def __init__(self, api_key, project_id, emulator_host=None):
        self.api_key = api_key
        self.project_id = project_id
        self.emulator_host = emulator_host       # e.g. "127.0.0.1" or None

        if emulator_host:
            self.auth_base = f"http://{emulator_host}:9099/identitytoolkit.googleapis.com/v1"
            self.token_url = f"http://{emulator_host}:9099/securetoken.googleapis.com/v1/token"
            fs = f"http://{emulator_host}:8080/v1"
        else:
            self.auth_base = "https://identitytoolkit.googleapis.com/v1"
            self.token_url = "https://securetoken.googleapis.com/v1/token"
            fs = "https://firestore.googleapis.com/v1"
        self.db_root = f"projects/{project_id}/databases/(default)/documents"
        self.fs_base = f"{fs}/{self.db_root}"

    @classmethod
    def load(cls, path=None):
        """Read firebase_config.json (next to this file) + env overrides.

        Env vars: FIREBASE_API_KEY, FIREBASE_PROJECT_ID,
                  FIREBASE_EMULATOR_HOST (set to e.g. 127.0.0.1 to use emulators)
        """
        path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "firebase_config.json")
        data = {}
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
        api_key = os.environ.get("FIREBASE_API_KEY", data.get("apiKey"))
        project = os.environ.get("FIREBASE_PROJECT_ID", data.get("projectId"))
        emu = os.environ.get("FIREBASE_EMULATOR_HOST", data.get("emulatorHost") or None)
        if emu:
            api_key = api_key or "fake-api-key"
            project = project or "demo-incident"
        if not api_key or not project:
            raise RuntimeError(
                "Missing Firebase config. Copy firebase_config.example.json to "
                "firebase_config.json and fill in apiKey + projectId "
                "(see DEPLOY_FIREBASE.md).")
        return cls(api_key, project, emu)


# ---------------------------------------------------------------------------
# Firestore value encoding  (Python <-> Firestore REST JSON)
# ---------------------------------------------------------------------------
def encode_value(v):
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, Timestamp):
        return {"timestampValue": str(v)}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, (bytes, bytearray)):
        return {"bytesValue": base64.b64encode(bytes(v)).decode()}
    if isinstance(v, datetime):
        return {"timestampValue": v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [encode_value(x) for x in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {k: encode_value(x) for k, x in v.items()}}}
    raise TypeError(f"can't store {type(v)} in Firestore")


def decode_value(v):
    (kind, val), = v.items()
    if kind == "nullValue":
        return None
    if kind == "booleanValue":
        return bool(val)
    if kind == "integerValue":
        return int(val)
    if kind == "doubleValue":
        return float(val)
    if kind in ("stringValue", "referenceValue", "timestampValue"):
        return val
    if kind == "bytesValue":
        return base64.b64decode(val)
    if kind == "arrayValue":
        return [decode_value(x) for x in val.get("values", [])]
    if kind == "mapValue":
        return {k: decode_value(x) for k, x in val.get("fields", {}).items()}
    if kind == "geoPointValue":
        return val
    raise ValueError(f"unknown Firestore type {kind}")


def decode_doc(doc):
    return {k: decode_value(v) for k, v in doc.get("fields", {}).items()}


def ts_key(ts: str):
    """Sortable key for an RFC3339 timestamp string from Firestore."""
    if not ts:
        return (0, 0)
    main, _, frac = ts.rstrip("Z").partition(".")
    secs = int(datetime.strptime(main, "%Y-%m-%dT%H:%M:%S")
               .replace(tzinfo=timezone.utc).timestamp())
    return (secs, int((frac + "000000000")[:9]) if frac else 0)


def ts_local(ts: str) -> str:
    """'2026-11-07T09:12:03.123Z' -> '2026-11-07 14:42' in the device's timezone."""
    if not ts:
        return ""
    secs, _ = ts_key(ts)
    return datetime.fromtimestamp(secs).strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Session: one signed-in user
# ---------------------------------------------------------------------------
class FirebaseSession:
    def __init__(self, config: FirebaseConfig, http=None):
        self.cfg = config
        self.http = http or requests.Session()
        self.uid = None
        self.email = None
        self.id_token = None
        self.refresh_token = None
        self.expires_at = 0

    # ---- low level ---------------------------------------------------------
    @staticmethod
    def _raise(r):
        try:
            err = r.json().get("error", {})
        except ValueError:
            raise FirebaseError(f"HTTP_{r.status_code}", r.text[:200], r.status_code)
        if isinstance(err, dict):
            code = err.get("status") or err.get("message") or f"HTTP_{r.status_code}"
            msg = err.get("message", "")
            # Auth errors put the code in `message` ("EMAIL_EXISTS : ...")
            if err.get("message") and err.get("message").split(" ")[0].isupper() \
                    and "_" in err.get("message").split(" ")[0]:
                code = err["message"].split(" ")[0]
            raise FirebaseError(code, msg, r.status_code)
        raise FirebaseError(f"HTTP_{r.status_code}", str(err), r.status_code)

    def _auth_call(self, method, body):
        r = self.http.post(f"{self.cfg.auth_base}/accounts:{method}",
                           params={"key": self.cfg.api_key}, json=body, timeout=30)
        if r.status_code >= 400:
            self._raise(r)
        return r.json()

    def _take_tokens(self, data):
        self.uid = data.get("localId") or data.get("user_id")
        self.email = data.get("email", self.email)
        self.id_token = data.get("idToken") or data.get("id_token")
        self.refresh_token = data.get("refreshToken") or data.get("refresh_token")
        self.expires_at = time.time() + int(data.get("expiresIn") or data.get("expires_in") or 3600) - 60

    def _token(self):
        if not self.id_token:
            raise FirebaseError("UNAUTHENTICATED", "not signed in")
        if time.time() >= self.expires_at:
            r = self.http.post(self.cfg.token_url, params={"key": self.cfg.api_key},
                               data={"grant_type": "refresh_token",
                                     "refresh_token": self.refresh_token}, timeout=30)
            if r.status_code >= 400:
                self._raise(r)
            self._take_tokens(r.json())
        return self.id_token

    def _fs(self, method, url, **kw):
        headers = {"Authorization": f"Bearer {self._token()}"}
        r = self.http.request(method, url, headers=headers, timeout=60, **kw)
        if r.status_code >= 400:
            self._raise(r)
        return r.json() if r.content else {}

    # ---- auth --------------------------------------------------------------
    def sign_up(self, email, password):
        self._take_tokens(self._auth_call(
            "signUp", {"email": email, "password": password, "returnSecureToken": True}))
        return self.uid

    def sign_in(self, email, password):
        self._take_tokens(self._auth_call(
            "signInWithPassword",
            {"email": email, "password": password, "returnSecureToken": True}))
        return self.uid

    def change_password(self, new_password):
        self._take_tokens(self._auth_call(
            "update", {"idToken": self._token(), "password": new_password,
                       "returnSecureToken": True}))

    def send_email_verification(self):
        try:
            self._auth_call("sendOobCode", {"requestType": "VERIFY_EMAIL",
                                            "idToken": self._token()})
        except FirebaseError:
            pass        # best effort; not required to use the app

    def delete_account(self):
        self._auth_call("delete", {"idToken": self._token()})
        self.id_token = None

    # ---- firestore ---------------------------------------------------------
    def doc_name(self, path):
        return f"{self.cfg.db_root}/{path}"

    def get(self, path):
        """Return the document's fields as a dict, or None if it doesn't exist."""
        try:
            return decode_doc(self._fs("GET", f"{self.cfg.fs_base}/{path}"))
        except FirebaseError as e:
            if e.code == "NOT_FOUND" or e.status == 404:
                return None
            raise

    def query(self, parent, collection, where=(), order_by=None, limit=None):
        """Simple structured query.

        where: list of (field, op, value) with op in ==, <, <=, >, >=,
               array-contains.  Returns [(doc_id, dict), ...].
        """
        ops = {"==": "EQUAL", "<": "LESS_THAN", "<=": "LESS_THAN_OR_EQUAL",
               ">": "GREATER_THAN", ">=": "GREATER_THAN_OR_EQUAL",
               "array-contains": "ARRAY_CONTAINS"}
        q = {"from": [{"collectionId": collection}]}
        filters = [{"fieldFilter": {"field": {"fieldPath": f}, "op": ops[op],
                                    "value": encode_value(v)}} for f, op, v in where]
        if len(filters) == 1:
            q["where"] = filters[0]
        elif filters:
            q["where"] = {"compositeFilter": {"op": "AND", "filters": filters}}
        if order_by:
            q["orderBy"] = [{"field": {"fieldPath": order_by}, "direction": "ASCENDING"}]
        if limit:
            q["limit"] = limit
        url = f"{self.cfg.fs_base}/{parent}:runQuery" if parent else f"{self.cfg.fs_base}:runQuery"
        out = []
        for row in self._fs("POST", url, json={"structuredQuery": q}):
            if "document" in row:
                d = row["document"]
                out.append((d["name"].rsplit("/", 1)[1], decode_doc(d)))
        return out

    # writes are built as dicts and sent together with commit() (atomic)
    def w_set(self, path, data, exists=None, merge_fields=None):
        """A write that creates/overwrites `path`.

        exists=False -> must not exist yet (create); True -> must exist.
        merge_fields -> only these top-level fields are written (update mask).
        SERVER_TIMESTAMP values become server-side request-time transforms.
        """
        fields, transforms = {}, []
        for k, v in data.items():
            if v is SERVER_TIMESTAMP:
                transforms.append({"fieldPath": k, "setToServerValue": "REQUEST_TIME"})
            else:
                fields[k] = encode_value(v)
        w = {"update": {"name": self.doc_name(path), "fields": fields}}
        if transforms:
            w["updateTransforms"] = transforms
        if merge_fields is not None:
            w["updateMask"] = {"fieldPaths": [f for f in merge_fields if data.get(f) is not SERVER_TIMESTAMP]}
        if exists is not None:
            w["currentDocument"] = {"exists": exists}
        return w

    def w_delete(self, path):
        return {"delete": self.doc_name(path)}

    def commit(self, writes):
        if not writes:
            return {}
        return self._fs("POST", f"{self.cfg.fs_base}:commit", json={"writes": writes})
