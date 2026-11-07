"""
fake_firebase.py  —  OFFLINE stand-in for Firebase Auth + Firestore (tests only)
================================================================================
Lets `python demo.py` run with no internet and no Java: it plugs into
`requests` as a transport adapter and answers the same REST calls that
firebase_rest.py makes to the real Firebase.

It also re-implements firestore.rules in Python so the demo can prove the
org/group isolation. That mirror is for fast local feedback — the
authoritative check is running demo.py against the REAL emulator:

    firebase emulators:exec --only auth,firestore --project demo-incident \
        "python demo.py --emulator"

Never ship this file in the app; it has no security of its own.
"""

import base64
import copy
import hashlib
import itertools
import json
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

import requests
from requests.adapters import BaseAdapter

from firebase_rest import decode_doc, ts_key

HOST = "fake"   # FirebaseConfig(api_key, project, emulator_host="fake")


class Denied(Exception):
    pass


class FakeFirebase(BaseAdapter):
    def __init__(self):
        super().__init__()
        self.accounts = {}          # email -> {uid, password}
        self.tokens = {}            # token -> (uid, email)
        self.docs = {}              # "a/b/c/d" -> {"fields": {...raw firestore json}}
        self._clock = itertools.count(1)

    # ----------------------------------------------------------- plumbing
    def session(self):
        s = requests.Session()
        s.mount(f"http://{HOST}:", self)
        return s

    def close(self):
        pass

    def send(self, request, **kw):
        url = urlparse(request.url)
        body = request.body or b""
        if isinstance(body, bytes):
            body = body.decode()
        try:
            if url.port == 9099:
                status, data = self._auth(url, body)
            else:
                status, data = self._firestore(request.method, url, body,
                                               request.headers.get("Authorization", ""))
        except Denied as e:
            status, data = 403, {"error": {"code": 403, "status": "PERMISSION_DENIED",
                                           "message": f"Missing or insufficient permissions. ({e})"}}
        r = requests.Response()
        r.status_code = status
        r._content = json.dumps(data).encode()
        r.headers["Content-Type"] = "application/json"
        r.url = request.url
        r.request = request
        return r

    @staticmethod
    def _err(code, status, msg):
        return code, {"error": {"code": code, "status": status, "message": msg}}

    # ----------------------------------------------------------- auth
    def _issue(self, uid, email):
        tok = "fake-" + secrets.token_hex(16)
        self.tokens[tok] = (uid, email)
        return {"localId": uid, "email": email, "idToken": tok,
                "refreshToken": "r-" + tok, "expiresIn": "3600"}

    def _auth(self, url, body):
        if url.path.endswith("/token"):
            q = parse_qs(body)
            tok = q["refresh_token"][0][2:]
            uid, email = self.tokens[tok]
            d = self._issue(uid, email)
            return 200, {"id_token": d["idToken"], "refresh_token": d["refreshToken"],
                         "expires_in": "3600", "user_id": uid}
        method = url.path.rsplit(":", 1)[1]
        b = json.loads(body or "{}")
        if method == "signUp":
            if b["email"] in self.accounts:
                return 400, {"error": {"code": 400, "message": "EMAIL_EXISTS"}}
            uid = secrets.token_hex(14)
            self.accounts[b["email"]] = {"uid": uid, "password": b["password"]}
            return 200, self._issue(uid, b["email"])
        if method == "signInWithPassword":
            a = self.accounts.get(b["email"])
            if not a or a["password"] != b["password"]:
                return 400, {"error": {"code": 400, "message": "INVALID_LOGIN_CREDENTIALS"}}
            return 200, self._issue(a["uid"], b["email"])
        uid, email = self.tokens.get(b.get("idToken"), (None, None))
        if not uid:
            return 400, {"error": {"code": 400, "message": "INVALID_ID_TOKEN"}}
        if method == "update":
            self.accounts[email]["password"] = b["password"]
            return 200, self._issue(uid, email)
        if method == "delete":
            self.accounts.pop(email, None)
            return 200, {}
        if method == "sendOobCode":
            return 200, {"email": email}
        return 400, {"error": {"code": 400, "message": "UNKNOWN_METHOD"}}

    # ----------------------------------------------------------- firestore
    def _who(self, header):
        tok = header.replace("Bearer ", "")
        if tok == "owner":
            return {"uid": None, "email": None, "admin": True}
        if tok not in self.tokens:
            # accept unsigned tokens from the real Auth emulator (--auth-emulator)
            try:
                part = tok.split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
                return {"uid": claims["user_id"], "email": claims.get("email"), "admin": False}
            except Exception:
                return None
        uid, email = self.tokens[tok]
        return {"uid": uid, "email": email, "admin": False}

    def _now(self):
        n = next(self._clock)
        base = datetime.now(timezone.utc).replace(microsecond=0)
        return base.strftime("%Y-%m-%dT%H:%M:%S") + f".{n:06d}Z"

    def _firestore(self, method, url, body, authz):
        auth = self._who(authz)
        path = unquote(url.path)
        root = path.split("/documents", 1)
        rest = root[1] if len(root) > 1 else ""
        if rest.startswith(":commit"):
            return self._commit(auth, json.loads(body))
        if rest.endswith(":runQuery"):
            parent = rest[:-len(":runQuery")].strip("/")
            return self._query(auth, parent, json.loads(body)["structuredQuery"])
        doc_path = rest.strip("/")
        if method == "GET":
            doc = self.docs.get(doc_path)
            self._check(auth, "get", doc_path, decode(doc), None, self.docs, self.docs)
            if doc is None:
                return self._err(404, "NOT_FOUND", f"No document to update: {doc_path}")
            return 200, {"name": doc_path, "fields": doc["fields"]}
        return self._err(400, "INVALID_ARGUMENT", "unsupported")

    def _commit(self, auth, req):
        now = self._now()
        after = copy.deepcopy(self.docs)
        checks = []
        for w in req["writes"]:
            if "delete" in w:
                p = w["delete"].split("/documents/", 1)[1]
                checks.append(("delete", p))
                after.pop(p, None)
                continue
            p = w["update"]["name"].split("/documents/", 1)[1]
            cur = after.get(p)
            pre = w.get("currentDocument", {})
            if pre.get("exists") is False and cur is not None:
                return self._err(409, "ALREADY_EXISTS", f"Document already exists: {p}")
            if pre.get("exists") is True and cur is None:
                return self._err(404, "NOT_FOUND", f"No document to update: {p}")
            fields = copy.deepcopy(w["update"].get("fields", {}))
            if "updateMask" in w and cur is not None:
                merged = copy.deepcopy(cur["fields"])
                for f in w["updateMask"]["fieldPaths"]:
                    if f in fields:
                        merged[f] = fields[f]
                    else:
                        merged.pop(f, None)
                fields = merged
            for t in w.get("updateTransforms", []):
                fields[t["fieldPath"]] = {"timestampValue": now}
            checks.append(("create" if cur is None else "update", p))
            after[p] = {"fields": fields}
        for op, p in checks:
            before_doc = self.docs.get(p)
            self._check(auth, op, p, decode(before_doc), decode(after.get(p)),
                        self.docs, after, now)
        self.docs = after
        return 200, {"commitTime": now, "writeResults": [{} for _ in req["writes"]]}

    def _query(self, auth, parent, q):
        coll = q["from"][0]["collectionId"]
        prefix = f"{parent}/{coll}/" if parent else f"{coll}/"
        rows = [(p, d) for p, d in self.docs.items()
                if p.startswith(prefix) and "/" not in p[len(prefix):]]

        def match(f, data):
            ff = f["fieldFilter"]
            field, op = ff["field"]["fieldPath"], ff["op"]
            val = decode({"fields": {"v": ff["value"]}})["v"]
            have = data.get(field)
            if op == "ARRAY_CONTAINS":
                return isinstance(have, list) and val in have
            if op == "EQUAL":
                return have == val
            if have is None:
                return False
            a, b = (ts_key(have), ts_key(val)) if "timestampValue" in ff["value"] else (have, val)
            return {"GREATER_THAN": a > b, "GREATER_THAN_OR_EQUAL": a >= b,
                    "LESS_THAN": a < b, "LESS_THAN_OR_EQUAL": a <= b}[op]

        filters = []
        if "where" in q:
            w = q["where"]
            filters = w["compositeFilter"]["filters"] if "compositeFilter" in w else [w]
        out = [(p, d) for p, d in rows if all(match(f, decode(d)) for f in filters)]
        if q.get("orderBy"):
            fld = q["orderBy"][0]["field"]["fieldPath"]
            out.sort(key=lambda pd: ts_key(decode(pd[1]).get(fld) or ""))
        if q.get("limit"):
            out = out[:q["limit"]]
        # rules: the query itself must be allowed (items/chunks rules don't
        # depend on the doc), and every returned doc must be allowed
        if coll in ("items", "chunks"):
            self._check(auth, "list", prefix + "_probe_", None, None, self.docs, self.docs)
        for p, d in out:
            self._check(auth, "list", p, decode(d), None, self.docs, self.docs)
        return 200, [{"document": {"name": f"projects/x/databases/(default)/documents/{p}",
                                   "fields": d["fields"]}} for p, d in out] or [{"readTime": "x"}]

    # ----------------------------------------------------------- RULES MIRROR
    def _check(self, auth, op, path, res, inc, before, after, now=None):
        if auth and auth.get("admin"):
            return
        ok = self._rules(auth, op, path, res, inc, before, after, now)
        if not ok:
            raise Denied(f"{op} {path}")

    def _rules(self, auth, op, path, res, inc, before, after, now):
        signed = auth is not None
        me = auth["uid"] if signed else None
        seg = path.split("/")

        def get(p, store=before):
            return decode(store.get(p)) or {}

        def changed_only(keys):
            ks = set(res) | set(inc)
            changed = {k for k in ks if res.get(k) != inc.get(k)}
            return changed <= set(keys)

        def keys_only(keys):
            return set(inc) <= set(keys)

        def valid_name(n):
            return isinstance(n, str) and 0 < len(n) <= 100

        def org_admin(org_id):
            return signed and me in (get(f"orgs/{org_id}").get("admins") or [])

        def is_member(gid):
            return signed and me in (get(f"groups/{gid}").get("members") or [])

        is_get = op == "get"
        is_list = op == "list"

        # ---- users/{uid}
        if len(seg) == 2 and seg[0] == "users":
            uid = seg[1]
            if is_get:
                return signed and me == uid
            if is_list:
                return False
            if op == "create":
                return (signed and me == uid
                        and keys_only(["displayName", "email", "phone", "role", "keyBackup", "createdAt"])
                        and inc.get("role") in ("employee", "employer")
                        and inc.get("email") == auth["email"]
                        and valid_name(inc.get("displayName"))
                        and inc.get("createdAt") == now)
            if op == "update":
                return (signed and me == uid and changed_only(["displayName", "phone", "keyBackup"])
                        and valid_name(inc.get("displayName")))
            return False

        # ---- publicKeys/{uid}
        if len(seg) == 2 and seg[0] == "publicKeys":
            uid = seg[1]
            if is_get:
                return signed
            if is_list:
                return False
            if op in ("create", "update"):
                shape = (keys_only(["publicKey", "displayName"]) if op == "create"
                         else changed_only(["publicKey", "displayName"]))
                return (signed and me == uid and shape
                        and isinstance(inc.get("publicKey"), str) and len(inc["publicKey"]) == 44
                        and valid_name(inc.get("displayName")))
            return False

        # ---- lookup/{id}
        if len(seg) == 2 and seg[0] == "lookup":
            lid = seg[1]
            if is_get:
                return signed
            if is_list:
                return False
            if op == "create":
                mine = "email_" + hashlib.sha256(auth["email"].lower().encode()).hexdigest()
                return (signed and keys_only(["uid"]) and inc.get("uid") == me
                        and (lid == mine or re.fullmatch(r"phone_[0-9a-f]{64}", lid) is not None))
            if op == "delete":
                return signed and res.get("uid") == me
            return False

        # ---- orgs/{orgId}
        if len(seg) == 2 and seg[0] == "orgs":
            if is_get or is_list:
                return signed and me in (res or {}).get("admins", [])
            if op == "create":
                return (signed and get(f"users/{me}").get("role") == "employer"
                        and keys_only(["name", "ownerUid", "admins", "createdAt"])
                        and inc.get("ownerUid") == me and inc.get("admins") == [me]
                        and valid_name(inc.get("name")) and inc.get("createdAt") == now)
            if op == "update":
                return (signed and res.get("ownerUid") == me and changed_only(["name", "admins"])
                        and me in inc.get("admins", []) and valid_name(inc.get("name")))
            return False

        # ---- groups/{gid}
        if len(seg) == 2 and seg[0] == "groups":
            if is_get or is_list:
                return signed and me in (res or {}).get("members", [])
            if op == "create":
                m = inc.get("members", [])
                return (org_admin(inc.get("orgId"))
                        and keys_only(["orgId", "orgName", "name", "createdBy", "members",
                                       "keyVersion", "createdAt"])
                        and inc.get("createdBy") == me and me in m and len(m) <= 50
                        and len(set(m)) == len(m) and inc.get("keyVersion") == 1
                        and valid_name(inc.get("name"))
                        and inc.get("orgName") == get(f"orgs/{inc.get('orgId')}").get("name")
                        and inc.get("createdAt") == now)
            if op == "update":
                m, old_m = inc.get("members", []), res.get("members", [])
                kv, old_kv = inc.get("keyVersion"), res.get("keyVersion")
                return (org_admin(res.get("orgId")) and me in old_m
                        and changed_only(["members", "keyVersion", "name"])
                        and me in m and len(m) <= 50 and len(set(m)) == len(m)
                        and valid_name(inc.get("name"))
                        and kv in (old_kv, old_kv + 1)
                        and (not (set(old_m) - set(m)) or kv == old_kv + 1))
            return False

        # ---- groups/{gid}/keys/{keyId}
        if len(seg) == 4 and seg[0] == "groups" and seg[2] == "keys":
            gid, kid = seg[1], seg[3]
            if is_get or is_list:
                r = res or {}
                return signed and (r.get("uid") == me or r.get("wrappedBy") == me)
            if op == "create":
                ga = get(f"groups/{gid}", after)
                return (signed and org_admin(ga.get("orgId")) and me in ga.get("members", [])
                        and keys_only(["uid", "version", "wrapped", "wrappedBy"])
                        and inc.get("uid") in ga.get("members", [])
                        and inc.get("version") == ga.get("keyVersion")
                        and kid == f"{inc.get('uid')}_{inc.get('version')}"
                        and inc.get("wrappedBy") == me
                        and isinstance(inc.get("wrapped"), str) and len(inc["wrapped"]) < 200)
            return False

        # ---- groups/{gid}/items/{itemId}
        if len(seg) == 4 and seg[0] == "groups" and seg[2] == "items":
            gid = seg[1]
            if is_get or is_list:
                return is_member(gid)
            kv = get(f"groups/{gid}").get("keyVersion")
            if op == "create":
                return (is_member(gid)
                        and keys_only(["kind", "sender", "keyVersion", "nonce", "body", "chunks",
                                       "media", "rev", "createdAt", "updatedAt"])
                        and inc.get("kind") in ("chat", "incident")
                        and inc.get("sender") == me and inc.get("keyVersion") == kv
                        and inc.get("createdAt") == now and inc.get("updatedAt") == now)
            if op == "update":
                return (is_member(gid) and res.get("kind") == "incident"
                        and changed_only(["keyVersion", "nonce", "body", "chunks", "media", "rev",
                                          "updatedAt", "editedBy"])
                        and inc.get("keyVersion") == kv and inc.get("editedBy") == me
                        and inc.get("updatedAt") == now)
            return False

        # ---- groups/{gid}/items/{itemId}/chunks/{chunkId}
        if len(seg) == 6 and seg[0] == "groups" and seg[2] == "items" and seg[4] == "chunks":
            gid = seg[1]
            if op in ("get", "list", "create", "delete"):
                return is_member(gid)
            return False

        return False

    # ----------------------------------------------------------- helpers
    def dump_bytes(self) -> bytes:
        """Everything 'the server' stores, as raw bytes (decoded bytesValues
        included) — used to prove no plaintext is stored."""
        out = json.dumps(self.docs).encode()
        for d in self.docs.values():
            for v in _walk(d["fields"]):
                if "bytesValue" in v:
                    out += base64.b64decode(v["bytesValue"])
        return out


def decode(doc):
    return decode_doc(doc) if doc else None


def _walk(fields):
    for v in fields.values():
        yield v
        if "mapValue" in v:
            yield from _walk(v["mapValue"].get("fields", {}))
        if "arrayValue" in v:
            for x in v["arrayValue"].get("values", []):
                yield x
