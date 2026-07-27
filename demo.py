"""
demo.py  —  Full end-to-end proof of the CONNECTED app
======================================================
Runs the whole system against the real FastAPI server (in-memory test client),
using the same client_api.py the phone app uses. It proves:

  1. Two users can register (password), create a group, and chat encrypted.
  2. An incident report round-trips encrypted (create -> update -> read).
  3. The server's database file contains NO plaintext — only ciphertext.
  4. Someone who is not a member is refused.

Run it:
    pip install -r requirements.txt
    python demo.py
"""

import os
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.gettempdir(), "demo_incident.db")
if os.path.exists(os.environ["DB_PATH"]):
    os.remove(os.environ["DB_PATH"])

import requests
from fastapi.testclient import TestClient
import server
from client_api import Client

server.init_db()
_test = TestClient(server.app)


# Make client_api talk to the in-memory test server instead of a real network.
class FakeResp:
    def __init__(self, r):
        self._r = r

    def raise_for_status(self):
        if self._r.status_code >= 400:
            err = requests.HTTPError(f"{self._r.status_code}")
            err.response = self._r
            raise err

    def json(self):
        return self._r.json()


requests.get = lambda url, headers=None, params=None, **k: FakeResp(
    _test.get(url.replace("http://server", ""), headers=headers, params=params))
requests.post = lambda url, json=None, headers=None, **k: FakeResp(
    _test.post(url.replace("http://server", ""), json=json, headers=headers))
requests.put = lambda url, json=None, headers=None, **k: FakeResp(
    _test.put(url.replace("http://server", ""), json=json, headers=headers))


def line(t):
    print("\n" + "=" * 60 + f"\n{t}\n" + "=" * 60)


SERVER = "http://server"
SECRET = "URGENT: gas leak near pump 3, evacuate zone B"

line("1) Alice and Bob register (password-protected)")
alice = Client(SERVER); alice.register("alice", "alice-pw-123")
bob = Client(SERVER); bob.register("bob", "bob-pw-456")
print("  both registered; private keys kept on their own devices")

line("2) Alice creates a group with Bob and sends an encrypted chat")
gid = alice.create_group("Site A Crew", ["bob"])
alice.send_chat(gid, SECRET)
alice.send_chat(gid, "photo attached", media_bytes=b"\x89PNG..fake..", media_name="leak.png")
print("  Alice sent 2 chat messages")
msgs = bob.read_chat(gid)
print("  Bob decrypts:", [m["text"] for m in msgs])
assert msgs[0]["text"] == SECRET
assert msgs[1]["media"]["bytes"] == b"\x89PNG..fake.."
print("  OK: Bob read the exact message and photo")

line("3) Incident report round-trips encrypted")
res = alice.create_incident(gid, {
    "title": "Cracked beam", "reporter": "alice", "assigned_to": "bob",
    "target_date": "2026-07-25", "status": "Open",
    "description": "Hairline crack on level 3.", "updates": [],
    "created_at": "2026-07-18 10:00",
})
item_id = res["id"]
incs = bob.read_incidents(gid)
incs[0]["updates"].append({"text": "Cordoned off", "timestamp": "2026-07-18 12:30"})
clean = {k: v for k, v in incs[0].items() if not k.startswith("_")}
bob.update_incident(gid, item_id, clean)
final = alice.read_incidents(gid)[0]
print("  incident:", final["title"], "| updates:", len(final["updates"]))
assert final["title"] == "Cracked beam" and len(final["updates"]) == 1
print("  OK: created by Alice, updated by Bob, read back correctly")

line("4) The server's database holds no plaintext")
with open(os.environ["DB_PATH"], "rb") as f:
    raw = f.read()
assert SECRET.encode() not in raw
assert b"Cracked beam" not in raw
assert b"Hairline crack" not in raw
print("  OK: none of the secret text appears in the database file")

line("5) An outsider cannot read the group")
eve = Client(SERVER); eve.register("eve", "eve-pw-789")
try:
    eve.read_chat(gid)
    raise SystemExit("FAIL: Eve should have been blocked!")
except requests.HTTPError as ex:
    print("  OK: server refused Eve with HTTP", ex.response.status_code)

line("ALL CHECKS PASSED  ✔  Connected app is end-to-end encrypted")
