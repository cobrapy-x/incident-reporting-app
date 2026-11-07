"""
demo.py  —  end-to-end proof of the Firebase version
=====================================================
Uses the SAME client_api.py the phone app uses and proves:

  1. Employees + employers register (email, phone, password); Firebase never
     receives the real password.
  2. An employer creates an org + group, adds people by email AND by phone.
  3. Chat (incl. a >1 MB photo, chunked) and incident reports round-trip
     encrypted; members can read and update them.
  4. ORG ISOLATION: a rival employer can't read, list, join, post to or
     manage another org's group — and employees can't manage groups.
  5. Removing a member rotates the key; they can't read anything afterwards.
  6. Logging in on a brand-new device restores the key from its encrypted
     backup; password change works; wrong passwords fail.
  7. The database holds NO plaintext (messages, incident text, photos, passwords).

Run it (offline, no setup):
    python demo.py

Run it against the REAL Firebase emulators (authoritative rules check):
    firebase emulators:exec --only auth,firestore --project demo-incident \\
        "python demo.py --emulator"
"""

import base64
import json
import os
import sys

import requests

from firebase_rest import FirebaseConfig, FirebaseError, SERVER_TIMESTAMP
from client_api import Client, lookup_id

EMULATOR = "--emulator" in sys.argv

if EMULATOR:
    CFG = FirebaseConfig("fake-api-key", "demo-incident",
                         emulator_host=os.environ.get("EMU_HOST", "127.0.0.1"))
    HTTP = requests.Session()
    # wipe emulator state from previous runs
    HTTP.delete(f"http://{CFG.emulator_host}:8080/emulator/v1/projects/demo-incident/databases/(default)/documents")
    HTTP.delete(f"http://{CFG.emulator_host}:9099/emulator/v1/projects/demo-incident/accounts")
    FAKE = None
else:
    from fake_firebase import FakeFirebase, HOST
    FAKE = FakeFirebase()
    CFG = FirebaseConfig("fake-api-key", "demo-incident", emulator_host=HOST)
    HTTP = FAKE.session()
    if "--auth-emulator" in sys.argv:
        # real Auth emulator + offline Firestore fake (when Java isn't available)
        real = FirebaseConfig("fake-api-key", "demo-incident", emulator_host="127.0.0.1")
        CFG.auth_base, CFG.token_url = real.auth_base, real.token_url
        HTTP.delete("http://127.0.0.1:9099/emulator/v1/projects/demo-incident/accounts")


def new_device():
    return Client(CFG, http=HTTP)


def line(t):
    print("\n" + "=" * 64 + f"\n{t}\n" + "=" * 64)


def ok(msg):
    print("  OK:", msg)


def denied(fn, what):
    """Assert that fn() is refused by Firebase/rules or the client."""
    try:
        fn()
    except (FirebaseError, PermissionError, KeyError, LookupError, ValueError) as e:
        code = getattr(e, "code", type(e).__name__)
        ok(f"{what} -> refused ({code})")
        return
    raise SystemExit(f"FAIL: {what} was allowed!")


SECRET = "URGENT: gas leak near pump 3, evacuate zone B"
PHOTO = b"\x89PNG\r\n" + os.urandom(1_500_000)          # > 1 MiB -> chunked
PASSWORDS = {"priya": "priya-pw-123", "bob": "bob-pw-4567", "carol": "carol-pw-89",
             "dave": "dave-pw-rival", "eve": "eve-pw-evil1"}

# ---------------------------------------------------------------------------
line("1) Accounts: employees + employers sign up (email, phone, password)")
priya = new_device(); priya.register("Priya (Acme)", "priya@acme.test", "+91 90000 00001",
                                     PASSWORDS["priya"], role="employer")
bob = new_device(); bob.register("Bob", "bob@mail.test", "+91 90000 00002", PASSWORDS["bob"])
carol = new_device(); carol.register("Carol", "carol@mail.test", "+91-90000-00003", PASSWORDS["carol"])
dave = new_device(); dave.register("Dave (Rival)", "dave@rival.test", "+44 7700 900004",
                                   PASSWORDS["dave"], role="employer")
eve = new_device(); eve.register("Eve", "eve@mail.test", "+1 555 0100 005", PASSWORDS["eve"])
ok("5 accounts; private keys made on-device, only encrypted backups uploaded")

denied(lambda: new_device().register("Eve2", "eve2@mail.test", "+91 90000 00002", "whatever-123"),
       "registering someone else's phone number")
if FAKE and "--auth-emulator" not in sys.argv:
    assert "eve2@mail.test" not in FAKE.accounts, "half-made account left behind"
    ok("no half-made Auth account left behind")

# ---------------------------------------------------------------------------
line("2) Employer creates an org + group, adds people by email and phone")
denied(lambda: bob.create_org("Bob's Fake Org"), "employee creating an org (client)")
denied(lambda: bob.fb.commit([bob.fb.w_set("orgs/o-bob", {
    "name": "x", "ownerUid": bob.uid, "admins": [bob.uid], "createdAt": SERVER_TIMESTAMP},
    exists=False)]), "employee creating an org (direct Firestore write)")

org_a = priya.create_org("Acme Builders")
gid = priya.create_group(org_a, "Site A Crew", ["bob@mail.test", "+91 90000 00003"])
names = sorted(m["displayName"] for m in priya.group_members(gid))
print("  members:", names)
assert names == ["Bob", "Carol", "Priya (Acme)"]
assert [g["name"] for g in bob.my_groups()] == ["Site A Crew"]
assert bob.my_groups()[0]["isAdmin"] is False and priya.my_groups()[0]["isAdmin"] is True
ok("Bob and Carol see the group; only Priya can manage it")

# ---------------------------------------------------------------------------
line("3) Encrypted chat (text + 1.5 MB photo) and incident reports")
priya.send_chat(gid, SECRET)
bob.send_chat(gid, "photo attached", media_bytes=PHOTO, media_name="leak.png")
msgs = carol.read_chat(gid)
print("  Carol decrypts:", [m["text"] for m in msgs])
assert msgs[0]["text"] == SECRET and msgs[0]["sender"] == "Priya (Acme)"
assert msgs[1]["media"]["bytes"] == PHOTO and msgs[1]["media"]["name"] == "leak.png"
ok("Carol read the exact message and the chunked photo")

res = carol.create_incident(gid, {
    "title": "Cracked beam", "reporter": "Carol", "assigned_to": "Bob",
    "target_date": "2026-11-20", "status": "Open",
    "description": "Hairline crack on level 3.", "updates": [],
    "created_at": "2026-11-07 10:00",
    "photos": [{"name": "beam.jpg", "b64": base64.b64encode(os.urandom(900_000)).decode()}],
})
inc = bob.read_incidents(gid)[0]
inc["updates"].append({"text": "Cordoned off", "timestamp": "2026-11-07 12:30"})
bob.update_incident(gid, res["id"], {k: v for k, v in inc.items() if not k.startswith("_")})
final = priya.read_incidents(gid)[0]
assert final["title"] == "Cracked beam" and len(final["updates"]) == 1
assert final["photos"][0]["b64"] == inc["photos"][0]["b64"]
ok("incident created by Carol, updated by Bob, read by Priya (photo intact)")
if FAKE:
    left = [p for p in FAKE.docs if "/chunks/0_" in p and res["id"] in p]
    assert not left, f"stale chunks left: {left}"
    ok("old ciphertext chunks cleaned up after the edit")

# ---------------------------------------------------------------------------
line("4) ORG ISOLATION — a rival employer gets nothing")
org_b = dave.create_org("Rival Corp")
gid_b = dave.create_group(org_b, "Rival Site", ["eve@mail.test"])
assert [g["name"] for g in dave.my_groups()] == ["Rival Site"]
ok("Dave's group list contains only his own org's group")
denied(lambda: dave.group(gid), "Dave reading Acme's group doc")
denied(lambda: dave.read_chat(gid), "Dave reading Acme's chat")
denied(lambda: dave.fb.query(f"groups/{gid}", "items"), "Dave listing Acme's items")
denied(lambda: dave.fb.get(f"groups/{gid}/keys/{priya.uid}_1"), "Dave reading Priya's sealed key")
denied(lambda: dave.fb.get(f"orgs/{org_a}"), "Dave reading Acme's org")
denied(lambda: dave.fb.commit([dave.fb.w_set(f"groups/{gid}", {
    "members": [priya.uid, bob.uid, carol.uid, dave.uid]}, exists=True, merge_fields=["members"])]),
    "Dave adding himself to Acme's group")
denied(lambda: dave.fb.commit([dave.fb.w_set("groups/g-evil", {
    "orgId": org_a, "orgName": "Acme Builders", "name": "trap", "createdBy": dave.uid,
    "members": [dave.uid, bob.uid], "keyVersion": 1, "createdAt": SERVER_TIMESTAMP},
    exists=False)]), "Dave creating a group inside Acme's org")
denied(lambda: dave.fb.commit([dave.fb.w_set(f"groups/{gid}/items/i-evil", {
    "kind": "chat", "sender": dave.uid, "keyVersion": 1, "nonce": "x", "body": b"x",
    "chunks": 0, "media": None, "rev": 0, "createdAt": SERVER_TIMESTAMP,
    "updatedAt": SERVER_TIMESTAMP}, exists=False)]), "Dave posting into Acme's chat")
denied(lambda: priya.read_chat(gid_b), "Priya reading Rival's chat (works both ways)")

line("4b) Employees can't manage groups or impersonate")
denied(lambda: bob.add_member(gid, "eve@mail.test"), "employee Bob adding Eve")
denied(lambda: bob.fb.commit([bob.fb.w_set(f"groups/{gid}/items/i-spoof", {
    "kind": "chat", "sender": priya.uid, "keyVersion": 1, "nonce": "x", "body": b"x",
    "chunks": 0, "media": None, "rev": 0, "createdAt": SERVER_TIMESTAMP,
    "updatedAt": SERVER_TIMESTAMP}, exists=False)]), "Bob posting as Priya")
denied(lambda: eve.fb.commit([eve.fb.w_set(f"lookup/{lookup_id('bob@mail.test')}",
                                           {"uid": eve.uid}, exists=False)]),
       "Eve claiming Bob's email in the directory")
denied(lambda: eve.fb.commit([eve.fb.w_set(f"lookup/{lookup_id('new.hire@acme.test')}",
                                           {"uid": eve.uid}, exists=False)]),
       "Eve pre-claiming a not-yet-registered email")
denied(lambda: eve.fb.query(None, "lookup"), "Eve browsing the user directory")
denied(lambda: eve.fb.get(f"users/{bob.uid}"), "Eve reading Bob's private profile")

# ---------------------------------------------------------------------------
line("5) Removing a member rotates the group key")
priya.remove_member(gid, carol.uid)
assert priya.group(gid)["keyVersion"] == 2
priya.send_chat(gid, "Carol has left; new key in use")
denied(lambda: carol.read_chat(gid), "removed Carol reading the chat")
assert bob.read_chat(gid)[-1]["text"] == "Carol has left; new key in use"
ok("Bob reads the post-rotation message; Carol is locked out")
denied(lambda: priya.fb.commit([priya.fb.w_set(f"groups/{gid}", {"members": [priya.uid]},
                                               exists=True, merge_fields=["members"])]),
       "removing a member WITHOUT rotating the key")

# ---------------------------------------------------------------------------
line("6) New phone: log in, key restored from encrypted backup")
bob_phone2 = new_device(); bob_phone2.login("BOB@mail.test", PASSWORDS["bob"])
assert bob_phone2.read_chat(gid)[0]["text"] == SECRET
ok("Bob's second device decrypts the full history")
denied(lambda: new_device().login("bob@mail.test", "wrong-password"), "login with wrong password")
bob_phone2.change_password(PASSWORDS["bob"], "bob-NEW-pw-999")
new_device().login("bob@mail.test", "bob-NEW-pw-999")
denied(lambda: new_device().login("bob@mail.test", PASSWORDS["bob"]), "login with OLD password")
ok("password change re-wraps the key backup")

# ---------------------------------------------------------------------------
line("7) The database holds no plaintext")
if FAKE:
    raw = FAKE.dump_bytes()
    raw += json.dumps(FAKE.accounts).encode()          # what Firebase Auth stores
else:
    raw = b""
    owner = {"Authorization": "Bearer owner"}
    base = f"http://{CFG.emulator_host}:8080/v1/{CFG.db_root}"

    def dump(path=""):
        global raw
        r = HTTP.post(f"{base}{'/' + path if path else ''}:listCollectionIds", headers=owner, json={})
        for coll in r.json().get("collectionIds", []):
            docs = HTTP.get(f"{base}/{path + '/' if path else ''}{coll}",
                            headers=owner, params={"pageSize": 1000}).json()
            for d in docs.get("documents", []):
                raw += json.dumps(d).encode()
                for v in d.get("fields", {}).values():
                    if "bytesValue" in v:
                        raw += base64.b64decode(v["bytesValue"])
                dump(d["name"].split("/documents/", 1)[1])
    dump()
for needle in [SECRET, "Cracked beam", "Hairline crack", "Cordoned off", "Carol has left",
               *PASSWORDS.values(), "bob-NEW-pw-999"]:
    assert needle.encode() not in raw, f"plaintext found: {needle}"
assert PHOTO[8:4000] not in raw
assert bob.private_key.encode() not in raw
ok("no messages, incident text, photos, passwords or private keys stored")

line("ALL CHECKS PASSED  ✔  " + ("(real Firebase emulators)" if EMULATOR else
                               "(real Auth emulator + offline Firestore)" if "--auth-emulator" in sys.argv
                               else "(offline fake)"))
