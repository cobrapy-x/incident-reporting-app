"""
Incident Reporting App  —  Firebase + end-to-end encrypted
==========================================================
Cross-platform (Android / iOS / desktop) app built with Flet.

Screens:
  1. Sign in / create account  (name, email, phone, password, employee|employer)
  2. Home                      (your groups; employers also manage orgs + groups)
  3. Group                     (tabs: encrypted Chat, Incidents, Members)
  4. Report incident           (encrypted; still exports a PDF with signature panel)

All messages, media and incident reports are encrypted on THIS device before
they are sent. Firebase only ever stores ciphertext. The heavy lifting lives
in client_api.py (Firebase + crypto) and e2e.py (encryption); this file is
just the screens.

Run it:
    pip install -r requirements.txt
    flet run main.py
"""

import io
import os
import json
import base64
import threading
from datetime import datetime

import flet as ft
from fpdf import FPDF

from client_api import Client
from firebase_rest import FirebaseConfig, friendly

# --- small local settings (only your email — keys are NOT stored on disk) ---
DATA_DIR = os.environ.get("FLET_APP_STORAGE_DATA") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "app_data")
os.makedirs(DATA_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
POLL_SECONDS = 15          # chat auto-refresh; each poll costs ~1 Firestore read


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            s = json.load(f)
        s.pop("private_key", None)          # left over from the Render version
        return s
    return {}


def save_settings(s):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)


def now_stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def shrink_image(data: bytes, max_side=1600, quality=80) -> bytes:
    """Make phone photos small before encrypting (Firestore free tier = 1 GiB).

    Uses Pillow if it's installed; otherwise sends the original bytes.
    """
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.thumbnail((max_side, max_side))
        out = io.BytesIO()
        img.convert("RGB").save(out, "JPEG", quality=quality, optimize=True)
        return out.getvalue() if out.tell() < len(data) else data
    except Exception:
        return data


# ---------------------------------------------------------------------------
# PDF report with signature panel (built after the incident is decrypted)
# ---------------------------------------------------------------------------
def make_pdf(incident, group_name, photo_paths=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Incident Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Group: {group_name}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    def field(label, value):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(45, 8, f"{label}:", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 8, str(value) if value else "-",
                       new_x="LMARGIN", new_y="NEXT")

    field("Title", incident.get("title"))
    field("Reported by", incident.get("reporter"))
    field("Reported on", incident.get("created_at"))
    field("Assigned to", incident.get("assigned_to"))
    field("Target date", incident.get("target_date"))
    field("Status", incident.get("status"))
    field("Description", incident.get("description"))
    field("Photo note", incident.get("photo_description"))

    for pp in (photo_paths or []):
        if pp and os.path.exists(pp):
            try:
                pdf.ln(2)
                pdf.image(pp, w=90)
            except Exception:
                pass

    updates = incident.get("updates", [])
    if updates:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Updates", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for u in updates:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 6, f"[{u['timestamp']}] {u['text']}",
                           new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Signatures", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)
    y = pdf.get_y()
    pdf.line(20, y, 90, y)
    pdf.line(120, y, 190, y)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_y(y + 1)
    pdf.set_x(20)
    pdf.cell(70, 6, "Reported by (sign & date)")
    pdf.set_x(120)
    pdf.cell(70, 6, "Rectified by (sign & date)")

    safe = "".join(c for c in incident.get("title", "report")
                   if c.isalnum() or c in " -_")[:40]
    out = os.path.join(DATA_DIR, f"report_{safe or 'incident'}.pdf")
    pdf.output(out)
    return out



# ---------------------------------------------------------------------------
# THE APP
# ---------------------------------------------------------------------------
def main(page: ft.Page):
    page.title = "Incident Reporting"
    page.scroll = ft.ScrollMode.AUTO
    page.padding = 16

    settings = load_settings()
    app = {"client": None, "group_id": None, "group_name": None,
           "is_admin": False, "screen": 0}

    try:
        config = FirebaseConfig.load()
    except Exception as ex:
        page.add(ft.Text("Firebase isn't configured yet", size=20, weight=ft.FontWeight.BOLD),
                 ft.Text(str(ex)))
        page.update()
        return

    def new_screen():
        """Clear the page; bumping the counter stops any old poller."""
        app["screen"] += 1
        page.controls.clear()
        # drop old file pickers (keep any open snackbar/dialog)
        page.overlay[:] = [o for o in page.overlay if not isinstance(o, ft.FilePicker)]
        return app["screen"]

    def toast(msg):
        page.open(ft.SnackBar(ft.Text(msg)))

    def show_error(e):
        toast(f"Error: {friendly(e)}")

    def busy(button, text="Working…"):
        """Disable a button while slow work (key derivation, network) runs."""
        old = button.text
        button.disabled, button.text = True, text
        page.update()

        def done():
            button.disabled, button.text = False, old
            page.update()
        return done

    def save_media(name, data):
        """Write a decrypted image to a 'downloads' folder and report where."""
        folder = os.path.join(DATA_DIR, "downloads")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name or "image")
        with open(path, "wb") as f:
            f.write(data)
        toast(f"Saved to {path}")
        return path

    def image_view(media, width=220, on_remove=None):
        """Show a decrypted image inline, with Save and optional Remove."""
        b64 = base64.b64encode(media["bytes"]).decode()
        row = [
            ft.Icon(ft.icons.PHOTO, size=13),
            ft.Text(media["name"] or "image", size=11),
            ft.TextButton("Save", icon=ft.icons.DOWNLOAD,
                          on_click=lambda e, m=media: save_media(m["name"], m["bytes"])),
        ]
        if on_remove is not None:
            row.append(ft.TextButton("Remove", icon=ft.icons.DELETE, on_click=on_remove))
        return ft.Column(spacing=4, controls=[
            ft.Image(src_base64=b64, width=width, fit=ft.ImageFit.CONTAIN,
                     border_radius=6,
                     error_content=ft.Text("Can't preview this image", size=11)),
            ft.Row(row),
        ])

    def read_photo(path):
        with open(path, "rb") as f:
            raw = f.read()
        small = shrink_image(raw)
        name = os.path.basename(path)
        if small is not raw:
            name = os.path.splitext(name)[0] + ".jpg"
        return name, small

    # =====================================================================
    # SCREEN 1 — Sign in / create account
    # =====================================================================
    def show_auth():
        new_screen()
        app["client"] = None

        # ---- sign in
        li_email = ft.TextField(label="Email", value=settings.get("email", ""),
                                keyboard_type=ft.KeyboardType.EMAIL)
        li_pw = ft.TextField(label="Password", password=True, can_reveal_password=True)
        li_btn = ft.ElevatedButton("Sign in", icon=ft.icons.LOGIN)

        def do_login(e):
            done = busy(li_btn, "Signing in…")
            try:
                c = Client(config)
                c.login(li_email.value, li_pw.value)
                settings["email"] = c.profile["email"]
                save_settings(settings)
                app["client"] = c
                show_home()
            except Exception as ex:
                done()
                show_error(ex)
        li_btn.on_click = do_login

        # ---- create account
        su_name = ft.TextField(label="Full name")
        su_email = ft.TextField(label="Email", keyboard_type=ft.KeyboardType.EMAIL)
        su_phone = ft.TextField(label="Phone (with country code, e.g. +91 98765 43210)",
                                keyboard_type=ft.KeyboardType.PHONE)
        su_pw = ft.TextField(label="Password (min 8 characters)", password=True,
                             can_reveal_password=True)
        su_pw2 = ft.TextField(label="Confirm password", password=True)
        su_role = ft.RadioGroup(value="employee", content=ft.Column([
            ft.Radio(value="employee", label="Employee — I'll be added to my team's groups"),
            ft.Radio(value="employer", label="Employer — I'll create an organisation and groups"),
        ]))
        su_btn = ft.ElevatedButton("Create account", icon=ft.icons.PERSON_ADD)

        def do_register(e):
            if su_pw.value != su_pw2.value:
                toast("Passwords don't match.")
                return
            done = busy(su_btn, "Creating keys…")
            try:
                c = Client(config)
                c.register(su_name.value, su_email.value, su_phone.value,
                           su_pw.value, role=su_role.value)
                settings["email"] = c.profile["email"]
                save_settings(settings)
                app["client"] = c
                toast("Account created. We sent a verification email.")
                show_home()
            except Exception as ex:
                done()
                show_error(ex)
        su_btn.on_click = do_register

        page.add(
            ft.Text("Incident Reporting", size=26, weight=ft.FontWeight.BOLD),
            ft.Row([ft.Icon(ft.icons.LOCK, size=16),
                    ft.Text("End-to-end encrypted", size=13)]),
            ft.Tabs(selected_index=0 if settings.get("email") else 1, animation_duration=150, tabs=[
                ft.Tab(text="Sign in", content=ft.Container(padding=10, content=ft.Column([
                    li_email, li_pw, li_btn,
                    ft.Text("Works on any device — your encrypted key backup is "
                            "unlocked with your password.", size=11, italic=True),
                ]))),
                ft.Tab(text="Create account", content=ft.Container(padding=10, content=ft.Column([
                    su_name, su_email, su_phone, su_pw, su_pw2,
                    ft.Text("Account type", weight=ft.FontWeight.BOLD), su_role, su_btn,
                    ft.Text("Your password never leaves this device. If you forget it, "
                            "your old messages can't be recovered.", size=11, italic=True),
                ]))),
            ]),
        )
        page.update()

    # =====================================================================
    # SCREEN 2 — Home: groups (+ org management for employers)
    # =====================================================================
    def show_home():
        new_screen()
        c = app["client"]

        def change_password_dialog(e):
            old = ft.TextField(label="Current password", password=True)
            new = ft.TextField(label="New password (min 8)", password=True)
            new2 = ft.TextField(label="Confirm new password", password=True)

            def save(ev):
                if new.value != new2.value:
                    toast("New passwords don't match.")
                    return
                try:
                    c.change_password(old.value, new.value)
                    page.close(dlg)
                    toast("Password changed.")
                except Exception as ex:
                    show_error(ex)
            dlg = ft.AlertDialog(title=ft.Text("Change password"),
                                 content=ft.Column([old, new, new2], tight=True),
                                 actions=[ft.TextButton("Cancel", on_click=lambda ev: page.close(dlg)),
                                          ft.TextButton("Save", on_click=save)])
            page.open(dlg)

        def fingerprint_dialog(e):
            dlg = ft.AlertDialog(
                title=ft.Text("Your safety number"),
                content=ft.Text(f"{c.my_fingerprint()}\n\nCompare this in person with what "
                                "others see next to your name in a group's Members tab. "
                                "If it matches, nobody is intercepting your messages."),
                actions=[ft.TextButton("OK", on_click=lambda ev: page.close(dlg))])
            page.open(dlg)

        header = ft.Row(alignment=ft.MainAxisAlignment.SPACE_BETWEEN, controls=[
            ft.Text(f"{c.username} · {'Employer' if c.is_employer else 'Employee'}", size=13),
            ft.PopupMenuButton(items=[
                ft.PopupMenuItem(text="My safety number", icon=ft.icons.FINGERPRINT,
                                 on_click=fingerprint_dialog),
                ft.PopupMenuItem(text="Change password", icon=ft.icons.PASSWORD,
                                 on_click=change_password_dialog),
                ft.PopupMenuItem(text="Refresh", icon=ft.icons.REFRESH,
                                 on_click=lambda e: show_home()),
                ft.PopupMenuItem(text="Sign out", icon=ft.icons.LOGOUT,
                                 on_click=lambda e: show_auth()),
            ]),
        ])

        try:
            groups = c.my_groups()
            orgs = c.my_orgs()
        except Exception as ex:
            show_error(ex)
            groups, orgs = [], []

        employer_panel = []
        if c.is_employer:
            org_name = ft.TextField(label="New organisation name", expand=True)

            def add_org(e):
                if not org_name.value.strip():
                    toast("Type an organisation name.")
                    return
                try:
                    c.create_org(org_name.value)
                    show_home()
                except Exception as ex:
                    show_error(ex)

            grp_org = ft.Dropdown(label="Organisation",
                                  options=[ft.dropdown.Option(o["id"], o["name"]) for o in orgs],
                                  value=orgs[0]["id"] if orgs else None)
            grp_name = ft.TextField(label="New group name")
            grp_members = ft.TextField(label="Add people (emails or phones, comma-separated)",
                                       multiline=True)
            grp_btn = ft.ElevatedButton("Create group", icon=ft.icons.GROUP_ADD)

            def add_group(e):
                if not grp_org.value:
                    toast("Create an organisation first.")
                    return
                if not grp_name.value.strip():
                    toast("Type a group name.")
                    return
                people = [m.strip() for m in grp_members.value.split(",") if m.strip()]
                done = busy(grp_btn, "Encrypting keys…")
                try:
                    c.create_group(grp_org.value, grp_name.value, people)
                    show_home()
                except Exception as ex:
                    done()
                    show_error(ex)
            grp_btn.on_click = add_group

            employer_panel = [
                ft.Text("Your organisations", size=20, weight=ft.FontWeight.BOLD),
                ft.Text(", ".join(o["name"] for o in orgs) or "None yet.", size=13),
                ft.Row([org_name, ft.ElevatedButton("Create", icon=ft.icons.BUSINESS,
                                                    on_click=add_org)]),
                ft.Container(height=8),
                ft.Text("New group", size=16, weight=ft.FontWeight.BOLD),
                grp_org, grp_name, grp_members, grp_btn,
                ft.Divider(),
            ]

        cards = []
        for g in groups:
            cards.append(ft.Card(content=ft.Container(padding=12, content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Column(spacing=2, expand=True, controls=[
                        ft.Text(g["name"], size=16, weight=ft.FontWeight.BOLD),
                        ft.Text(g["orgName"], size=12, color=ft.colors.SECONDARY),
                        ft.Row([ft.Icon(ft.icons.LOCK, size=12),
                                ft.Text(f"{g['members']}/50 members · encrypted"
                                        + (" · you manage this" if g["isAdmin"] else ""),
                                        size=12)]),
                    ]),
                    ft.ElevatedButton("Open", on_click=lambda e, g=g: open_group(g)),
                ]))))

        empty = ("No groups yet. Create one above." if c.is_employer else
                 "No groups yet. Ask your employer to add you using your email or phone number.")
        page.add(
            header,
            *employer_panel,
            ft.Text("Your groups", size=22, weight=ft.FontWeight.BOLD),
            *(cards or [ft.Text(empty, italic=True)]),
        )
        page.update()

    def open_group(g):
        app["group_id"], app["group_name"] = g["id"], g["name"]
        app["is_admin"] = g["isAdmin"]
        show_group()

    # =====================================================================
    # SCREEN 3 — One group: Chat + Incidents + Members
    # =====================================================================
    def show_group(tab=0):
        screen = new_screen()
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]

        # ---- Chat tab ----
        chat_input = ft.TextField(label="Message", expand=True)
        chat_photo = {"path": None}
        chat_photo_label = ft.Text("", size=11, italic=True)

        def on_chat_photo(e):
            if e.files:
                chat_photo["path"] = e.files[0].path
                chat_photo_label.value = "photo attached"
                page.update()

        chat_picker = ft.FilePicker(on_result=on_chat_photo)
        page.overlay.append(chat_picker)
        chat_list = ft.Column(spacing=8)
        seen = {"n": -1}

        def render_chat(msgs):
            chat_list.controls.clear()
            for m in msgs:
                mine = m["senderUid"] == c.uid
                rows = [ft.Text(f"{'You' if mine else m['sender']} · {m['at']}", size=11,
                                weight=ft.FontWeight.BOLD, color=ft.colors.SECONDARY),
                        ft.Text(m["text"], size=13, italic=m["locked"], selectable=True)]
                if m["media"]:
                    rows.append(image_view(m["media"]))
                chat_list.controls.append(ft.Container(
                    bgcolor=ft.colors.PRIMARY_CONTAINER if mine else ft.colors.SURFACE_CONTAINER_HIGHEST,
                    border_radius=8, padding=8, margin=ft.margin.only(left=40 if mine else 0,
                                                                      right=0 if mine else 40),
                    content=ft.Column(rows, spacing=2)))
            if not msgs:
                chat_list.controls.append(ft.Text("No messages yet.", italic=True))

        def refresh_chat(quiet=False):
            try:
                msgs = c.read_chat(gid)
                if quiet and len(msgs) == seen["n"]:
                    return
                seen["n"] = len(msgs)
                render_chat(msgs)
                page.update()
            except PermissionError:
                if not quiet:
                    toast("You are no longer a member of this group.")
            except Exception as ex:
                if not quiet:
                    show_error(ex)

        send_btn = ft.IconButton(ft.icons.SEND)

        def send_chat(e):
            if not chat_input.value.strip() and not chat_photo["path"]:
                return
            media_bytes = media_name = None
            try:
                if chat_photo["path"]:
                    media_name, media_bytes = read_photo(chat_photo["path"])
                send_btn.disabled = True
                page.update()
                c.send_chat(gid, chat_input.value.strip(), media_bytes, media_name)
                chat_input.value = ""
                chat_photo["path"] = None
                chat_photo_label.value = ""
                refresh_chat()
            except Exception as ex:
                show_error(ex)
            finally:
                send_btn.disabled = False
                page.update()
        send_btn.on_click = send_chat
        chat_input.on_submit = send_chat

        chat_tab = ft.Column([
            ft.Row([ft.TextButton("Refresh", icon=ft.icons.REFRESH,
                                  on_click=lambda e: refresh_chat()),
                    ft.Text(f"auto-refreshes every {POLL_SECONDS}s", size=11, italic=True)]),
            chat_list,
            ft.Row([chat_input,
                    ft.IconButton(ft.icons.CAMERA_ALT, on_click=lambda e: chat_picker.pick_files(
                        file_type=ft.FilePickerFileType.IMAGE)),
                    send_btn]),
            chat_photo_label,
        ])

        # ---- Incidents tab ----
        incident_list = ft.Column(spacing=8)

        def refresh_incidents():
            incident_list.controls.clear()
            try:
                incs = c.read_incidents(gid)
                for inc in incs:
                    incident_list.controls.append(ft.Card(content=ft.Container(
                        padding=12, content=ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                ft.Column(spacing=2, expand=True, controls=[
                                    ft.Text(inc.get("title", "-"), size=15,
                                            weight=ft.FontWeight.BOLD),
                                    ft.Text(f"Assigned: {inc.get('assigned_to') or '-'}"
                                            f"  ·  Target: {inc.get('target_date') or '-'}",
                                            size=12),
                                    ft.Text(f"Status: {inc.get('status', 'Open')}", size=12),
                                ]),
                                ft.ElevatedButton("View",
                                                  on_click=lambda e, i=inc: open_incident(i)),
                            ]))))
                if not incs:
                    incident_list.controls.append(ft.Text("No incidents reported.", italic=True))
            except Exception as ex:
                show_error(ex)
            page.update()

        incidents_tab = ft.Column([
            ft.Row([ft.ElevatedButton("Report incident", icon=ft.icons.ADD,
                                      on_click=lambda e: show_new_incident()),
                    ft.TextButton("Refresh", icon=ft.icons.REFRESH,
                                  on_click=lambda e: refresh_incidents())]),
            incident_list,
        ])

        # ---- Members tab ----
        member_list = ft.Column(spacing=4)
        add_field = ft.TextField(label="Email or phone of person to add", expand=True)

        def refresh_members():
            member_list.controls.clear()
            try:
                for m in c.group_members(gid):
                    trailing = []
                    if app["is_admin"] and not m["isMe"]:
                        trailing.append(ft.IconButton(
                            ft.icons.PERSON_REMOVE, tooltip="Remove (rotates the key)",
                            on_click=lambda e, m=m: confirm_remove(m)))
                    member_list.controls.append(ft.ListTile(
                        leading=ft.Icon(ft.icons.PERSON),
                        title=ft.Text(m["displayName"] + (" (you)" if m["isMe"] else "")),
                        subtitle=ft.Text(f"Safety number: {m['fingerprint']}", size=11),
                        trailing=trailing[0] if trailing else None))
            except Exception as ex:
                show_error(ex)
            page.update()

        def find_and_add(e):
            if not add_field.value.strip():
                return
            try:
                who = c.find_user(add_field.value)
            except Exception as ex:
                show_error(ex)
                return

            def really_add(ev):
                page.close(dlg)
                try:
                    c.add_member_uid(gid, who["uid"])
                    add_field.value = ""
                    toast(f"Added {who['displayName']}.")
                    refresh_members()
                except Exception as ex:
                    show_error(ex)
            dlg = ft.AlertDialog(
                title=ft.Text(f"Add {who['displayName']}?"),
                content=ft.Text(f"Found: {who['displayName']}\nSafety number: {who['fingerprint']}"
                                "\n\nThey'll be able to read this group's messages sent "
                                "since the last time someone was removed."),
                actions=[ft.TextButton("Cancel", on_click=lambda ev: page.close(dlg)),
                         ft.TextButton("Add", on_click=really_add)])
            page.open(dlg)

        def confirm_remove(m):
            def really_remove(ev):
                page.close(dlg)
                try:
                    c.remove_member(gid, m["uid"])
                    toast(f"Removed {m['displayName']}; group key rotated.")
                    refresh_members()
                except Exception as ex:
                    show_error(ex)
            dlg = ft.AlertDialog(
                title=ft.Text(f"Remove {m['displayName']}?"),
                content=ft.Text("A new encryption key will be made for everyone else, so they "
                                "can't read anything sent after this."),
                actions=[ft.TextButton("Cancel", on_click=lambda ev: page.close(dlg)),
                         ft.TextButton("Remove", on_click=really_remove)])
            page.open(dlg)

        members_tab = ft.Column([
            *([ft.Row([add_field, ft.ElevatedButton("Add", icon=ft.icons.PERSON_ADD,
                                                    on_click=find_and_add)])]
              if app["is_admin"] else
              [ft.Text("Only your employer can add or remove people.", size=12, italic=True)]),
            member_list,
            ft.Text("Compare safety numbers in person to be sure nobody is in the middle.",
                    size=11, italic=True),
        ])

        page.add(
            ft.Row([ft.TextButton("← Groups", on_click=lambda e: show_home())]),
            ft.Row([ft.Icon(ft.icons.LOCK, size=16),
                    ft.Text(gname, size=22, weight=ft.FontWeight.BOLD)]),
            ft.Tabs(selected_index=tab, tabs=[
                ft.Tab(text="Chat", content=ft.Container(chat_tab, padding=10)),
                ft.Tab(text="Incidents", content=ft.Container(incidents_tab, padding=10)),
                ft.Tab(text="Members", content=ft.Container(members_tab, padding=10)),
            ]),
        )
        page.update()
        refresh_chat()
        refresh_incidents()
        refresh_members()

        def poll():
            # quiet background refresh while this screen is open
            ev = threading.Event()
            while not ev.wait(POLL_SECONDS):
                if app["screen"] != screen or app["client"] is not c:
                    return
                refresh_chat(quiet=True)
        threading.Thread(target=poll, daemon=True).start()

    # =====================================================================
    # SCREEN 4 — New incident
    # =====================================================================
    def show_new_incident():
        new_screen()
        c = app["client"]
        gid = app["group_id"]
        photos = []  # list of {"name", "b64"} — ride inside the encrypted incident
        photo_list = ft.Column(spacing=4)

        def render_photo_list():
            photo_list.controls.clear()
            if not photos:
                photo_list.controls.append(ft.Text("No photos yet", size=11, italic=True))
            for idx, p in enumerate(photos):
                photo_list.controls.append(ft.Row([
                    ft.Icon(ft.icons.PHOTO, size=14),
                    ft.Text(p["name"], size=11, expand=True),
                    ft.IconButton(ft.icons.CLOSE, icon_size=16, tooltip="Remove",
                                  on_click=lambda e, i=idx: remove_photo(i)),
                ]))
            page.update()

        def remove_photo(i):
            if 0 <= i < len(photos):
                photos.pop(i)
                render_photo_list()

        def on_photos(e):
            if not e.files:
                return
            for picked in e.files:
                try:
                    name, data = read_photo(picked.path)
                    photos.append({"name": name, "b64": base64.b64encode(data).decode()})
                except Exception as ex:
                    show_error(ex)
            render_photo_list()

        picker = ft.FilePicker(on_result=on_photos)
        page.overlay.append(picker)

        try:
            member_names = [m["displayName"] for m in c.group_members(gid)]
        except Exception:
            member_names = []

        title = ft.TextField(label="Problem title")
        desc = ft.TextField(label="Description", multiline=True, min_lines=3)
        photo_desc = ft.TextField(label="Photo description")
        reporter = ft.TextField(label="Your name (reporter)", value=c.username)
        assignee = ft.Dropdown(label="Assign to",
                               options=[ft.dropdown.Option(n) for n in member_names])
        target = ft.TextField(label="Target date (YYYY-MM-DD)")
        save_btn = ft.ElevatedButton("Save incident", icon=ft.icons.SAVE)

        def save(e):
            if not title.value.strip():
                toast("Give the problem a title.")
                return
            incident = {
                "title": title.value.strip(),
                "description": desc.value.strip(),
                "photo_description": photo_desc.value.strip(),
                "reporter": reporter.value.strip(),
                "assigned_to": assignee.value or "",
                "target_date": target.value.strip(),
                "status": "Open",
                "created_at": now_stamp(),
                "updates": [],
                "photos": photos,
            }
            done = busy(save_btn, "Encrypting…")
            try:
                c.create_incident(gid, incident)
                toast("Incident saved (encrypted).")
                show_group(tab=1)
            except Exception as ex:
                done()
                show_error(ex)
        save_btn.on_click = save

        page.add(
            ft.Row([ft.TextButton("← Back", on_click=lambda e: show_group(tab=1))]),
            ft.Text("Report an incident", size=22, weight=ft.FontWeight.BOLD),
            title, desc,
            ft.ElevatedButton("Attach photos", icon=ft.icons.PHOTO_CAMERA,
                              on_click=lambda e: picker.pick_files(
                                  allow_multiple=True, file_type=ft.FilePickerFileType.IMAGE)),
            photo_list,
            photo_desc, reporter, assignee, target,
            save_btn,
        )
        page.update()
        render_photo_list()

    # =====================================================================
    # SCREEN 5 — Incident detail: updates + PDF export
    # =====================================================================
    def open_incident(inc):
        new_screen()
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]
        update_text = ft.TextField(label="Add an update", expand=True)

        def save_and_reload():
            c.update_incident(gid, inc["_id"], _clean(inc))
            open_incident(inc)

        def add_update(e):
            if not update_text.value.strip():
                return
            inc.setdefault("updates", []).append(
                {"text": update_text.value.strip(), "timestamp": now_stamp(),
                 "by": c.username})
            try:
                save_and_reload()
            except Exception as ex:
                show_error(ex)

        def toggle_status(e):
            inc["status"] = "Closed" if inc.get("status", "Open") == "Open" else "Open"
            try:
                save_and_reload()
            except Exception as ex:
                show_error(ex)

        def export_pdf(e):
            photo_paths = []
            for i, p in enumerate(inc.get("photos", [])):
                fp = os.path.join(DATA_DIR, f"_pdf_{i}_{p['name']}")
                with open(fp, "wb") as f:
                    f.write(base64.b64decode(p["b64"]))
                photo_paths.append(fp)
            path = make_pdf(inc, gname, photo_paths)
            for fp in photo_paths:          # don't leave decrypted photos lying around
                try:
                    os.remove(fp)
                except OSError:
                    pass
            toast(f"PDF saved: {path}")

        updates = [ft.Text(f"[{u['timestamp']}] {u.get('by', '') + ': ' if u.get('by') else ''}"
                           f"{u['text']}", size=12)
                   for u in inc.get("updates", [])]

        def make_remove(idx):
            def _rm(e):
                try:
                    inc.get("photos", []).pop(idx)
                    save_and_reload()
                except Exception as ex:
                    show_error(ex)
            return _rm

        photo_controls = [
            image_view({"name": p["name"], "bytes": base64.b64decode(p["b64"])},
                       on_remove=make_remove(i))
            for i, p in enumerate(inc.get("photos", []))
        ]

        page.add(
            ft.Row([ft.TextButton("← Back", on_click=lambda e: show_group(tab=1))]),
            ft.Text(inc.get("title", "-"), size=22, weight=ft.FontWeight.BOLD),
            ft.Text(f"Reported by {inc.get('reporter') or '-'} on {inc.get('created_at')}", size=12),
            ft.Text(f"Assigned to: {inc.get('assigned_to') or '-'}", size=12),
            ft.Text(f"Target date: {inc.get('target_date') or '-'}", size=12),
            ft.Text(f"Status: {inc.get('status', 'Open')}", size=12, weight=ft.FontWeight.BOLD),
            ft.Divider(),
            ft.Text("Description", weight=ft.FontWeight.BOLD),
            ft.Text(inc.get("description") or "-", selectable=True),
            ft.Text(f"Photo note: {inc.get('photo_description') or '-'}", size=12, italic=True),
            *photo_controls,
            ft.Divider(),
            ft.Text("Updates", weight=ft.FontWeight.BOLD),
            *(updates or [ft.Text("No updates yet.", italic=True)]),
            ft.Row([update_text, ft.ElevatedButton("Add", on_click=add_update)]),
            ft.Divider(),
            ft.Row(wrap=True, controls=[
                ft.ElevatedButton("Toggle Open/Closed", on_click=toggle_status),
                ft.ElevatedButton("Export PDF", icon=ft.icons.PICTURE_AS_PDF, on_click=export_pdf)]),
        )
        page.update()

    def _clean(inc):
        """Strip the local-only helper fields before saving back."""
        return {k: v for k, v in inc.items() if not k.startswith("_")}

    # Start on the sign-in screen.
    show_auth()


if __name__ == "__main__":
    ft.app(target=main)
