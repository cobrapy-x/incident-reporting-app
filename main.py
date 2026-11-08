"""
Facilis Relatio  —  incident reporting, Firebase + end-to-end encrypted
=======================================================================
Cross-platform (Android / iOS / desktop) app built with Flet 1.x.

Screens:
  1. Sign in / create account  (name, email, phone, password, employee|employer)
  2. Home                      (your groups; employers also manage orgs + groups)
  3. Group                     (tabs: encrypted Chat, Incidents, Members)
  4. Report incident           (encrypted; still exports a PDF with signature panel)

All messages, media and incident reports are encrypted on THIS device before
they are sent. Firebase only ever stores ciphertext. The heavy lifting lives
in client_api.py (Firebase + crypto) and e2e.py (encryption); this file is
just the screens.

Run it on your computer:
    pip install -r requirements.txt
    flet run main.py
Build the phone apps: see BUILD_MOBILE.md
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
        from PIL import Image, ImageOps
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(data)))   # keep phone photos upright
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
APP_NAME = "Facilis Relatio"
BRAND_BLUE = "#0D47A1"
BRAND_AMBER = "#FFB300"


def main(page: ft.Page):
    page.title = APP_NAME
    page.padding = 0
    page.theme = ft.Theme(color_scheme_seed=BRAND_BLUE)
    page.dark_theme = ft.Theme(color_scheme_seed=BRAND_BLUE)

    settings = load_settings()
    app = {"client": None, "group_id": None, "group_name": None,
           "is_admin": False, "screen": 0}
    is_mobile = page.platform in (ft.PagePlatform.ANDROID, ft.PagePlatform.IOS)

    # one file picker for the whole app (it's a page "service")
    picker = ft.FilePicker()

    # ---------------------------------------------------------------- helpers
    def show(*controls, scroll=True):
        """Replace the screen. Content sits inside the phone's safe area
        (clear of the notch / status bar / home indicator)."""
        app["screen"] += 1
        page.controls.clear()
        page.add(ft.SafeArea(expand=True, minimum_padding=ft.Padding.all(16), content=ft.Column(
            list(controls), expand=True, spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,     # full-width fields
            scroll=ft.ScrollMode.AUTO if scroll else None)))
        page.update()
        return app["screen"]

    def toast(msg):
        page.show_dialog(ft.SnackBar(content=ft.Text(msg)))

    def show_error(e):
        toast(f"Error: {friendly(e)}")

    def close_dialog(e=None):
        page.pop_dialog()

    def busy(button, text="Working…"):
        """Disable a button while slow work (key derivation, network) runs."""
        old = button.content
        button.disabled, button.content = True, text
        page.update()

        def done():
            button.disabled, button.content = False, old
            page.update()
        return done

    async def deliver_file(name, data, mime):
        """Phones: open the share sheet (save to Files, WhatsApp, email…).
        Desktop: save into the app's downloads folder."""
        if is_mobile:
            await ft.Share().share_files([ft.ShareFile(data=data, name=name, mime_type=mime)])
            return
        folder = os.path.join(DATA_DIR, "downloads")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name or "file")
        with open(path, "wb") as f:
            f.write(data)
        toast(f"Saved to {path}")

    def image_view(media, width=220, on_remove=None):
        """Show a decrypted image inline, with Save/Share and optional Remove."""
        async def save(e, m=media):
            await deliver_file(m["name"] or "image.jpg", m["bytes"], "image/jpeg")
        row = [ft.Icon(ft.Icons.PHOTO, size=13),
               ft.Text(media["name"] or "image", size=11, expand=True),
               ft.TextButton("Share" if is_mobile else "Save",
                             icon=ft.Icons.SHARE if is_mobile else ft.Icons.DOWNLOAD,
                             on_click=save)]
        if on_remove is not None:
            row.append(ft.TextButton("Remove", icon=ft.Icons.DELETE, on_click=on_remove))
        return ft.Column(spacing=4, controls=[
            ft.Image(src=media["bytes"], width=width, fit=ft.BoxFit.CONTAIN,
                     border_radius=6,
                     error_content=ft.Text("Can't preview this image", size=11)),
            ft.Row(row),
        ])

    async def pick_photos(multiple=False):
        """Pick photo(s) → [(name, jpeg_bytes)], shrunk before encryption."""
        files = await picker.pick_files(file_type=ft.FilePickerFileType.IMAGE,
                                        allow_multiple=multiple, with_data=True)
        out = []
        for f in files or []:
            data = f.bytes
            if data is None and f.path:
                with open(f.path, "rb") as fh:
                    data = fh.read()
            if data is None:
                continue
            small = shrink_image(data)
            name = f.name or "photo.jpg"
            if small is not data:
                name = os.path.splitext(name)[0] + ".jpg"
            out.append((name, small))
        return out

    def logo(size=96):
        return ft.Image(src="icon.png", width=size, height=size, border_radius=size // 5,
                        error_content=ft.Icon(ft.Icons.ENGINEERING, size=size // 2))

    # =====================================================================
    # SCREEN 1 — Sign in / create account
    # =====================================================================
    def show_auth(tab=None):
        app["client"] = None
        if tab is None:
            tab = 0 if settings.get("email") else 1

        # ---- sign in
        li_email = ft.TextField(label="Email", value=settings.get("email", ""),
                                keyboard_type=ft.KeyboardType.EMAIL, autocorrect=False)
        li_pw = ft.TextField(label="Password", password=True, can_reveal_password=True)
        li_btn = ft.FilledButton("Sign in", icon=ft.Icons.LOGIN)

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
        li_pw.on_submit = do_login

        # ---- create account
        su_name = ft.TextField(label="Full name", capitalization=ft.TextCapitalization.WORDS)
        su_email = ft.TextField(label="Email", keyboard_type=ft.KeyboardType.EMAIL,
                                autocorrect=False)
        su_phone = ft.TextField(label="Phone (with country code)", hint_text="+91 98765 43210",
                                keyboard_type=ft.KeyboardType.PHONE)
        su_pw = ft.TextField(label="Password (min 8 characters)", password=True,
                             can_reveal_password=True)
        su_pw2 = ft.TextField(label="Confirm password", password=True)
        su_role = ft.RadioGroup(value="employee", content=ft.Column([
            ft.Radio(value="employee", label="Employee — I'll be added to my team's groups"),
            ft.Radio(value="employer", label="Employer — I'll create an organisation and groups"),
        ]))
        su_btn = ft.FilledButton("Create account", icon=ft.Icons.PERSON_ADD)

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
                show_home()
                toast("Account created. We sent a verification email.")
            except Exception as ex:
                done()
                show_error(ex)
        su_btn.on_click = do_register

        sign_in = ft.Column(scroll=ft.ScrollMode.AUTO, spacing=12,
                            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, controls=[
            ft.Container(height=4), li_email, li_pw, li_btn,
            ft.Text("Works on any device — your encrypted key backup is "
                    "unlocked with your password.", size=11, italic=True),
        ])
        sign_up = ft.Column(scroll=ft.ScrollMode.AUTO, spacing=12,
                            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, controls=[
            ft.Container(height=4), su_name, su_email, su_phone, su_pw, su_pw2,
            ft.Text("Account type", weight=ft.FontWeight.BOLD), su_role, su_btn,
            ft.Text("Your password never leaves this device. If you forget it, "
                    "your old messages can't be recovered.", size=11, italic=True),
        ])
        show(
            ft.Row([logo(64), ft.Column(spacing=2, controls=[
                ft.Text(APP_NAME, size=24, weight=ft.FontWeight.BOLD),
                ft.Row([ft.Icon(ft.Icons.LOCK, size=14),
                        ft.Text("End-to-end encrypted", size=12)]),
            ])]),
            ft.Tabs(length=2, selected_index=tab, expand=True, content=ft.Column(expand=True, controls=[
                ft.TabBar(tabs=[ft.Tab(label="Sign in"), ft.Tab(label="Create account")]),
                ft.TabBarView(expand=True, controls=[sign_in, sign_up]),
            ])),
            scroll=False,
        )

    # =====================================================================
    # SCREEN 2 — Home: groups (+ org management for employers)
    # =====================================================================
    def show_home():
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
                    close_dialog()
                    toast("Password changed.")
                except Exception as ex:
                    show_error(ex)
            page.show_dialog(ft.AlertDialog(
                title=ft.Text("Change password"),
                content=ft.Column([old, new, new2], tight=True),
                actions=[ft.TextButton("Cancel", on_click=close_dialog),
                         ft.TextButton("Save", on_click=save)]))

        def fingerprint_dialog(e):
            page.show_dialog(ft.AlertDialog(
                title=ft.Text("Your safety number"),
                content=ft.Text(f"{c.my_fingerprint()}\n\nCompare this in person with what "
                                "others see next to your name in a group's Members tab. "
                                "If it matches, nobody is intercepting your messages."),
                actions=[ft.TextButton("OK", on_click=close_dialog)]))

        header = ft.Row(alignment=ft.MainAxisAlignment.SPACE_BETWEEN, controls=[
            ft.Row(expand=True, controls=[logo(36), ft.Column(spacing=0, expand=True, controls=[
                ft.Text(c.username, size=15, weight=ft.FontWeight.BOLD),
                ft.Text("Employer" if c.is_employer else "Employee", size=12)])]),
            ft.PopupMenuButton(items=[
                ft.PopupMenuItem("My safety number", icon=ft.Icons.FINGERPRINT,
                                 on_click=fingerprint_dialog),
                ft.PopupMenuItem("Change password", icon=ft.Icons.PASSWORD,
                                 on_click=change_password_dialog),
                ft.PopupMenuItem("Refresh", icon=ft.Icons.REFRESH,
                                 on_click=lambda e: show_home()),
                ft.PopupMenuItem("Sign out", icon=ft.Icons.LOGOUT,
                                 on_click=lambda e: show_auth(tab=0)),
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

            grp_org = ft.Dropdown(label="Organisation", expand=True,
                                  options=[ft.DropdownOption(key=o["id"], text=o["name"]) for o in orgs],
                                  value=orgs[0]["id"] if orgs else None)
            grp_name = ft.TextField(label="New group name")
            grp_members = ft.TextField(label="Add people (optional)", multiline=True,
                                       hint_text="emails or phones, separated by commas")
            grp_btn = ft.FilledButton("Create group", icon=ft.Icons.GROUP_ADD)

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
                ft.Text("Your organisations", size=18, weight=ft.FontWeight.BOLD),
                ft.Text(", ".join(o["name"] for o in orgs) or "None yet.", size=13),
                ft.Row([org_name, ft.IconButton(ft.Icons.ADD_BUSINESS, tooltip="Create organisation",
                                                on_click=add_org)]),
                ft.Text("New group", size=16, weight=ft.FontWeight.BOLD),
                ft.Row([grp_org]), grp_name, grp_members, grp_btn,
            ]

        cards = []
        for g in groups:
            cards.append(ft.Card(content=ft.Container(
                padding=12, on_click=lambda e, g=g: open_group(g), content=ft.Row(controls=[
                    ft.Column(spacing=2, expand=True, controls=[
                        ft.Text(g["name"], size=16, weight=ft.FontWeight.BOLD),
                        ft.Text(g["orgName"], size=12, color=ft.Colors.SECONDARY),
                        ft.Row([ft.Icon(ft.Icons.LOCK, size=12),
                                ft.Text(f"{g['members']}/50 members · encrypted"
                                        + (" · you manage this" if g["isAdmin"] else ""),
                                        size=12)]),
                    ]),
                    ft.Button("Open", on_click=lambda e, g=g: open_group(g)),
                ]))))

        empty = ("No groups yet. Create one above." if c.is_employer else
                 "No groups yet. Ask your employer to add you using your email or phone number.")
        show(
            header,
            ft.Divider(),
            ft.Text("Your groups", size=20, weight=ft.FontWeight.BOLD),
            *(cards or [ft.Text(empty, italic=True)]),
            *([ft.Divider()] + employer_panel if employer_panel else []),
        )

    def open_group(g):
        app["group_id"], app["group_name"] = g["id"], g["name"]
        app["is_admin"] = g["isAdmin"]
        show_group()

    # =====================================================================
    # SCREEN 3 — One group: Chat + Incidents + Members
    # =====================================================================
    def show_group(tab=0):
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]

        # ---- Chat tab ----
        chat_input = ft.TextField(hint_text="Message", expand=True, multiline=True,
                                  min_lines=1, max_lines=4, shift_enter=True)
        chat_photo = {"name": None, "bytes": None}
        chat_photo_label = ft.Text("", size=11, italic=True)
        chat_list = ft.ListView(expand=True, spacing=8, auto_scroll=True)
        seen = {"n": -1}

        async def on_attach(e):
            try:
                picked = await pick_photos()
            except Exception as ex:
                show_error(ex)
                return
            if picked:
                chat_photo["name"], chat_photo["bytes"] = picked[0]
                chat_photo_label.value = f"📎 {picked[0][0]} attached"
                page.update()

        def render_chat(msgs):
            chat_list.controls.clear()
            for m in msgs:
                mine = m["senderUid"] == c.uid
                rows = [ft.Text(f"{'You' if mine else m['sender']} · {m['at']}", size=11,
                                weight=ft.FontWeight.BOLD, color=ft.Colors.SECONDARY),
                        ft.Text(m["text"], size=14, italic=m["locked"], selectable=True)]
                if m["media"]:
                    rows.append(image_view(m["media"]))
                chat_list.controls.append(ft.Container(
                    bgcolor=ft.Colors.PRIMARY_CONTAINER if mine else ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    border_radius=10, padding=10,
                    margin=ft.Margin.only(left=40 if mine else 0, right=0 if mine else 40),
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

        send_btn = ft.IconButton(ft.Icons.SEND, tooltip="Send")

        def send_chat(e):
            if not chat_input.value.strip() and not chat_photo["bytes"]:
                return
            try:
                send_btn.disabled = True
                page.update()
                c.send_chat(gid, chat_input.value.strip(), chat_photo["bytes"], chat_photo["name"])
                chat_input.value = ""
                chat_photo["name"] = chat_photo["bytes"] = None
                chat_photo_label.value = ""
                refresh_chat()
            except Exception as ex:
                show_error(ex)
            finally:
                send_btn.disabled = False
                page.update()
        send_btn.on_click = send_chat
        chat_input.on_submit = send_chat

        chat_tab = ft.Column(expand=True, controls=[
            chat_list,
            chat_photo_label,
            ft.Row([ft.IconButton(ft.Icons.ADD_A_PHOTO, tooltip="Attach photo", on_click=on_attach),
                    chat_input, send_btn]),
        ])

        # ---- Incidents tab ----
        incident_list = ft.Column(spacing=8)

        def refresh_incidents():
            incident_list.controls.clear()
            try:
                incs = c.read_incidents(gid)
                for inc in incs:
                    closed = inc.get("status", "Open") != "Open"
                    incident_list.controls.append(ft.Card(content=ft.Container(
                        padding=12, on_click=lambda e, i=inc: open_incident(i),
                        content=ft.Row(controls=[
                            ft.Icon(ft.Icons.CHECK_CIRCLE if closed else ft.Icons.WARNING_AMBER,
                                    color=ft.Colors.GREEN if closed else BRAND_AMBER),
                            ft.Column(spacing=2, expand=True, controls=[
                                ft.Text(inc.get("title", "-"), size=15, weight=ft.FontWeight.BOLD),
                                ft.Text(f"Assigned: {inc.get('assigned_to') or '-'}"
                                        f"  ·  Target: {inc.get('target_date') or '-'}", size=12),
                                ft.Text(f"Status: {inc.get('status', 'Open')}", size=12),
                            ]),
                            ft.Button("View", on_click=lambda e, i=inc: open_incident(i)),
                        ]))))
                if not incs:
                    incident_list.controls.append(ft.Text("No incidents reported.", italic=True))
            except Exception as ex:
                show_error(ex)
            page.update()

        incidents_tab = ft.Column(expand=True, scroll=ft.ScrollMode.AUTO,
                                  horizontal_alignment=ft.CrossAxisAlignment.STRETCH, controls=[
            ft.Row([ft.FilledButton("Report incident", icon=ft.Icons.ADD,
                              on_click=lambda e: show_new_incident()),
                    ft.TextButton("Refresh", icon=ft.Icons.REFRESH,
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
                    trailing = None
                    if app["is_admin"] and not m["isMe"]:
                        trailing = ft.IconButton(
                            ft.Icons.PERSON_REMOVE, tooltip="Remove (rotates the key)",
                            on_click=lambda e, m=m: confirm_remove(m))
                    member_list.controls.append(ft.ListTile(
                        leading=ft.Icon(ft.Icons.PERSON),
                        title=ft.Text(m["displayName"] + (" (you)" if m["isMe"] else "")),
                        subtitle=ft.Text(f"Safety number: {m['fingerprint']}", size=11),
                        trailing=trailing))
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
                close_dialog()
                try:
                    c.add_member_uid(gid, who["uid"])
                    add_field.value = ""
                    toast(f"Added {who['displayName']}.")
                    refresh_members()
                except Exception as ex:
                    show_error(ex)
            page.show_dialog(ft.AlertDialog(
                title=ft.Text(f"Add {who['displayName']}?"),
                content=ft.Text(f"Found: {who['displayName']}\nSafety number: {who['fingerprint']}"
                                "\n\nThey'll be able to read this group's messages sent "
                                "since the last time someone was removed."),
                actions=[ft.TextButton("Cancel", on_click=close_dialog),
                         ft.TextButton("Add", on_click=really_add)]))

        def confirm_remove(m):
            def really_remove(ev):
                close_dialog()
                try:
                    c.remove_member(gid, m["uid"])
                    toast(f"Removed {m['displayName']}; group key rotated.")
                    refresh_members()
                except Exception as ex:
                    show_error(ex)
            page.show_dialog(ft.AlertDialog(
                title=ft.Text(f"Remove {m['displayName']}?"),
                content=ft.Text("A new encryption key will be made for everyone else, so they "
                                "can't read anything sent after this."),
                actions=[ft.TextButton("Cancel", on_click=close_dialog),
                         ft.TextButton("Remove", on_click=really_remove)]))

        members_tab = ft.Column(expand=True, scroll=ft.ScrollMode.AUTO, controls=[
            *([ft.Row([add_field, ft.IconButton(ft.Icons.PERSON_ADD, tooltip="Add",
                                                on_click=find_and_add)])]
              if app["is_admin"] else
              [ft.Text("Only your employer can add or remove people.", size=12, italic=True)]),
            member_list,
            ft.Text("Compare safety numbers in person to be sure nobody is in the middle.",
                    size=11, italic=True),
        ])

        screen = show(
            ft.Row([ft.IconButton(ft.Icons.ARROW_BACK, tooltip="Groups",
                                  on_click=lambda e: show_home()),
                    ft.Icon(ft.Icons.LOCK, size=16),
                    ft.Text(gname, size=20, weight=ft.FontWeight.BOLD, expand=True,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.IconButton(ft.Icons.REFRESH, tooltip="Refresh",
                                  on_click=lambda e: (refresh_chat(), refresh_incidents()))]),
            ft.Tabs(length=3, selected_index=tab, expand=True, content=ft.Column(expand=True, controls=[
                ft.TabBar(tabs=[ft.Tab(label="Chat"), ft.Tab(label="Incidents"),
                                ft.Tab(label="Members")]),
                ft.TabBarView(expand=True, controls=[chat_tab, incidents_tab, members_tab]),
            ])),
            scroll=False,
        )
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
        page.run_thread(poll)

    # =====================================================================
    # SCREEN 4 — New incident
    # =====================================================================
    def show_new_incident():
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
                    ft.Icon(ft.Icons.PHOTO, size=14),
                    ft.Text(p["name"], size=11, expand=True),
                    ft.IconButton(ft.Icons.CLOSE, icon_size=16, tooltip="Remove",
                                  on_click=lambda e, i=idx: remove_photo(i)),
                ]))
            page.update()

        def remove_photo(i):
            if 0 <= i < len(photos):
                photos.pop(i)
                render_photo_list()

        async def on_photos(e):
            try:
                for name, data in await pick_photos(multiple=True):
                    photos.append({"name": name, "b64": base64.b64encode(data).decode()})
            except Exception as ex:
                show_error(ex)
            render_photo_list()

        try:
            member_names = [m["displayName"] for m in c.group_members(gid)]
        except Exception:
            member_names = []

        title = ft.TextField(label="Problem title")
        desc = ft.TextField(label="Description", multiline=True, min_lines=3)
        photo_desc = ft.TextField(label="Photo description")
        reporter = ft.TextField(label="Your name (reporter)", value=c.username)
        assignee = ft.Dropdown(label="Assign to", expand=True,
                               options=[ft.DropdownOption(key=n, text=n) for n in member_names])
        target = ft.TextField(label="Target date (YYYY-MM-DD)",
                              keyboard_type=ft.KeyboardType.DATETIME)

        def pick_date(e):
            def chosen(ev):
                if ev.control.value:
                    target.value = ev.control.value.strftime("%Y-%m-%d")
                    page.update()
            page.show_dialog(ft.DatePicker(first_date=datetime.now(), on_change=chosen,
                                           help_text="Target date"))
        target.expand = True
        date_btn = ft.IconButton(ft.Icons.CALENDAR_MONTH, tooltip="Pick a date",
                                 on_click=pick_date)
        save_btn = ft.FilledButton("Save incident", icon=ft.Icons.SAVE)

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
                show_group(tab=1)
                toast("Incident saved (encrypted).")
            except Exception as ex:
                done()
                show_error(ex)
        save_btn.on_click = save

        show(
            ft.Row([ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda e: show_group(tab=1)),
                    ft.Text("Report an incident", size=20, weight=ft.FontWeight.BOLD)]),
            title, desc,
            ft.Button("Attach photos", icon=ft.Icons.PHOTO_CAMERA, on_click=on_photos),
            photo_list,
            photo_desc, reporter, ft.Row([assignee]), ft.Row([target, date_btn]),
            save_btn,
        )
        render_photo_list()

    # =====================================================================
    # SCREEN 5 — Incident detail: updates + PDF export
    # =====================================================================
    def open_incident(inc):
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]
        update_text = ft.TextField(label="Add an update", expand=True, multiline=True)

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

        async def export_pdf(e):
            tmp = os.path.join(DATA_DIR, "_pdf_tmp")
            os.makedirs(tmp, exist_ok=True)
            photo_paths = []
            try:
                for i, p in enumerate(inc.get("photos", [])):
                    fp = os.path.join(tmp, f"{i}_{os.path.basename(p['name'])}")
                    with open(fp, "wb") as f:
                        f.write(base64.b64decode(p["b64"]))
                    photo_paths.append(fp)
                path = make_pdf(inc, gname, photo_paths)
                with open(path, "rb") as f:
                    data = f.read()
                os.remove(path)                  # don't leave decrypted copies around
            finally:
                for fp in photo_paths:
                    try:
                        os.remove(fp)
                    except OSError:
                        pass
            await deliver_file(os.path.basename(path), data, "application/pdf")

        updates = [ft.Text(f"[{u['timestamp']}] {u.get('by', '') + ': ' if u.get('by') else ''}"
                           f"{u['text']}", size=12, selectable=True)
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

        show(
            ft.Row([ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda e: show_group(tab=1)),
                    ft.Text(inc.get("title", "-"), size=20, weight=ft.FontWeight.BOLD,
                            expand=True)]),
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
            ft.Row([update_text, ft.IconButton(ft.Icons.SEND, tooltip="Add update",
                                               on_click=add_update)]),
            ft.Divider(),
            ft.Row(wrap=True, controls=[
                ft.Button("Mark Closed" if inc.get("status", "Open") == "Open" else "Re-open",
                          on_click=toggle_status),
                ft.Button("Share PDF" if is_mobile else "Export PDF",
                          icon=ft.Icons.PICTURE_AS_PDF, on_click=export_pdf)]),
        )

    def _clean(inc):
        """Strip the local-only helper fields before saving back."""
        return {k: v for k, v in inc.items() if not k.startswith("_")}

    # ------------------------------------------------------------ start
    try:
        config = FirebaseConfig.load()
    except Exception as ex:
        show(ft.Text("Firebase isn't configured yet", size=20, weight=ft.FontWeight.BOLD),
             ft.Text(str(ex)))
        return
    show_auth()


if __name__ == "__main__":
    ft.run(main)
