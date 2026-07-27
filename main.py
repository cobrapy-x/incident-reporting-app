"""
Incident Reporting App  —  connected + end-to-end encrypted
===========================================================
Cross-platform (Android / iOS / desktop) app built with Flet.

Screens:
  1. Sign in / register  (username + password; keys made on this device)
  2. Groups              (synced from your backend, max 50 members each)
  3. Group               (two tabs: encrypted Chat + Incidents)
  4. Report incident     (encrypted; still exports a PDF with signature panel)

All messages, media and incident reports are encrypted on THIS device before
they are sent. The server only ever stores ciphertext. The heavy lifting lives
in client_api.py (network + crypto) and e2e.py (encryption); this file is just
the screens.

Run it:
    pip install -r requirements.txt
    flet run main.py
"""

import os
import json
import base64
from datetime import datetime

import flet as ft
from fpdf import FPDF

from client_api import Client

# --- where we remember this device's identity (private key stays here) ------
DATA_DIR = os.environ.get("FLET_APP_STORAGE_DATA") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "app_data")
os.makedirs(DATA_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
DEFAULT_SERVER = "http://127.0.0.1:8000"


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    return {}


def save_settings(s):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)


def now_stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


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
    app = {"client": None, "group_id": None, "group_name": None}

    def toast(msg):
        page.open(ft.SnackBar(ft.Text(msg)))

    def show_error(e):
        # Turn network/HTTP errors into a short readable message.
        msg = str(e)
        try:
            msg = e.response.json().get("detail", msg)
        except Exception:
            pass
        toast(f"Error: {msg}")

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
        """Show a decrypted image inline, with Save (download) and optional Remove.

        The bytes are already decrypted on this device; Flet renders them from
        base64 (no temp file needed), which is why the image now loads.
        """
        b64 = base64.b64encode(media["bytes"]).decode()
        row = [
            ft.Icon(ft.icons.PHOTO, size=13),
            ft.Text(media["name"] or "image", size=11),
            ft.TextButton("Save", icon=ft.icons.DOWNLOAD,
                          on_click=lambda e, m=media: save_media(m["name"],
                                                                 m["bytes"])),
        ]
        if on_remove is not None:
            row.append(ft.TextButton("Remove", icon=ft.icons.DELETE,
                                     on_click=on_remove))
        return ft.Column(spacing=4, controls=[
            ft.Image(src_base64=b64, width=width, fit=ft.ImageFit.CONTAIN,
                     border_radius=6,
                     error_content=ft.Text("Can't preview this image", size=11)),
            ft.Row(row),
        ])

    # =====================================================================
    # SCREEN 1 — Sign in / register
    # =====================================================================
    def show_auth():
        page.controls.clear()
        app["client"] = None
        known_user = settings.get("username", "")
        have_key = bool(settings.get("private_key"))

        server = ft.TextField(label="Server address",
                              value=settings.get("server", DEFAULT_SERVER))
        username = ft.TextField(label="Username", value=known_user)
        password = ft.TextField(label="Password", password=True,
                                can_reveal_password=True)

        def do_register(e):
            try:
                c = Client(server.value.strip())
                c.register(username.value.strip(), password.value)
                settings.update(server=server.value.strip(),
                                username=c.username, private_key=c.private_key)
                save_settings(settings)
                app["client"] = c
                toast("Account created and keys saved on this device.")
                show_groups()
            except Exception as ex:
                show_error(ex)

        def do_login(e):
            try:
                c = Client(server.value.strip())
                priv = settings.get("private_key")
                if not priv:
                    toast("No keys on this device — use Create account first.")
                    return
                c.login(username.value.strip(), password.value, priv)
                settings.update(server=server.value.strip(), username=c.username)
                save_settings(settings)
                app["client"] = c
                show_groups()
            except Exception as ex:
                show_error(ex)

        buttons = [ft.ElevatedButton("Create account", icon=ft.icons.PERSON_ADD,
                                     on_click=do_register)]
        if have_key:
            buttons.insert(0, ft.ElevatedButton("Log in", icon=ft.icons.LOGIN,
                                                on_click=do_login))

        page.add(
            ft.Text("Incident Reporting", size=26, weight=ft.FontWeight.BOLD),
            ft.Row([ft.Icon(ft.icons.LOCK, size=16),
                    ft.Text("End-to-end encrypted", size=13)]),
            ft.Divider(),
            server, username, password,
            ft.Row(buttons),
            ft.Text("Your private key is generated and stored on this device only.",
                    size=11, italic=True),
        )
        page.update()

    # =====================================================================
    # SCREEN 2 — Groups
    # =====================================================================
    def show_groups():
        page.controls.clear()
        c = app["client"]

        new_name = ft.TextField(label="New group name", expand=True)
        members_field = ft.TextField(label="Members (comma-separated usernames)")

        def add_group(e):
            name = new_name.value.strip()
            if not name:
                toast("Type a group name.")
                return
            members = [m.strip() for m in members_field.value.split(",") if m.strip()]
            try:
                c.create_group(name, members)
                show_groups()
            except Exception as ex:
                show_error(ex)

        try:
            groups = c.my_groups()
        except Exception as ex:
            show_error(ex)
            groups = []

        cards = []
        for g in groups:
            cards.append(ft.Card(content=ft.Container(padding=12, content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Column(spacing=2, controls=[
                        ft.Text(g["name"], size=16, weight=ft.FontWeight.BOLD),
                        ft.Row([ft.Icon(ft.icons.LOCK, size=12),
                                ft.Text(f"{g['members']}/50 members  ·  encrypted",
                                        size=12)]),
                    ]),
                    ft.ElevatedButton("Open",
                                      on_click=lambda e, gid=g["id"], gn=g["name"]:
                                      open_group(gid, gn)),
                ]))))

        page.add(
            ft.Row([ft.Text(f"Signed in as {c.username}", size=13),
                    ft.TextButton("Sign out", on_click=lambda e: show_auth())],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Text("Your groups", size=22, weight=ft.FontWeight.BOLD),
            ft.Column([new_name, members_field,
                       ft.ElevatedButton("Create group", icon=ft.icons.ADD,
                                         on_click=add_group)]),
            ft.Divider(),
            *(cards or [ft.Text("No groups yet. Create one above.", italic=True)]),
        )
        page.update()

    def open_group(gid, gname):
        app["group_id"], app["group_name"] = gid, gname
        show_group()

    # =====================================================================
    # SCREEN 3 — One group: Chat tab + Incidents tab
    # =====================================================================
    def show_group():
        page.controls.clear()
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

        def refresh_chat():
            chat_list.controls.clear()
            try:
                for m in c.read_chat(gid):
                    rows = [ft.Text(f"{m['sender']} · {m['at']}", size=11,
                                    weight=ft.FontWeight.BOLD,
                                    color=ft.colors.SECONDARY),
                            ft.Text(m["text"], size=13)]
                    if m["media"]:
                        rows.append(image_view(m["media"]))
                    chat_list.controls.append(ft.Container(
                        bgcolor=ft.colors.SURFACE_CONTAINER_HIGHEST,
                        border_radius=8, padding=8,
                        content=ft.Column(rows, spacing=2)))
            except Exception as ex:
                show_error(ex)
            page.update()

        def send_chat(e):
            if not chat_input.value.strip() and not chat_photo["path"]:
                return
            media_bytes = media_name = None
            if chat_photo["path"]:
                with open(chat_photo["path"], "rb") as f:
                    media_bytes = f.read()
                media_name = os.path.basename(chat_photo["path"])
            try:
                c.send_chat(gid, chat_input.value.strip(), media_bytes, media_name)
                chat_input.value = ""
                chat_photo["path"] = None
                chat_photo_label.value = ""
                refresh_chat()
            except Exception as ex:
                show_error(ex)

        chat_tab = ft.Column([
            ft.Row([ft.ElevatedButton("Refresh", icon=ft.icons.REFRESH,
                                      on_click=lambda e: refresh_chat())]),
            chat_list,
            ft.Row([chat_input,
                    ft.IconButton(ft.icons.CAMERA_ALT,
                                  on_click=lambda e: chat_picker.pick_files()),
                    ft.IconButton(ft.icons.SEND, on_click=send_chat)]),
            chat_photo_label,
        ])

        # ---- Incidents tab ----
        incident_list = ft.Column(spacing=8)

        def refresh_incidents():
            incident_list.controls.clear()
            try:
                for inc in c.read_incidents(gid):
                    incident_list.controls.append(ft.Card(content=ft.Container(
                        padding=12, content=ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                ft.Column(spacing=2, controls=[
                                    ft.Text(inc.get("title", "-"), size=15,
                                            weight=ft.FontWeight.BOLD),
                                    ft.Text(f"Assigned: {inc.get('assigned_to') or '-'}"
                                            f"  ·  Target: {inc.get('target_date') or '-'}",
                                            size=12),
                                    ft.Text(f"Status: {inc.get('status', 'Open')}",
                                            size=12),
                                ]),
                                ft.ElevatedButton(
                                    "View",
                                    on_click=lambda e, i=inc: open_incident(i)),
                            ]))))
            except Exception as ex:
                show_error(ex)
            page.update()

        incidents_tab = ft.Column([
            ft.Row([ft.ElevatedButton("+ Report incident", icon=ft.icons.ADD,
                                      on_click=lambda e: show_new_incident()),
                    ft.ElevatedButton("Refresh", icon=ft.icons.REFRESH,
                                      on_click=lambda e: refresh_incidents())]),
            incident_list,
        ])

        page.add(
            ft.Row([ft.TextButton("← Groups", on_click=lambda e: show_groups())]),
            ft.Row([ft.Icon(ft.icons.LOCK, size=16),
                    ft.Text(gname, size=22, weight=ft.FontWeight.BOLD)]),
            ft.Tabs(selected_index=0, tabs=[
                ft.Tab(text="Chat", content=ft.Container(chat_tab, padding=10)),
                ft.Tab(text="Incidents",
                       content=ft.Container(incidents_tab, padding=10)),
            ]),
        )
        page.update()
        refresh_chat()
        refresh_incidents()

    # =====================================================================
    # SCREEN 4 — New incident
    # =====================================================================
    def show_new_incident():
        page.controls.clear()
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]
        photos = []  # list of {"name", "b64"} — added to the encrypted incident
        photo_list = ft.Column(spacing=4)

        def render_photo_list():
            photo_list.controls.clear()
            if not photos:
                photo_list.controls.append(
                    ft.Text("No photos yet", size=11, italic=True))
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
                    with open(picked.path, "rb") as fh:
                        data = fh.read()
                    photos.append({"name": os.path.basename(picked.path),
                                   "b64": base64.b64encode(data).decode()})
                except Exception as ex:
                    show_error(ex)
            render_photo_list()

        picker = ft.FilePicker(on_result=on_photos)
        page.overlay.append(picker)

        title = ft.TextField(label="Problem title")
        desc = ft.TextField(label="Description", multiline=True, min_lines=3)
        photo_desc = ft.TextField(label="Photo description")
        reporter = ft.TextField(label="Your name (reporter)", value=c.username)
        assignee = ft.TextField(label="Assign to (username)")
        target = ft.TextField(label="Target date (YYYY-MM-DD)")

        def save(e):
            if not title.value.strip():
                toast("Give the problem a title.")
                return
            incident = {
                "title": title.value.strip(),
                "description": desc.value.strip(),
                "photo_description": photo_desc.value.strip(),
                "reporter": reporter.value.strip(),
                "assigned_to": assignee.value.strip(),
                "target_date": target.value.strip(),
                "status": "Open",
                "created_at": now_stamp(),
                "updates": [],
                "photos": photos,          # images ride inside the encrypted blob
            }
            try:
                c.create_incident(gid, incident)
                toast("Incident saved (encrypted).")
                show_group()
            except Exception as ex:
                show_error(ex)

        page.add(
            ft.Row([ft.TextButton("← Back", on_click=lambda e: show_group())]),
            ft.Text("Report an incident", size=22, weight=ft.FontWeight.BOLD),
            title, desc,
            ft.ElevatedButton("Attach photos", icon=ft.icons.PHOTO_CAMERA,
                              on_click=lambda e: picker.pick_files(
                                  allow_multiple=True)),
            photo_list,
            photo_desc, reporter, assignee, target,
            ft.ElevatedButton("Save incident", icon=ft.icons.SAVE, on_click=save),
        )
        page.update()
        render_photo_list()

    # =====================================================================
    # SCREEN 5 — Incident detail: updates + PDF export
    # =====================================================================
    def open_incident(inc):
        page.controls.clear()
        c = app["client"]
        gid, gname = app["group_id"], app["group_name"]
        update_text = ft.TextField(label="Add an update", expand=True)

        def add_update(e):
            if not update_text.value.strip():
                return
            inc.setdefault("updates", []).append(
                {"text": update_text.value.strip(), "timestamp": now_stamp()})
            try:
                c.update_incident(gid, inc["_id"], _clean(inc))
                open_incident(inc)
            except Exception as ex:
                show_error(ex)

        def toggle_status(e):
            inc["status"] = "Closed" if inc.get("status") == "Open" else "Open"
            try:
                c.update_incident(gid, inc["_id"], _clean(inc))
                open_incident(inc)
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
            toast(f"PDF saved: {path}")

        updates = [ft.Text(f"[{u['timestamp']}] {u['text']}", size=12)
                   for u in inc.get("updates", [])]
        def make_remove(idx):
            def _rm(e):
                try:
                    inc.get("photos", []).pop(idx)
                    c.update_incident(gid, inc["_id"], _clean(inc))
                    open_incident(inc)          # re-render without that photo
                except Exception as ex:
                    show_error(ex)
            return _rm

        photo_controls = [
            image_view({"name": p["name"], "bytes": base64.b64decode(p["b64"])},
                       on_remove=make_remove(i))
            for i, p in enumerate(inc.get("photos", []))
        ]

        page.add(
            ft.Row([ft.TextButton("← Back", on_click=lambda e: show_group())]),
            ft.Text(inc.get("title", "-"), size=22, weight=ft.FontWeight.BOLD),
            ft.Text(f"Reported by {inc.get('reporter') or '-'} on "
                    f"{inc.get('created_at')}", size=12),
            ft.Text(f"Assigned to: {inc.get('assigned_to') or '-'}", size=12),
            ft.Text(f"Target date: {inc.get('target_date') or '-'}", size=12),
            ft.Text(f"Status: {inc.get('status', 'Open')}", size=12,
                    weight=ft.FontWeight.BOLD),
            ft.Divider(),
            ft.Text("Description", weight=ft.FontWeight.BOLD),
            ft.Text(inc.get("description") or "-"),
            ft.Text(f"Photo note: {inc.get('photo_description') or '-'}",
                    size=12, italic=True),
            *photo_controls,
            ft.Divider(),
            ft.Text("Updates", weight=ft.FontWeight.BOLD),
            *(updates or [ft.Text("No updates yet.", italic=True)]),
            ft.Row([update_text, ft.ElevatedButton("Add", on_click=add_update)]),
            ft.Divider(),
            ft.Row([ft.ElevatedButton("Toggle Open/Closed", on_click=toggle_status),
                    ft.ElevatedButton("Export PDF", icon=ft.icons.PICTURE_AS_PDF,
                                      on_click=export_pdf)]),
        )
        page.update()

    def _clean(inc):
        """Strip the local-only helper fields before saving back to the server."""
        return {k: v for k, v in inc.items() if not k.startswith("_")}

    # Start on the sign-in screen.
    show_auth()


if __name__ == "__main__":
    ft.app(target=main)
