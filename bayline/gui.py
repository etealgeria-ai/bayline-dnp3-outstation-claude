"""Desktop window matching the Bayline console: points, comms, master, wire, SAv5."""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

from bayline.outstation import write_point
from bayline.station import KEY_AUTH_FAIL, KEY_OK, ROLES, find_point

BG = "#121816"
SURFACE = "#1c2621"
INK = "#e7efe9"
MUTED = "#8ea197"
LINE = "#2c3a34"
AMBER = "#e2a53a"
ALARM = "#e15b4a"


def run_gui(host) -> None:
    root = tk.Tk()
    root.title("DNP3 Outstation Simulator by Claude")
    root.geometry("1080x720")
    root.minsize(860, 560)
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=SURFACE, foreground=INK, padding=(14, 8))
    style.map("TNotebook.Tab", background=[("selected", AMBER)], foreground=[("selected", "#1a140c")])
    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=INK, borderwidth=0, rowheight=26)
    style.configure("Treeview.Heading", background="#24302a", foreground=MUTED, relief="flat")
    style.map("Treeview", background=[("selected", "#2f4038")], foreground=[("selected", INK)])

    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=16, pady=(12, 4))
    tk.Label(header, text="BAYLINE", bg=BG, fg=AMBER, font=("Segoe UI", 9)).pack(anchor="w")
    tk.Label(header, text="DNP3 Outstation Simulator by Claude", bg=BG, fg=INK, font=("Segoe UI", 18)).pack(anchor="w")
    subtitle = tk.StringVar()
    tk.Label(header, textvariable=subtitle, bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w")
    lamps = tk.Frame(header, bg=BG)
    lamps.pack(anchor="w", pady=(6, 0))
    lamp_vars = {name: tk.StringVar(value=name) for name in ("TCP", "SAv5", "Restart", "Time", "Local", "C1", "C2", "C3")}
    lamp_widgets = {}
    for name, var in lamp_vars.items():
        label = tk.Label(lamps, textvariable=var, bg=BG, fg=MUTED, font=("Segoe UI", 9))
        label.pack(side="left", padx=(0, 14))
        lamp_widgets[name] = label

    actions = tk.Frame(root, bg=BG)
    actions.pack(fill="x", padx=16, pady=8)
    power = tk.Button(actions, command=lambda: _toggle(host), bg=ALARM, fg="#1a100e", relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold"))
    power.pack(side="left")

    book = ttk.Notebook(root)
    book.pack(fill="both", expand=True, padx=16, pady=(0, 16))
    points_tab = _tab(book, "Points")
    trend_tab = _tab(book, "Trend")
    comms_tab = _tab(book, "Comms")
    wire_tab = _tab(book, "Wire")
    security_tab = _tab(book, "Security")
    lab_tab = _tab(book, "Lab")

    points = ttk.Treeview(points_tab, columns=("kind", "addr", "idx", "clazz", "name", "value"), show="headings")
    for key, title, width in (("kind", "Type", 60), ("addr", "DNP3 address", 110), ("idx", "Index", 60), ("clazz", "Class", 60), ("name", "Point", 260), ("value", "Value", 160)):
        points.heading(key, text=title)
        points.column(key, width=width, anchor="w")
    points.pack(fill="both", expand=True, padx=8, pady=8)
    point_actions = tk.Frame(points_tab, bg=BG)
    point_actions.pack(fill="x", padx=8, pady=(0, 8))
    for index, title in ((0, "52-T1"), (1, "52-F1"), (2, "52-F2")):
        tk.Button(point_actions, text=f"Trip {title}", command=lambda i=index: _breaker(host, i, 0), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 6))
        tk.Button(point_actions, text=f"Close {title}", command=lambda i=index: _breaker(host, i, 1), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=6).pack(side="left", padx=(0, 12))
    manual = tk.Frame(points_tab, bg=BG)
    manual.pack(fill="x", padx=8, pady=(0, 8))
    tk.Label(manual, text="Manual value", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(side="left")
    manual_entry = tk.Entry(manual, width=16, bg=SURFACE, fg=INK, insertbackground=INK, relief="flat", font=("Consolas", 11))
    manual_entry.pack(side="left", padx=8)
    manual_error = tk.StringVar()
    tk.Button(manual, text="Write", command=lambda: _write(host, points, manual_entry, manual_error), bg=AMBER, fg="#1a140c", relief="flat", padx=12, pady=6).pack(side="left")
    tk.Button(manual, text="Release to random", command=lambda: _release(host, points), bg=SURFACE, fg=INK, relief="flat", padx=12, pady=6).pack(side="left", padx=(8, 0))
    tk.Label(manual, textvariable=manual_error, bg=BG, fg=ALARM, font=("Segoe UI", 10)).pack(side="left", padx=8)

    trend = tk.Canvas(trend_tab, bg=BG, highlightthickness=0)
    trend.pack(fill="both", expand=True)
    samples: list[dict] = []

    comms = _text(comms_tab)
    security_state = _build_security(security_tab, host)
    lab_state = _build_lab(lab_tab, host)
    wire = tk.Listbox(wire_tab, bg=SURFACE, fg=INK, selectbackground="#2f4038", highlightthickness=0, relief="flat", font=("Consolas", 10))
    wire.pack(fill="both", expand=True, padx=8, pady=(8, 4))
    hex_line = tk.StringVar(value="Select a frame to see the hex.")
    tk.Label(wire_tab, textvariable=hex_line, bg=BG, fg=AMBER, anchor="w", font=("Consolas", 9), wraplength=980, justify="left").pack(fill="x", padx=8, pady=(0, 8))
    shown: list[tuple] = []

    def on_wire(_event=None) -> None:
        pick = wire.curselection()
        if not pick or pick[0] >= len(shown):
            return
        hex_line.set(shown[pick[0]][4] or shown[pick[0]][3])

    wire.bind("<<ListboxSelect>>", on_wire)

    log_key: list[tuple] = [()]

    def refresh() -> None:
        snap = host.snapshot()
        sav = snap["sav"]
        subtitle.set(f"{snap['name']} · address {snap['outstation']} · master {snap['master']} · port {snap['port']}")
        power.configure(text="Stop outstation" if snap["running"] else "Start outstation", bg=ALARM if snap["running"] else AMBER, fg="#1a100e")
        _lamp(lamp_widgets["TCP"], lamp_vars["TCP"], f"TCP {snap['clients']}" if snap["clients"] else f"TCP {snap['port']}", snap["running"] and not snap["error"], bool(snap["error"]))
        _lamp(lamp_widgets["SAv5"], lamp_vars["SAv5"], "SAv off" if not sav["enabled"] else sav["label"] if sav["status"] == KEY_OK else f"{sav['label']} fail" if sav["status"] == KEY_AUTH_FAIL else f"{sav['label']} init", sav["enabled"] and sav["status"] == KEY_OK, sav["enabled"] and sav["status"] == KEY_AUTH_FAIL)
        _lamp(lamp_widgets["Restart"], lamp_vars["Restart"], "Restart", snap["restart"], snap["restart"])
        _lamp(lamp_widgets["Time"], lamp_vars["Time"], "Time", snap["need_time"], snap["need_time"])
        _lamp(lamp_widgets["Local"], lamp_vars["Local"], "Local", snap["local"], snap["local"])
        for clazz, name in ((1, "C1"), (2, "C2"), (3, "C3")):
            count = snap["classes"][clazz]
            _lamp(lamp_widgets[name], lamp_vars[name], f"{name} {count}", count > 0, False)
        verdict, detail = _verdict(snap)
        unsol = " ".join(key.upper() for key, on in snap["unsol"].items() if on) or "Off"
        confirm = "None" if snap["confirm"] is None else f"Seq {snap['confirm']['seq']} · {snap['confirm']['left']} s"
        armed = "None" if snap["select"] is None else f"g{snap['select']['group']} · {snap['select']['index']} · {snap['select']['left']} s"
        quiet = "None" if snap["quiet"] is None else "Just now" if snap["quiet"] < 1500 else f"{round(snap['quiet'] / 1000)} s ago"
        _fill(comms, [
            verdict,
            detail,
            "",
            f"TCP listener     {'Up · port ' + str(snap['port']) if snap['running'] else 'Down'}",
            f"TCP clients      {snap['error'] or snap['clients']}",
            "Station owner    This PC",
            f"Outstation       {snap['outstation']}",
            f"Master           {snap['master']}",
            f"Link             {'Reset' if snap['link'] else 'Not reset'}",
            f"Last frame       {quiet}",
            f"Received         {snap['rx']}",
            f"Sent             {snap['tx']}",
            f"Rejected         {snap['bad']}",
            f"Confirm pending  {confirm}",
            f"Select armed     {armed}",
            f"Unsolicited      {unsol}",
            "",
            "Secure session",
            f"Authentication   {'On' if sav['enabled'] else 'Off'}",
            f"Version          {sav['label']}",
            f"MAC              {sav['mac_name']}",
            f"Key wrap         {sav['wrap_name']}",
            f"Key status       {_key_name(sav['status'])}",
            f"User             {sav['user']}",
            f"KSQ              {sav['ksq']}",
            f"CSQ              {sav['csq']}",
            f"Accepted         {sav['ok']}",
            f"Failed           {sav['fail']}",
            f"Aggressive       {'On' if sav['aggressive'] else 'Off'}",
            "",
            sav["result"],
        ])
        _paint_security(security_state, snap)
        _paint_lab(lab_state, snap)
        _sample(samples, snap)
        _draw_trend(trend, samples)
        selected = points.selection()
        points.delete(*points.get_children())
        for kind, index, name, value, units, held, clazz in snap["points"]:
            shown_value = _shown(kind, index, value, units, held)
            address = f"{_group(kind)}:{index}"
            points.insert("", "end", iid=f"{kind}-{index}", values=(kind.upper(), address, index, clazz, name, shown_value))
        if selected:
            points.selection_set([item for item in selected if points.exists(item)])
        key = tuple((item[0], item[2], item[3]) for item in snap["log"])
        if key != log_key[0]:
            log_key[0] = key
            shown.clear()
            shown.extend(snap["log"])
            wire.delete(0, "end")
            for _id, stamp, direction, summary, _hx, ok in snap["log"]:
                mark = {"in": "RX", "out": "TX"}.get(direction, "--")
                clock = time.strftime("%H:%M:%S", time.gmtime(stamp / 1000))
                wire.insert("end", f"{clock}  {mark}  {summary}")
                if not ok:
                    wire.itemconfig("end", fg=ALARM)
            if not snap["log"]:
                wire.insert("end", "No frames yet. Connect a master on port 20000.")
            wire.yview_moveto(1)
        root.after(500, refresh)

    host.start()
    refresh()
    root.protocol("WM_DELETE_WINDOW", lambda: (_shutdown(host), root.destroy()))
    root.mainloop()


def _tab(book: ttk.Notebook, title: str) -> tk.Frame:
    frame = tk.Frame(book, bg=BG)
    book.add(frame, text=title)
    return frame


def _text(parent: tk.Frame) -> tk.Text:
    widget = tk.Text(parent, bg=BG, fg=INK, relief="flat", font=("Consolas", 11), padx=12, pady=12, wrap="word")
    widget.pack(fill="both", expand=True)
    widget.configure(state="disabled")
    return widget


def _fill(widget: tk.Text, lines: list[str]) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("end", "\n".join(lines))
    widget.configure(state="disabled")


def _lamp(widget: tk.Label, var: tk.StringVar, text: str, on: bool, alarm: bool) -> None:
    var.set(("● " if on else "○ ") + text)
    widget.configure(fg=ALARM if alarm and on else AMBER if on else MUTED)


def _key_name(status: int) -> str:
    return {1: "OK", 2: "NOT_INIT", 3: "COMM_FAIL", 4: "AUTH_FAIL"}.get(status, f"KS_{status}")


def _verdict(snap: dict) -> tuple[str, str]:
    if not snap["running"]:
        return "Stopped", "The outstation is stopped. Start it before a master can connect."
    if snap["error"]:
        return "TCP down", snap["error"]
    if snap["clients"] and snap["link"]:
        word = "master" if snap["clients"] == 1 else "masters"
        return "Master online", f"{snap['clients']} TCP {word} on port {snap['port']}. The link is reset."
    if snap["clients"]:
        return "TCP connected", "A master socket is open, but the link is not reset yet."
    if snap["quiet"] is not None and snap["quiet"] > 15000:
        return "Idle", f"Listening on port {snap['port']}. Nothing has been received for {round(snap['quiet'] / 1000)} seconds."
    return "Waiting", f"Listening on port {snap['port']}, address {snap['outstation']}. No TCP master is connected."


def _sample(rows: list[dict], snap: dict) -> None:
    values = {(kind, index): value for kind, index, _name, value, _units, _held, _clazz in snap["points"]}
    rows.append(values)
    if len(rows) > 120:
        del rows[:-120]


def _draw_trend(canvas: tk.Canvas, rows: list[dict]) -> None:
    canvas.delete("all")
    width = max(canvas.winfo_width(), 480)
    height = max(canvas.winfo_height(), 360)
    bands = [
        ("Voltage", [(("ai", 0), "Bus", AMBER), (("ai", 10), "F1", "#7dcea0"), (("ai", 11), "F2", "#5dade2")], "kV"),
        ("Current", [(("ai", 1), "F1", ALARM), (("ai", 2), "F2", "#f0b27a")], "A"),
        ("Frequency", [(("ai", 5), "Hz", "#d7bde2")], "Hz"),
        ("Load", [(("ai", 7), "F1", "#82e0aa"), (("ai", 8), "F2", "#85c1e9")], "kW"),
    ]
    gap = 10
    band_h = (height - gap * (len(bands) + 1)) / len(bands)
    left, right = 64, 16
    for index, (title, series, unit) in enumerate(bands):
        top = gap + index * (band_h + gap)
        bottom = top + band_h
        canvas.create_rectangle(8, top, width - 8, bottom, outline=LINE, fill=SURFACE)
        canvas.create_text(16, top + 14, text=title, fill=INK, anchor="w", font=("Segoe UI", 10))
        plot_top = top + 28
        plot_bottom = bottom - 18
        plot_left = left
        plot_right = width - right
        present = [row[key] for row in rows for key, _label, _color in series if key in row]
        if len(rows) < 2 or not present:
            canvas.create_text(plot_left, (plot_top + plot_bottom) / 2, text="Waiting for samples", fill=MUTED, anchor="w", font=("Segoe UI", 9))
            continue
        low = min(present)
        high = max(present)
        if high - low < 0.05:
            mid = (high + low) / 2
            low, high = mid - 0.5, mid + 0.5
        span = plot_right - plot_left
        count = len(rows)

        def y_of(value: float, lo: float = low, hi: float = high) -> float:
            return plot_bottom - ((value - lo) / (hi - lo)) * (plot_bottom - plot_top)

        canvas.create_text(plot_left - 8, plot_top, text=f"{high:,.2f}", fill=MUTED, anchor="e", font=("Consolas", 8))
        canvas.create_text(plot_left - 8, plot_bottom, text=f"{low:,.2f}", fill=MUTED, anchor="e", font=("Consolas", 8))
        legend_x = 120
        for key, label, color in series:
            latest = rows[-1].get(key)
            caption = label if latest is None else f"{label} {latest:,.2f} {unit}"
            canvas.create_text(legend_x, top + 14, text=caption, fill=color, anchor="w", font=("Consolas", 9))
            legend_x += 150
            coords = []
            for step, row in enumerate(rows):
                if key not in row:
                    continue
                x = plot_left + (step / max(1, count - 1)) * span
                coords.extend((x, y_of(row[key])))
            if len(coords) >= 4:
                canvas.create_line(*coords, fill=color, width=2, smooth=True)


def _build_security(parent: tk.Frame, host) -> dict:
    outer = tk.Frame(parent, bg=BG)
    outer.pack(fill="both", expand=True)
    canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
    scroll = ttk.Scrollbar(outer, command=canvas.yview)
    canvas.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    form = tk.Frame(canvas, bg=BG)
    window = canvas.create_window((0, 0), window=form, anchor="nw")
    form.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))

    enabled = tk.BooleanVar(value=True)
    aggressive = tk.BooleanVar(value=False)
    version = tk.StringVar(value="SAv5")
    role = tk.StringVar(value="Operator")
    user = tk.StringVar(value="1")
    mac = tk.StringVar(value="HMAC-SHA-256-16")
    wrap = tk.StringVar(value="AES-256")
    key = tk.StringVar()
    show_key = tk.BooleanVar(value=False)
    challenge_ms = tk.StringVar(value="5000")
    lifetime = tk.StringVar(value="3600")
    notice = tk.StringVar()
    gate = {"ready": False}
    stats = {name: tk.StringVar(value="—") for name in ("session", "key_status", "ksq", "csq", "sent", "rx", "ok", "fail", "changes", "error", "last_user", "last_time")}
    policy_vars = {}

    def section(title: str) -> tk.Frame:
        tk.Label(form, text=title, bg=BG, fg=AMBER, anchor="w", font=("Segoe UI", 11, "bold")).pack(fill="x", padx=16, pady=(14, 4))
        body = tk.Frame(form, bg=BG)
        body.pack(fill="x", padx=16)
        return body

    def row(body: tk.Frame, label: str, widget: tk.Widget) -> None:
        line = tk.Frame(body, bg=BG)
        line.pack(fill="x", pady=3)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w", font=("Segoe UI", 10)).pack(side="left")
        widget.pack(side="left", fill="x", expand=True)

    def check(body: tk.Frame, label: str, variable: tk.BooleanVar, command) -> tk.Checkbutton:
        box = tk.Checkbutton(body, text=label, variable=variable, command=command, bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK, anchor="w")
        box.pack(fill="x", pady=1)
        return box

    auth = section("1  Secure authentication")
    check(auth, "Enable secure authentication", enabled, lambda: host.set_flag("sav5", enabled.get()))
    row(auth, "SA version", ttk.Combobox(auth, textvariable=version, values=("SAv2", "SAv5"), state="readonly", width=28))
    def on_version(*_args) -> None:
        if not gate["ready"]:
            return
        host.set_auth_version(2 if version.get() == "SAv2" else 5)
        if version.get() == "SAv2":
            mac.set("HMAC-SHA-1-8")
            wrap.set("AES-128")
        else:
            mac.set("HMAC-SHA-256-16")
            wrap.set("AES-256")

    version.trace_add("write", on_version)
    row(auth, "User number", ttk.Entry(auth, textvariable=user, width=30))
    row(auth, "Role", ttk.Combobox(auth, textvariable=role, values=("Viewer", "Operator", "Engineer", "Installer", "SECADM"), state="readonly", width=28))

    def on_role(*_args) -> None:
        if not gate["ready"] or not role.get():
            return
        host.set_role(role.get())
        spec = ROLES.get(role.get())
        if spec:
            user.set(str(spec[0]))

    role.trace_add("write", on_role)
    check(auth, "Aggressive mode", aggressive, lambda: host.set_flag("aggressive", aggressive.get()))

    crypto = section("2  Cryptography")
    mac_box = ttk.Combobox(crypto, textvariable=mac, values=("HMAC-SHA-1-8", "HMAC-SHA-256-16"), state="readonly", width=28)
    wrap_box = ttk.Combobox(crypto, textvariable=wrap, values=("AES-128", "AES-256"), state="readonly", width=28)
    row(crypto, "MAC algorithm", mac_box)
    row(crypto, "Key wrap", wrap_box)
    tk.Label(crypto, text="SA version selects the procedure. The MAC and key wrap must match that version.", bg=BG, fg=MUTED, anchor="w", font=("Segoe UI", 9)).pack(fill="x", pady=(4, 2))
    key_entry = ttk.Entry(crypto, textvariable=key, show="*")
    row(crypto, "Update key", key_entry)
    buttons = tk.Frame(crypto, bg=BG)
    buttons.pack(fill="x", pady=4)

    def apply_algo(selected_mac: str, selected_wrap: str) -> None:
        if not gate["ready"]:
            return
        pair = {"HMAC-SHA-1-8": 2, "AES-128": 2, "HMAC-SHA-256-16": 5, "AES-256": 5}
        wanted = pair.get(selected_mac)
        if wanted is None or pair.get(selected_wrap) != wanted:
            notice.set("MAC and key wrap do not form an implemented pair. SAv2 is HMAC-SHA-1-8 + AES-128. SAv5 is HMAC-SHA-256-16 + AES-256.")
            return
        if (wanted == 5) != (version.get() == "SAv5"):
            notice.set(f"That pair belongs to SAv{wanted}. Change SA version to SAv{wanted}. The version is not inferred from the algorithm.")
            return
        notice.set(f"SAv{wanted} procedures are active with {selected_mac} and {selected_wrap}.")

    mac.trace_add("write", lambda *_args: apply_algo(mac.get(), wrap.get()))
    wrap.trace_add("write", lambda *_args: apply_algo(mac.get(), wrap.get()))

    def import_key() -> None:
        notice.set(host.set_update_key(key.get()) or "Update key imported.")

    def generate_key() -> None:
        key.set(host.generate_update_key())
        notice.set("New update key generated. Copy it into the master.")

    def toggle_key() -> None:
        key_entry.configure(show="" if show_key.get() else "*")

    tk.Button(buttons, text="Generate key", command=generate_key, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(buttons, text="Import key", command=import_key, bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Checkbutton(buttons, text="Show key", variable=show_key, command=toggle_key, bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK).pack(side="left")

    session = section("3  Session")
    for label, name in (("Session status", "session"), ("Session key status", "key_status"), ("Key change sequence", "ksq"), ("Challenge sequence", "csq"), ("Session key lifetime", "lifetime_label"), ("Challenge timeout", "timeout_label")):
        if name in ("lifetime_label", "timeout_label"):
            continue
        line = tk.Frame(session, bg=BG)
        line.pack(fill="x", pady=2)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w").pack(side="left")
        tk.Label(line, textvariable=stats[name], bg=BG, fg=INK, anchor="w", font=("Consolas", 10)).pack(side="left")
    row(session, "Session key lifetime (s)", ttk.Entry(session, textvariable=lifetime, width=30))
    row(session, "Challenge timeout (ms)", ttk.Entry(session, textvariable=challenge_ms, width=30))

    def apply_limits(*_args) -> None:
        if not gate["ready"]:
            return
        try:
            host.set_auth_limits(int(challenge_ms.get()), int(lifetime.get()))
        except ValueError:
            notice.set("Lifetime and challenge timeout must be numbers.")

    lifetime.trace_add("write", apply_limits)
    challenge_ms.trace_add("write", apply_limits)

    policy = section("4  Authentication policy")
    boxes = (
        ("controls", "Authenticate controls"),
        ("crob", "Binary output / CROB"),
        ("analog", "Analog output"),
        ("direct_operate", "Direct operate"),
        ("direct_operate_nr", "Direct operate no ack"),
        ("select_operate", "Select before operate"),
        ("cold_restart", "Cold restart"),
        ("warm_restart", "Warm restart"),
        ("unsolicited", "Enable / disable unsolicited"),
        ("assign_class", "Assign class"),
        ("initialize", "Initialize data and application"),
        ("time_write", "Time write"),
        ("file_transfer", "File transfer"),
    )
    for name, label in boxes:
        variable = tk.BooleanVar(value=name != "time_write")
        policy_vars[name] = variable
        box = check(policy, label, variable, lambda n=name, v=variable: host.set_policy(n, v.get()))
        if name != "time_write":
            box.configure(state="disabled")

    diag = section("5  Diagnostics")
    for label, name in (
        ("Challenges sent", "sent"),
        ("Challenges received", "rx"),
        ("Authentication accepted", "ok"),
        ("Authentication rejected", "fail"),
        ("Key changes", "changes"),
        ("Last error", "error"),
        ("Last authenticated user", "last_user"),
        ("Last authentication time", "last_time"),
    ):
        line = tk.Frame(diag, bg=BG)
        line.pack(fill="x", pady=2)
        tk.Label(line, text=label, bg=BG, fg=MUTED, width=28, anchor="w").pack(side="left")
        tk.Label(line, textvariable=stats[name], bg=BG, fg=INK, anchor="w", font=("Consolas", 10)).pack(side="left")
    tk.Label(form, textvariable=notice, bg=BG, fg=AMBER, anchor="w", justify="left", wraplength=860, font=("Segoe UI", 10)).pack(fill="x", padx=16, pady=8)
    actions = tk.Frame(form, bg=BG)
    actions.pack(fill="x", padx=16, pady=(0, 16))
    tk.Button(actions, text="Remote / local", command=lambda: host.set_flag("local", not host.snapshot()["local"]), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(actions, text="Yard run / hold", command=lambda: host.set_flag("sim", not host.snapshot()["sim_on"]), bg=SURFACE, fg=INK, relief="flat", padx=8, pady=4).pack(side="left")
    return {"enabled": enabled, "aggressive": aggressive, "version": version, "role": role, "user": user, "mac": mac, "wrap": wrap, "key": key, "lifetime": lifetime, "challenge_ms": challenge_ms, "notice": notice, "stats": stats, "policy": policy_vars, "gate": gate}


def _paint_security(state: dict, snap: dict) -> None:
    sav = snap["sav"]
    if not state["gate"]["ready"]:
        state["enabled"].set(sav["enabled"])
        state["aggressive"].set(sav["aggressive"])
        state["version"].set(sav["label"] if sav["version"] in (2, 5) else "SAv5")
        state["role"].set(sav["role"])
        state["user"].set(str(sav["user"]))
        state["mac"].set(sav["mac_name"])
        state["wrap"].set(sav["wrap_name"])
        state["key"].set(sav["key"])
        state["lifetime"].set(str(sav["session_lifetime_s"]))
        state["challenge_ms"].set(str(sav["challenge_timeout_ms"]))
        for name, variable in state["policy"].items():
            variable.set(sav["policy"][name])
        state["notice"].set(sav["result"])
        state["gate"]["ready"] = True
    status = "OFF" if not sav["enabled"] else "OK" if sav["status"] == KEY_OK else "AUTH_FAIL" if sav["status"] == KEY_AUTH_FAIL else "INVALID"
    key_status = "OFF" if not sav["enabled"] else _key_name(sav["status"]) if sav["status"] == KEY_OK else "INVALID" if sav["status"] != KEY_AUTH_FAIL else "AUTH_FAIL"
    state["stats"]["session"].set(status)
    state["stats"]["key_status"].set(key_status)
    state["stats"]["ksq"].set(str(sav["ksq"]))
    state["stats"]["csq"].set(str(sav["csq"]))
    state["stats"]["sent"].set(str(sav["challenges_sent"]))
    state["stats"]["rx"].set(str(sav["challenges_rx"]))
    state["stats"]["ok"].set(str(sav["ok"]))
    state["stats"]["fail"].set(str(sav["fail"]))
    state["stats"]["changes"].set(str(sav["key_changes"]))
    state["stats"]["error"].set(sav["result"])
    state["stats"]["last_user"].set(str(sav["last_user"] or "—"))
    when = sav["last_auth_time"]
    state["stats"]["last_time"].set(time.strftime("%H:%M:%S", time.localtime(when / 1000)) if when else "—")


def _build_lab(parent: tk.Frame, host) -> dict:
    form = tk.Frame(parent, bg=BG)
    form.pack(fill="both", expand=True, padx=16, pady=8)
    notice = tk.StringVar(value="Faults apply to outgoing frames only. Changes take effect on the next reply.")
    fields = {
        "drop_pct": ("Drop outgoing frames (%)", tk.StringVar(value="0")),
        "corrupt_pct": ("Corrupt CRC (%)", tk.StringVar(value="0")),
        "duplicate_pct": ("Duplicate frames (%)", tk.StringVar(value="0")),
        "delay_ms": ("Reply delay (ms)", tk.StringVar(value="0")),
        "jitter_ms": ("Random jitter (ms)", tk.StringVar(value="0")),
        "seed": ("Random seed (blank = random)", tk.StringVar(value="")),
    }
    silent = tk.BooleanVar(value=False)
    reads = tk.BooleanVar(value=False)
    fail_count = tk.StringVar(value="1")
    status = tk.StringVar(value="—")

    def heading(text: str) -> None:
        tk.Label(form, text=text, bg=BG, fg=AMBER, anchor="w", font=("Segoe UI", 11, "bold")).pack(fill="x", pady=(10, 4))

    def line(label: str, widget_factory) -> tk.Frame:
        row = tk.Frame(form, bg=BG)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, bg=BG, fg=MUTED, width=30, anchor="w").pack(side="left")
        widget_factory(row).pack(side="left")
        return row

    heading("1  Link faults")
    for name, (label, var) in fields.items():
        line(label, lambda row, v=var: ttk.Entry(row, textvariable=v, width=12))

    def apply_faults() -> None:
        for name, (_label, var) in fields.items():
            problem = host.set_fault(name, var.get().strip())
            if problem:
                notice.set(problem)
                return
        notice.set("Link faults applied.")

    def clear_faults() -> None:
        for name, (_label, var) in fields.items():
            var.set("" if name == "seed" else "0")
        silent.set(False)
        host.set_fault("silent", False)
        apply_faults()
        notice.set("All link faults cleared.")

    buttons = tk.Frame(form, bg=BG)
    buttons.pack(fill="x", pady=6)
    tk.Button(buttons, text="Apply", command=apply_faults, bg=AMBER, fg="#1a140c", relief="flat", padx=12, pady=4).pack(side="left", padx=(0, 6))
    tk.Button(buttons, text="Clear all", command=clear_faults, bg=SURFACE, fg=INK, relief="flat", padx=12, pady=4).pack(side="left")
    tk.Checkbutton(form, text="Silent: answer nothing (dead RTU)", variable=silent, command=lambda: host.set_fault("silent", silent.get()), bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK, anchor="w").pack(fill="x", pady=2)

    heading("2  Secure authentication faults")
    tk.Checkbutton(form, text="Challenge every Read as well", variable=reads, command=lambda: host.set_lab_flag("challenge_reads", reads.get()), bg=BG, fg=INK, selectcolor=SURFACE, activebackground=BG, activeforeground=INK, anchor="w").pack(fill="x", pady=2)
    sa = tk.Frame(form, bg=BG)
    sa.pack(fill="x", pady=4)
    tk.Label(sa, text="Reject the next", bg=BG, fg=MUTED).pack(side="left")
    ttk.Entry(sa, textvariable=fail_count, width=5).pack(side="left", padx=4)
    tk.Label(sa, text="valid authentications", bg=BG, fg=MUTED).pack(side="left")

    def fail_auth() -> None:
        try:
            host.fail_next_auth(int(fail_count.get()))
            notice.set(f"The next {int(fail_count.get())} valid authentication(s) will be rejected with error 1.")
        except ValueError:
            notice.set("Enter a whole number.")

    tk.Button(sa, text="Arm", command=fail_auth, bg=SURFACE, fg=INK, relief="flat", padx=10, pady=3).pack(side="left", padx=6)
    tk.Button(form, text="Expire session keys now", command=lambda: (host.expire_session(), notice.set("Session keys expired. The master must rekey.")), bg=SURFACE, fg=INK, relief="flat", padx=10, pady=4).pack(anchor="w", pady=4)

    heading("3  Capture")
    line("Wire capture", lambda row: tk.Label(row, textvariable=status, bg=BG, fg=INK, font=("Consolas", 10)))
    tk.Label(form, textvariable=notice, bg=BG, fg=AMBER, anchor="w", justify="left", wraplength=860).pack(fill="x", pady=10)
    return {"fields": fields, "silent": silent, "reads": reads, "status": status, "ready": [False]}


def _paint_lab(state: dict, snap: dict) -> None:
    lab = snap["lab"]
    if not state["ready"][0]:
        for name, (_label, var) in state["fields"].items():
            value = lab.get(name)
            var.set("" if value is None else str(value))
        state["silent"].set(lab["silent"])
        state["reads"].set(lab["challenge_reads"])
        state["ready"][0] = True
    armed = f"  ·  {lab['fail_auth']} auth rejection(s) armed" if lab["fail_auth"] else ""
    state["status"].set((f"{lab['capture']}  ({lab['captured']} records)" if lab["capture"] else "off (start with --capture FILE)") + armed)


def _shown(kind: str, index: int, value: float, units: str, held: bool) -> str:
    if kind == "bo":
        text = "Latched" if value >= 0.5 else "Dropped"
    elif kind == "bi":
        if index <= 3:
            text = "Closed" if value >= 0.5 else "Open"
        elif index == 10:
            text = "Remote" if value >= 0.5 else "Local"
        else:
            text = "Alarm" if value >= 0.5 else "Normal"
    else:
        if kind in ("ai", "ao"):
            number = f"{value:,.2f}"
        else:
            number = f"{round(value):,}"
        text = f"{number} {units}".strip()
    if held:
        text += "  held"
    return text


def _group(kind: str) -> int:
    return {"bi": 1, "bo": 10, "ctr": 20, "ai": 30, "ao": 40}.get(kind, 0)


def _selected(points: ttk.Treeview) -> tuple[str, int] | None:
    pick = points.selection()
    if not pick or "-" not in pick[0]:
        return None
    kind, index = pick[0].split("-", 1)
    return kind, int(index)


def _write(host, points: ttk.Treeview, entry: tk.Entry, error: tk.StringVar) -> None:
    chosen = _selected(points)
    if chosen is None:
        error.set("Select a point.")
        return
    message = host.write_manual(chosen[0], chosen[1], entry.get())
    error.set(message or "Held. Simulation will not change it.")


def _release(host, points: ttk.Treeview) -> None:
    chosen = _selected(points)
    if chosen:
        host.release_point(chosen[0], chosen[1])


def _toggle(host) -> None:
    if host.running:
        host.stop()
    else:
        host.start()


def _breaker(host, index: int, closed: int) -> None:
    with host.lock:
        point = find_point(host.station, "bo", index)
        if point:
            write_point(host.station, point, closed, point.flags, int(time.time() * 1000), "control")


def _shutdown(host) -> None:
    host.stop()
