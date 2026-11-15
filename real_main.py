#!/usr/bin/env python3
"""
Aminium Studio - Kivy / Android port.

Same four steps as the desktop app (Token -> Clean IPs -> Build -> Configs), plus the ONE
feature this version adds: a "My configs" screen to manage every config ever built on this
device (rename, delete locally, optionally also delete the Worker/Pages project on Cloudflare).

All networking / scanning / Cloudflare / config-generation logic is unchanged from the desktop
app - it lives in aminium_core.py and is simply called from here. This file only replaces the
customtkinter UI with a Kivy UI that works on a phone.
"""
import json
import re
import threading
import time
import uuid as uuidlib

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ListProperty
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.utils import platform

import aminium_core as core

# ───────────────────────────── Android runtime permissions ─────────────────────────────
if platform == "android":
    try:
        from android.permissions import request_permissions, Permission  # type: ignore
        request_permissions([Permission.INTERNET, Permission.ACCESS_NETWORK_STATE])
    except Exception:
        pass

KV = r"""
#:import dp kivy.metrics.dp

<Card@BoxLayout>:
    orientation: "vertical"
    padding: dp(14)
    spacing: dp(8)
    size_hint_y: None
    height: self.minimum_height
    canvas.before:
        Color:
            rgba: 0.071, 0.102, 0.212, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<SectionLabel@Label>:
    bold: True
    font_size: "16sp"
    size_hint_y: None
    height: self.texture_size[1]
    halign: "left"
    valign: "middle"
    text_size: self.width, None
    color: 0.91, 0.925, 1, 1

<SubLabel@Label>:
    font_size: "12sp"
    size_hint_y: None
    height: self.texture_size[1]
    halign: "left"
    valign: "middle"
    text_size: self.width, None
    color: 0.56, 0.61, 0.78, 1

<FieldLabel@Label>:
    font_size: "13sp"
    size_hint_y: None
    height: dp(24)
    halign: "left"
    valign: "middle"
    text_size: self.width, None
    color: 0.72, 0.76, 0.9, 1

<StepHeader@BoxLayout>:
    size_hint_y: None
    height: dp(56)
    canvas.before:
        Color:
            rgba: 0.106, 0.157, 0.42, 1
        Rectangle:
            pos: self.pos
            size: self.size
    Label:
        text: root.title if hasattr(root, "title") else ""
        bold: True
        font_size: "18sp"

BoxLayout:
    orientation: "vertical"
    canvas.before:
        Color:
            rgba: 0.039, 0.055, 0.122, 1
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        size_hint_y: None
        height: dp(52)
        padding: dp(10), 0
        canvas.before:
            Color:
                rgba: 0.106, 0.157, 0.42, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: "AMINIUM STUDIO"
            bold: True
            font_size: "18sp"
            halign: "left"
            text_size: self.size

    BoxLayout:
        id: tabbar
        size_hint_y: None
        height: dp(44)
        canvas.before:
            Color:
                rgba: 0.071, 0.102, 0.212, 1
            Rectangle:
                pos: self.pos
                size: self.size
        ToggleButton:
            text: "1 Token"
            group: "tabs"
            state: "down"
            on_press: app.goto("token")
        ToggleButton:
            text: "2 Clean IPs"
            group: "tabs"
            on_press: app.goto("scan")
        ToggleButton:
            text: "3 Build"
            group: "tabs"
            on_press: app.goto("build")
        ToggleButton:
            text: "4 Configs"
            group: "tabs"
            on_press: app.goto("output")
        ToggleButton:
            text: "My configs"
            group: "tabs"
            on_press: app.goto("manage")

    ScreenManager:
        id: sm

    BoxLayout:
        id: logbar
        size_hint_y: None
        height: dp(72)
        padding: dp(8)
        canvas.before:
            Color:
                rgba: 0.027, 0.039, 0.086, 1
            Rectangle:
                pos: self.pos
                size: self.size
        ScrollView:
            Label:
                id: logbox
                text: ""
                size_hint_y: None
                height: self.texture_size[1]
                text_size: self.width, None
                font_size: "11sp"
                color: 0.56, 0.61, 0.78, 1


<TokenScreen>:
    name: "token"
    ScrollView:
        BoxLayout:
            orientation: "vertical"
            padding: dp(12)
            spacing: dp(10)
            size_hint_y: None
            height: self.minimum_height

            Card:
                SectionLabel:
                    text: "Step 1 - Cloudflare API token"
                SubLabel:
                    text: "Paste your Cloudflare API token once. It is stored only on this phone (app-private storage)."
                FieldLabel:
                    text: "API token (or Global API Key)"
                TextInput:
                    id: f_token
                    multiline: False
                    password: True
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "Email (only needed for a Global API Key)"
                TextInput:
                    id: f_email
                    multiline: False
                    size_hint_y: None
                    height: dp(44)
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    spacing: dp(8)
                    Button:
                        text: "Save && verify"
                        on_release: app.on_save_token()
                    Button:
                        text: "Forget token"
                        on_release: app.on_forget_token()
                Label:
                    id: lbl_token_state
                    text: ""
                    size_hint_y: None
                    height: dp(22)
                    text_size: self.width, None
                FieldLabel:
                    text: "Account"
                Spinner:
                    id: sp_account
                    text: "(verify token first)"
                    size_hint_y: None
                    height: dp(44)


<ScanScreen>:
    name: "scan"
    ScrollView:
        BoxLayout:
            orientation: "vertical"
            padding: dp(12)
            spacing: dp(10)
            size_hint_y: None
            height: self.minimum_height

            Card:
                SectionLabel:
                    text: "Step 2 - find clean Cloudflare IPs"
                SubLabel:
                    text: "Run this with any VPN off. Each IP gets a real TCP + TLS + HTTP test."
                FieldLabel:
                    text: "Connection"
                Spinner:
                    id: sp_conn
                    text: "TLS"
                    values: ["TLS", "No TLS"]
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "Search depth"
                Spinner:
                    id: sp_depth
                    text: "Normal"
                    values: ["Quick", "Normal", "Deep"]
                    size_hint_y: None
                    height: dp(44)
                Button:
                    id: btn_scan
                    text: "\u25b6  Start scan"
                    size_hint_y: None
                    height: dp(48)
                    on_release: app.on_scan()
                Button:
                    id: btn_stop
                    text: "Stop"
                    size_hint_y: None
                    height: dp(40)
                    disabled: True
                    on_release: app.on_stop_scan()
                Label:
                    id: lbl_scan_stats
                    text: "idle"
                    size_hint_y: None
                    height: dp(24)
                ProgressBar:
                    id: pb_scan
                    max: 1
                    value: 0
                    size_hint_y: None
                    height: dp(16)

            Card:
                SectionLabel:
                    text: "Clean IPs found"
                Label:
                    id: lbl_ip_list
                    text: "(none yet)"
                    size_hint_y: None
                    height: self.texture_size[1]
                    text_size: self.width, None
                    font_size: "12sp"


<BuildScreen>:
    name: "build"
    ScrollView:
        BoxLayout:
            orientation: "vertical"
            padding: dp(12)
            spacing: dp(10)
            size_hint_y: None
            height: self.minimum_height

            Card:
                SectionLabel:
                    text: "Step 3 - build"
                Label:
                    id: lbl_build_sum
                    text: ""
                    size_hint_y: None
                    height: self.texture_size[1]
                    text_size: self.width, None
                FieldLabel:
                    text: "Deploy to"
                Spinner:
                    id: sp_mode
                    text: "Workers (recommended)"
                    values: ["Workers (recommended)", "Pages (pages.dev)"]
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "Source (_worker.js zip, e.g. aminium-pages.zip)"
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    spacing: dp(6)
                    TextInput:
                        id: f_source
                        multiline: False
                    Button:
                        text: "Pick"
                        size_hint_x: None
                        width: dp(70)
                        on_release: app.pick_source_file()
                FieldLabel:
                    text: "Project name"
                TextInput:
                    id: f_project
                    multiline: False
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "ADMIN_PASSWORD"
                TextInput:
                    id: f_pass
                    multiline: False
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "PANEL_PATH"
                TextInput:
                    id: f_panel
                    multiline: False
                    size_hint_y: None
                    height: dp(44)
                FieldLabel:
                    text: "Custom domain (optional)"
                TextInput:
                    id: f_domain
                    multiline: False
                    size_hint_y: None
                    height: dp(44)
                Button:
                    text: "Re-roll random values"
                    size_hint_y: None
                    height: dp(40)
                    on_release: app.roll_all()
                Button:
                    id: btn_build
                    text: "\u26a1  Build my configs"
                    size_hint_y: None
                    height: dp(52)
                    on_release: app.on_build()
                Label:
                    id: lbl_build_stage
                    text: "Waiting for you."
                    size_hint_y: None
                    height: self.texture_size[1]
                    text_size: self.width, None
                ProgressBar:
                    id: pb_build
                    max: 1
                    value: 0
                    size_hint_y: None
                    height: dp(16)


<OutputScreen>:
    name: "output"
    ScrollView:
        BoxLayout:
            orientation: "vertical"
            padding: dp(12)
            spacing: dp(10)
            size_hint_y: None
            height: self.minimum_height

            Card:
                SectionLabel:
                    text: "Step 4 - your configs"
                Label:
                    id: lbl_out_info
                    text: "Nothing built yet. Go through steps 1-3, or pick an earlier deployment in \"My configs\"."
                    size_hint_y: None
                    height: self.texture_size[1]
                    text_size: self.width, None
                FieldLabel:
                    text: "Format"
                Spinner:
                    id: sp_fmt
                    text: "Auto (recommended)"
                    values: ["Auto (recommended)", "Xray + fragment", "Clash", "sing-box", "Patt", "Plain links"]
                    size_hint_y: None
                    height: dp(44)
                    on_text: app.on_pick_fmt(self.text)
                TextInput:
                    id: f_sub_url
                    multiline: False
                    readonly: True
                    size_hint_y: None
                    height: dp(44)
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    spacing: dp(6)
                    Button:
                        text: "Copy link"
                        on_release: app.copy_sub_url()
                    Button:
                        text: "Save all to device"
                        on_release: app.save_all_configs()
                TextInput:
                    id: f_preview
                    text: ""
                    readonly: True
                    size_hint_y: None
                    height: dp(220)


<ManageScreen>:
    name: "manage"
    BoxLayout:
        orientation: "vertical"
        padding: dp(12)
        spacing: dp(10)
        Card:
            size_hint_y: None
            SectionLabel:
                text: "My configs"
            SubLabel:
                text: "Every config you have built on this phone. Tap one to load it into Step 4, or delete it."
        ScrollView:
            BoxLayout:
                id: manage_list
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(8)
                padding: dp(4)
"""


class TokenScreen(Screen):
    pass


class ScanScreen(Screen):
    pass


class BuildScreen(Screen):
    pass


class OutputScreen(Screen):
    pass


class ManageScreen(Screen):
    pass


class DeploymentRow(BoxLayout):
    def __init__(self, rec, index, app, **kw):
        super().__init__(orientation="vertical", size_hint_y=None, padding=10, spacing=4, **kw)
        self.height = 110
        from kivy.uix.label import Label
        from kivy.uix.button import Button
        from kivy.graphics import Color, RoundedRectangle
        with self.canvas.before:
            Color(0.071, 0.102, 0.212, 1)
            self._bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[10])
        self.bind(pos=self._update_bg, size=self._update_bg)
        title = rec.get("label") or rec.get("project", "(unnamed)")
        lbl = Label(text=f"[b]{title}[/b]\n{rec.get('base', '')}\ncreated: {rec.get('created', '')}  |  {len(rec.get('ips', []))} clean IPs",
                    markup=True, halign="left", valign="top", size_hint_y=None, height=64, font_size="12sp")
        lbl.bind(size=lambda i, v: setattr(i, "text_size", (i.width, None)))
        self.add_widget(lbl)
        row = BoxLayout(size_hint_y=None, height=34, spacing=6)
        b1 = Button(text="Load", on_release=lambda *_: app.load_deployment(index))
        b2 = Button(text="Rename", on_release=lambda *_: app.rename_deployment_prompt(index))
        b3 = Button(text="Delete", on_release=lambda *_: app.delete_deployment_prompt(index))
        row.add_widget(b1)
        row.add_widget(b2)
        row.add_widget(b3)
        self.add_widget(row)

    def _update_bg(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size


FORMATS_UI = [
    ("auto", "Auto (recommended)", ""),
    ("xray", "Xray + fragment", "?format=xray"),
    ("clash", "Clash", "?format=clash"),
    ("singbox", "sing-box", "?format=singbox"),
    ("patt", "Patt", "?format=patt"),
    ("v2ray", "Plain links", "?format=base64"),
]


class AminiumApp(App):
    title = "Aminium Studio"

    def build(self):
        Window.clearcolor = (0.039, 0.055, 0.122, 1)
        self.cfg = self.load_cfg()
        self.token = self.cfg.get("token", "")
        self.email = self.cfg.get("email", "")
        self.accounts = []
        self.token_ok = False
        self.job = None
        self.ips = []
        self.rec = None
        self.out = None
        self.cur_fmt = "auto"
        self.deployments = core.load_deployments()
        root = Builder.load_string(KV)
        self.sm = root.ids.sm
        self.logbox = root.ids.logbox
        self.sm.add_widget(TokenScreen())
        self.sm.add_widget(ScanScreen())
        self.sm.add_widget(BuildScreen())
        self.sm.add_widget(OutputScreen())
        self.sm.add_widget(ManageScreen())
        Clock.schedule_once(lambda dt: self.init_fields(), 0)
        return root

    # ---------- small helpers ----------
    def cfg_path(self):
        return core.APP_DIR / "aminium_studio_config.json"

    def load_cfg(self):
        try:
            return json.loads(self.cfg_path().read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_cfg(self):
        self.cfg["token"] = self.token
        self.cfg["email"] = self.email
        try:
            core.APP_DIR.mkdir(parents=True, exist_ok=True)
            self.cfg_path().write_text(json.dumps(self.cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            self.log(f"Could not save settings: {e}")

    def log(self, msg):
        def ui(*_):
            self.logbox.text = (self.logbox.text + "\n" + str(msg))[-4000:]
        Clock.schedule_once(ui, 0)

    def goto(self, name):
        self.sm.current = name
        if name == "manage":
            self.refresh_manage_list()
        if name == "build":
            self.refresh_build_summary()

    def init_fields(self):
        t = self.sm.get_screen("token")
        t.ids.f_token.text = self.token
        t.ids.f_email.text = self.email
        if self.token:
            t.ids.lbl_token_state.text = "Token loaded from this phone's storage. Press 'Save & verify'."
        self.roll_all()

    # ---------- step 1: token ----------
    def on_save_token(self):
        t = self.sm.get_screen("token")
        tok = t.ids.f_token.text.strip()
        if not tok:
            return self.log("Paste the API token first.")
        self.token, self.email = tok, t.ids.f_email.text.strip()
        t.ids.lbl_token_state.text = "Checking the token..."

        def work():
            try:
                cf = core.CF(self.token, self.log, self.email)
                info = cf.verify()
                accs = cf.accounts()
                if not accs:
                    raise core.CFError("No account visible to this token (add 'Account Settings: Read').")
                self.accounts = accs
                vals = [f"{a['name']} ({a['id'][:6]})" for a in accs]

                def ui(*_):
                    t.ids.sp_account.values = vals
                    t.ids.sp_account.text = vals[0]
                    self.token_ok = True
                    t.ids.lbl_token_state.text = f"Token is valid ({info.get('status')}). Go to step 2."
                    self.save_cfg()
                Clock.schedule_once(ui, 0)
            except Exception as e:
                self.log(f"Token check failed: {e}")

                def ui2(*_):
                    self.token_ok = False
                    t.ids.lbl_token_state.text = f"Token check failed: {e}"
                Clock.schedule_once(ui2, 0)
        threading.Thread(target=work, daemon=True).start()

    def on_forget_token(self):
        self.token, self.email, self.token_ok = "", "", False
        self.accounts = []
        t = self.sm.get_screen("token")
        t.ids.f_token.text = ""
        t.ids.f_email.text = ""
        t.ids.sp_account.values = ["(verify token first)"]
        t.ids.sp_account.text = "(verify token first)"
        t.ids.lbl_token_state.text = ""
        self.save_cfg()
        self.log("Token removed from this phone.")

    # ---------- step 2: scan ----------
    def scan_form(self):
        s = self.sm.get_screen("scan")
        tls = s.ids.sp_conn.text == "TLS"
        depth = core.DEPTH[s.ids.sp_depth.text]
        return {
            "host": core.SPEED_HOST, "port": 443 if tls else 80, "count": depth["count"],
            "threads": depth["threads"], "timeout": 5.0, "rounds": 3, "target": depth["target"],
            "mode": "spread", "custom": "", "verify": True, "neighbors": True, "auto": True,
            "ws": False, "speed": False,
        }

    def on_scan(self):
        if self.job and self.job.phase in ("diagnosing", "scanning", "speed", "finishing"):
            return
        s = self.sm.get_screen("scan")
        cfg = core.Config.from_dict(self.scan_form())
        self.job = core.ScanJob(cfg, self.log)
        job = self.job
        s.ids.btn_scan.disabled = True
        s.ids.btn_scan.text = "Scanning..."
        s.ids.btn_stop.disabled = False
        Clock.schedule_once(lambda dt: self.poll_scan(), 0.3)

        def go():
            job.run()
            Clock.schedule_once(lambda dt: self.scan_finished(), 0)
        threading.Thread(target=go, daemon=True).start()

    def on_stop_scan(self):
        if self.job:
            self.job.stop.set()
            self.log("Stopping...")

    def poll_scan(self):
        job = self.job
        if not job:
            return
        s = self.sm.get_screen("scan")
        snap = job.snapshot()
        s.ids.lbl_scan_stats.text = f"{snap['phase']}  -  {snap['tested']}/{snap['total']}  -  {snap['elapsed']}s  -  {snap['found']} found"
        if snap["total"]:
            s.ids.pb_scan.value = min(1.0, snap["tested"] / snap["total"])
        if snap["phase"] in ("diagnosing", "scanning", "speed", "finishing", "idle"):
            Clock.schedule_once(lambda dt: self.poll_scan(), 0.5)

    def scan_finished(self):
        s = self.sm.get_screen("scan")
        s.ids.btn_scan.disabled = False
        s.ids.btn_scan.text = "\u25b6  Start scan"
        s.ids.btn_stop.disabled = True
        snap = self.job.snapshot() if self.job else {"results": []}
        results = sorted(snap["results"], key=lambda r: -r["score"])
        self.ips = [r["ip"] for r in results]
        s.ids.lbl_ip_list.text = "\n".join(f"{r['ip']}  score={r['score']}  {r.get('colo', '')}" for r in results[:60]) or "nothing found - see the log"
        self.log(f"Finished: {len(self.ips)} clean IPs.")

    # ---------- step 3: build ----------
    def roll_all(self):
        b = self.sm.get_screen("build")
        b.ids.f_project.text = core.rnd_name()
        b.ids.f_pass.text = core.rnd(20)
        b.ids.f_panel.text = "/" + core.rnd(10, core.LOWER)
        self._ws_path = "/stream/" + core.rnd(18, core.LOWER)
        self._cron = core.rnd(24)
        self._uuid = str(uuidlib.uuid4())
        default_zip = core.APP_DIR / "aminium-pages.zip"
        if not b.ids.f_source.text and default_zip.exists():
            b.ids.f_source.text = str(default_zip)

    def pick_source_file(self):
        self.log("On Android, place aminium-pages.zip in the app's data folder, or wire a file picker here "
                  "(plyer.filechooser) for the person to browse to it.")

    def refresh_build_summary(self):
        b = self.sm.get_screen("build")
        n = len(self.ips)
        tls = self.sm.get_screen("scan").ids.sp_conn.text == "TLS"
        ports = len(core.TLS_PORTS if tls else core.PLAIN_PORTS)
        b.ids.lbl_build_sum.text = (f"{n} clean IPs (+ your worker's own address)  x  {ports} ports  x  2 protocols\n"
                                     f"= up to {(n + 1) * ports * 2} configs\nConnection: {'TLS' if tls else 'No TLS'}")

    def on_build(self):
        b = self.sm.get_screen("build")
        project = b.ids.f_project.text.strip().lower()
        source = b.ids.f_source.text.strip()
        if not self.ips:
            return self.log("ERROR: no clean IPs yet - run step 2 first.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,56}", project or ""):
            return self.log("ERROR: project name: lowercase letters, digits and '-' only.")
        import pathlib
        if not source or not pathlib.Path(source).exists():
            return self.log("ERROR: source zip not found - pick aminium-pages.zip first.")
        if not b.ids.f_pass.text:
            return self.log("ERROR: ADMIN_PASSWORD is empty.")
        panel = b.ids.f_panel.text.strip()
        if panel and not panel.startswith("/"):
            panel = "/" + panel
            b.ids.f_panel.text = panel
        mode = "workers" if b.ids.sp_mode.text.startswith("Workers") else "pages"
        tls = self.sm.get_screen("scan").ids.sp_conn.text == "TLS"
        form = {
            "pass": b.ids.f_pass.text, "ws_path": self._ws_path, "cron": self._cron, "uuid": self._uuid,
            "decoy": "", "tg_token": "", "tg_secret": "", "tg_admins": "", "domain": b.ids.f_domain.text.strip().lower(),
            "d1": True, "verify_ws": True, "scan": self.scan_form(), "ips": list(self.ips), "keep": 100, "tls": tls,
        }
        b.ids.btn_build.disabled = True
        b.ids.btn_build.text = "Building..."
        b.ids.pb_build.value = 0

        def stage(text, frac):
            def ui(*_):
                b.ids.lbl_build_stage.text = text
                b.ids.pb_build.value = frac
            Clock.schedule_once(ui, 0)

        def work():
            try:
                result = core.run_build(self.token, self.email, self.accounts, None, project, source, panel, mode, form, self.log, stage)
                self.rec, self.out = result["rec"], result["out"]
                self.deployments = core.add_deployment(self.rec)

                def ui(*_):
                    b.ids.btn_build.disabled = False
                    b.ids.btn_build.text = "\u26a1  Build my configs"
                    self.render_output()
                    self.goto("output")
                Clock.schedule_once(ui, 0)
            except Exception as e:
                self.log(f"ERROR: {e}")

                def ui2(*_):
                    b.ids.btn_build.disabled = False
                    b.ids.btn_build.text = "\u26a1  Build my configs"
                    b.ids.lbl_build_stage.text = "Something went wrong - see the log."
                Clock.schedule_once(ui2, 0)
        threading.Thread(target=work, daemon=True).start()

    # ---------- step 4: configs ----------
    def render_output(self):
        o = self.sm.get_screen("output")
        if not self.rec:
            o.ids.lbl_out_info.text = "Nothing built yet."
            return
        n = len(self.out["links"]) if self.out else 0
        o.ids.lbl_out_info.text = (f"{n} configs  -  {len(self.rec.get('ips', []))} clean IPs\n"
                                    f"Panel:    {self.rec['base']}{self.rec['panel_path']}\nPassword: {self.rec['password']}")
        self.on_pick_fmt(o.ids.sp_fmt.text)

    def on_pick_fmt(self, label):
        o = self.sm.get_screen("output")
        key, _, q = next((x for x in FORMATS_UI if x[1] == label), FORMATS_UI[0])
        self.cur_fmt = key
        if not self.out:
            o.ids.f_sub_url.text = ""
            o.ids.f_preview.text = "No configs available yet."
            return
        if key == "auto":
            o.ids.f_sub_url.text = self.out["sub"]
        else:
            o.ids.f_sub_url.text = self.out["sub"] + q
        o.ids.f_preview.text = (self.out["text"].get(key) or "(empty)")[:4000]

    def copy_sub_url(self):
        o = self.sm.get_screen("output")
        from kivy.core.clipboard import Clipboard
        Clipboard.copy(o.ids.f_sub_url.text)
        self.log("Copied.")

    def save_all_configs(self):
        if not (self.rec and self.out):
            return self.log("Nothing to save yet.")
        try:
            folder = core.save_all(self.rec, self.out, self.log)
            self.log(f"Saved to {folder}")
        except Exception as e:
            self.log(f"ERROR: save failed: {e}")

    # ---------- "My configs" management screen (the new feature) ----------
    def refresh_manage_list(self):
        m = self.sm.get_screen("manage")
        box = m.ids.manage_list
        box.clear_widgets()
        self.deployments = core.load_deployments()
        if not self.deployments:
            from kivy.uix.label import Label
            box.add_widget(Label(text="No configs built yet.", size_hint_y=None, height=40))
            return
        for i, rec in enumerate(reversed(self.deployments)):
            real_index = len(self.deployments) - 1 - i
            box.add_widget(DeploymentRow(rec, real_index, self))

    def load_deployment(self, index):
        items = core.load_deployments()
        if not (0 <= index < len(items)):
            return
        rec = items[index]
        self.rec = rec
        self.log(f"Loading configs of {rec['project']} ...")

        def work():
            try:
                out = core.fetch_configs(rec["sub"], self.log) if rec.get("sub") else None
            except Exception as e:
                self.log(f"Could not load: {e}")
                out = None
            self.out = out

            def ui(*_):
                self.render_output()
                self.goto("output")
            Clock.schedule_once(ui, 0)
        threading.Thread(target=work, daemon=True).start()

    def rename_deployment_prompt(self, index):
        items = core.load_deployments()
        if not (0 <= index < len(items)):
            return
        content = BoxLayout(orientation="vertical", padding=10, spacing=10)
        from kivy.uix.textinput import TextInput
        from kivy.uix.button import Button
        ti = TextInput(text=items[index].get("label") or items[index].get("project", ""), multiline=False, size_hint_y=None, height=44)
        content.add_widget(ti)
        btn = Button(text="Save", size_hint_y=None, height=44)
        content.add_widget(btn)
        popup = Popup(title="Rename this config", content=content, size_hint=(0.85, 0.35))

        def do_save(*_):
            core.rename_deployment(items, index, ti.text.strip() or items[index].get("project", ""))
            popup.dismiss()
            self.refresh_manage_list()
        btn.bind(on_release=do_save)
        popup.open()

    def delete_deployment_prompt(self, index):
        items = core.load_deployments()
        if not (0 <= index < len(items)):
            return
        content = BoxLayout(orientation="vertical", padding=10, spacing=10)
        from kivy.uix.label import Label
        from kivy.uix.button import Button
        content.add_widget(Label(text=f"Delete \"{items[index].get('label') or items[index]['project']}\" from this list?\n"
                                       "(The Cloudflare project itself is NOT touched.)"))
        row = BoxLayout(size_hint_y=None, height=44, spacing=8)
        b_yes = Button(text="Delete")
        b_no = Button(text="Cancel")
        row.add_widget(b_yes)
        row.add_widget(b_no)
        content.add_widget(row)
        popup = Popup(title="Confirm delete", content=content, size_hint=(0.85, 0.4))

        def do_delete(*_):
            core.delete_deployment(items, index, log=self.log, also_remove_remote=False)
            popup.dismiss()
            self.refresh_manage_list()
        b_yes.bind(on_release=do_delete)
        b_no.bind(on_release=lambda *_: popup.dismiss())
        popup.open()


if __name__ == "__main__":
    AminiumApp().run()
