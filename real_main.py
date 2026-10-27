"""
Aether / WARP - Kivy / Android port of aether_tool2.py

Tabs: Connect, WARP Account, aether:// Link, Endpoint Scan, Settings.

Real tunnel on Android:
  usque (bundled as libusque.so, started as a subprocess) listens as a
  local SOCKS5 proxy -> VpnTunnelService (Java VpnService, see
  android_src/) establishes a system-wide TUN device and hands it to
  tun2socks (bundled as libtun2socks.so) which forwards every packet into
  that SOCKS5 proxy. That TUN device is what makes Android show the VPN
  "key" icon in the status bar, and it's what actually routes ALL apps'
  traffic, not just this app's.

  On desktop (no android/jnius available) the VPN step is skipped
  automatically and only the local SOCKS5 proxy runs -- useful for
  testing the rest of the app without a phone.
"""
import json
import os
import threading
import time

from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.label import Label

import warpcore as core
import android_bridge as bridge

Window.clearcolor = (0x07 / 255, 0x0a / 255, 0x13 / 255, 1)

KV = """
#:import utils kivy.utils

<Pill@Label>:
    color: 0.92, 0.94, 0.98, 1
    font_size: '13sp'

<SectionLabel@Label>:
    color: 0.55, 0.6, 0.78, 1
    font_size: '11sp'
    size_hint_y: None
    height: '20dp'
    halign: 'left'
    valign: 'middle'
    text_size: self.size

<Field@BoxLayout>:
    orientation: 'vertical'
    size_hint_y: None
    height: '56dp'
    label: ''
    hint: ''
    text: ''
    password: False
    SectionLabel:
        text: root.label
    TextInput:
        id: ti
        text: root.text
        hint_text: root.hint
        multiline: False
        password: root.password
        background_color: 0.04, 0.07, 0.13, 1
        foreground_color: 0.92, 0.94, 0.98, 1
        cursor_color: 0.13, 0.83, 0.93, 1
        padding: '10dp', '10dp'
        on_text: root.text = self.text

<BigButton@Button>:
    background_normal: ''
    background_down: ''
    background_color: 0.19, 0.35, 0.65, 1
    color: 1, 1, 1, 1
    bold: True
    size_hint_y: None
    height: '48dp'

<GhostButton@Button>:
    background_normal: ''
    background_down: ''
    background_color: 0.09, 0.13, 0.22, 1
    color: 0.85, 0.88, 0.95, 1
    size_hint_y: None
    height: '40dp'

<Card@BoxLayout>:
    orientation: 'vertical'
    padding: '14dp'
    spacing: '8dp'
    size_hint_y: None
    height: self.minimum_height
    canvas.before:
        Color:
            rgba: 0.06, 0.09, 0.16, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [14,]
        Color:
            rgba: 0.11, 0.16, 0.27, 1
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, 14
            width: 1

RootWidget:
    orientation: 'vertical'

    BoxLayout:
        size_hint_y: None
        height: '46dp'
        padding: '12dp', '6dp'
        canvas.before:
            Color:
                rgba: 0.04, 0.06, 0.11, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: 'Aether  ·  WARP / MASQUE'
            bold: True
            color: 0.9, 0.93, 0.98, 1
            halign: 'left'
            text_size: self.size

    TabbedPanel:
        id: tabs
        do_default_tab: False
        tab_width: self.width / 5
        background_color: 0.03, 0.05, 0.09, 1

        TabbedPanelItem:
            text: 'Connect'
            ScrollView:
                BoxLayout:
                    id: connect_root
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    padding: '14dp'
                    spacing: '12dp'

        TabbedPanelItem:
            text: 'Account'
            ScrollView:
                BoxLayout:
                    id: account_root
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    padding: '14dp'
                    spacing: '12dp'

        TabbedPanelItem:
            text: 'Link'
            ScrollView:
                BoxLayout:
                    id: link_root
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    padding: '14dp'
                    spacing: '12dp'

        TabbedPanelItem:
            text: 'Scan'
            ScrollView:
                BoxLayout:
                    id: scan_root
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    padding: '14dp'
                    spacing: '12dp'

        TabbedPanelItem:
            text: 'Settings'
            ScrollView:
                BoxLayout:
                    id: settings_root
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    padding: '14dp'
                    spacing: '12dp'
"""


class RootWidget(BoxLayout):
    pass


def log_box(height_lines=14):
    from kivy.uix.textinput import TextInput
    ti = TextInput(readonly=True, background_color=(0.04, 0.07, 0.13, 1),
                    foreground_color=(0.78, 0.82, 0.92, 1),
                    size_hint_y=None, height=f'{18 * height_lines}dp')
    ti.bind(minimum_height=ti.setter('height'))
    return ti


class AetherApp(App):
    title = "Aether WARP"

    def build(self):
        self.base = core.app_dir()
        self.cfg_path = os.path.join(self.base, "config.json")
        self.settings_path = os.path.join(self.base, "aether_settings.json")
        self.account = None
        self.usque_proc = None
        self.scan_rows = []
        self.selected_row = None
        self.vpn_connected = False

        root = Builder.load_string(KV)
        self.root_widget = root
        self._build_connect(root.ids.connect_root)
        self._build_account(root.ids.account_root)
        self._build_link(root.ids.link_root)
        self._build_scan(root.ids.scan_root)
        self._build_settings(root.ids.settings_root)
        self._load_settings()
        self._gen_link()
        return root

    # ---------------------------------------------------------- Connect
    def _build_connect(self, parent):
        from kivy.uix.boxlayout import BoxLayout as BL

        card = Builder.load_string("Card:\n    id: c")
        self.status_label = Label(text="Disconnected", bold=True, font_size='20sp',
                                   color=(0.9, 0.93, 0.98, 1), size_hint_y=None, height='30dp',
                                   halign='left', valign='middle')
        self.status_label.bind(size=lambda w, *_: setattr(w, 'text_size', w.size))
        self.status_sub = Label(text="Tap Connect to start the tunnel.",
                                 color=(0.55, 0.6, 0.78, 1), size_hint_y=None, height='40dp',
                                 halign='left', valign='top')
        self.status_sub.bind(size=lambda w, *_: setattr(w, 'text_size', w.size))
        card.add_widget(self.status_label)
        card.add_widget(self.status_sub)

        row = BL(size_hint_y=None, height='48dp', spacing='8dp')
        self.btn_connect = Builder.load_string("BigButton:\n    text: 'Connect'")
        self.btn_connect.bind(on_release=lambda *_: self.toggle_connect())
        btn_test = Builder.load_string("GhostButton:\n    text: 'Test'")
        btn_test.bind(on_release=lambda *_: self.do_test())
        row.add_widget(self.btn_connect)
        row.add_widget(btn_test)
        card.add_widget(row)
        parent.add_widget(card)

        log_card = Builder.load_string("Card:\n    id: c")
        log_card.add_widget(Builder.load_string("SectionLabel:\n    text: 'Console'"))
        self.console = log_box(16)
        log_card.add_widget(self.console)
        parent.add_widget(log_card)

    def clog(self, msg):
        line = f"[{core.ts()}] {msg}\n"

        @mainthread
        def add(_dt=None):
            self.console.text += line
            try:
                self.console.cursor = self.console.get_cursor_from_index(len(self.console.text))
            except Exception:
                pass
        add()

    def _set_state(self, state):
        states = {
            "idle": ("Disconnected", "Tap Connect to start the tunnel.", "Connect"),
            "connecting": ("Connecting…", "Handshaking with Cloudflare (5-15s).", "Cancel"),
            "connected": ("Connected", "Traffic is flowing through Cloudflare WARP.", "Disconnect"),
            "error": ("Check failed", "Proxy is up but the WARP check failed. See console.", "Disconnect"),
        }
        title, sub, btn = states[state]
        self.status_label.text = title
        self.status_sub.text = sub
        self.btn_connect.text = btn

    # ----- usque process management -----
    def _usque_path(self):
        d = core.native_lib_dir()
        cand = os.path.join(d, "libusque.so")
        if os.path.exists(cand):
            return cand
        # desktop fallback / manual testing
        for name in ("usque", "usque.exe", "libusque.so"):
            p = os.path.join(self.base, name)
            if os.path.exists(p):
                return p
        return cand  # best guess; c_connect will report "not found"

    def toggle_connect(self):
        if self.usque_proc and self.usque_proc.poll() is None:
            self.do_disconnect()
        else:
            self.do_connect()

    def do_connect(self):
        if not os.path.exists(self.cfg_path):
            self.clog("config.json not found - register an account first (Account tab).")
            return
        exe = self._usque_path()
        if not os.path.exists(exe):
            self.clog(f"usque binary not found at {exe}")
            return
        bind, port = self.s_bind.text.strip() or "127.0.0.1", self.s_port.text.strip() or "10820"
        if not core.port_free(bind, port):
            self.clog(f"port {port} already in use, pick another one in Settings.")
            return
        mode = self.s_mode or "socks"
        args = [exe, "-c", self.cfg_path, mode, "-b", bind, "-p", str(port)]
        if self.s_h2.active:
            args.append("--http2")
        if self.s_sni.text.strip():
            args += ["-s", self.s_sni.text.strip()]
        if self.s_extra.text.strip():
            args += self.s_extra.text.strip().split()
        self.clog("starting: " + " ".join(args))

        def work():
            try:
                self.usque_proc = __import__("subprocess").Popen(
                    args, stdout=__import__("subprocess").PIPE,
                    stderr=__import__("subprocess").STDOUT, text=True, errors="replace")
            except OSError as e:
                self.clog(f"cannot run usque: {e}")
                return
            self._set_state_main("connecting")
            threading.Thread(target=self._stream_usque, daemon=True).start()
            time.sleep(1.5)
            self.do_test(after_connect_port=port)

        threading.Thread(target=work, daemon=True).start()

    @mainthread
    def _set_state_main(self, state):
        self._set_state(state)

    def _stream_usque(self):
        p = self.usque_proc
        for line in p.stdout:
            self.clog(line.rstrip())
        self.clog(f"[usque exited with code {p.wait()}]")
        if p is self.usque_proc:
            self._set_state_main("idle")
            self.vpn_connected = False

    def do_test(self, after_connect_port=None):
        bind = self.s_bind.text.strip() or "127.0.0.1"
        port = after_connect_port or (self.s_port.text.strip() or "10820")

        def work():
            try:
                t = core.socks5_trace(bind, port, timeout=20)
                warp = t.get("warp")
                self.clog(f"test: warp={warp} loc={t.get('loc')} ip={core.mask_ip(t.get('ip', '?'))}")
                if warp in ("on", "plus"):
                    self._set_state_main("connected")
                    self._on_tunnel_verified(int(port))
                else:
                    self._set_state_main("error")
            except Exception as e:  # noqa: BLE001
                self.clog(f"test failed: {type(e).__name__}: {e}")
                if self.usque_proc and self.usque_proc.poll() is None:
                    self._set_state_main("error")

        threading.Thread(target=work, daemon=True).start()

    def _on_tunnel_verified(self, port):
        """usque's SOCKS5 proxy is confirmed working -> now ask Android to
        route the WHOLE DEVICE through it via VpnService. This is the step
        that makes the key icon appear; on desktop it's a no-op."""
        if self.vpn_connected:
            return

        def granted(ok):
            if not ok:
                self.clog("VPN permission not granted - only the local SOCKS5 proxy "
                          f"on 127.0.0.1:{port} is running (apps must be set to use it manually).")
                return
            bridge.start_vpn(port)
            bridge.keep_screen_on_and_wakelock()
            self.vpn_connected = True
            self.clog("system VPN tunnel established (key icon should now be visible).")

        bridge.request_vpn_permission(granted)

    def do_disconnect(self):
        if self.usque_proc and self.usque_proc.poll() is None:
            self.usque_proc.terminate()
            self.clog("stopped usque.")
        if self.vpn_connected:
            bridge.stop_vpn()
            self.vpn_connected = False
        self._set_state("idle")

    # ---------------------------------------------------------- Account
    def _build_account(self, parent):
        from kivy.uix.checkbox import CheckBox
        from kivy.uix.boxlayout import BoxLayout as BL

        card = Builder.load_string("Card:\n    id: c")
        row = BL(size_hint_y=None, height='36dp', spacing='8dp')
        self.ac_masque = CheckBox(active=True, size_hint_x=None, width='36dp')
        row.add_widget(self.ac_masque)
        lbl = Label(text="Enroll MASQUE key (needed for usque)", color=(0.85, 0.88, 0.95, 1),
                    halign='left', valign='middle')
        lbl.bind(size=lambda w, *_: setattr(w, 'text_size', w.size))
        row.add_widget(lbl)
        card.add_widget(row)

        self.ac_proxy = Builder.load_string(
            "Field:\n    label: 'Proxy for registration (optional)'\n"
            "    hint: 'socks5h://127.0.0.1:10808'")
        card.add_widget(self.ac_proxy)

        btn_row = BL(size_hint_y=None, height='46dp', spacing='8dp')
        btn_reg = Builder.load_string("BigButton:\n    text: 'Get new WARP key'")
        btn_reg.bind(on_release=lambda *_: self.on_register())
        btn_save = Builder.load_string("GhostButton:\n    text: 'Save'")
        btn_save.bind(on_release=lambda *_: self.save_account_json())
        btn_row.add_widget(btn_reg)
        btn_row.add_widget(btn_save)
        card.add_widget(btn_row)
        self.btn_reg = btn_reg
        parent.add_widget(card)

        out_card = Builder.load_string("Card:\n    id: c")
        out_card.add_widget(Builder.load_string("SectionLabel:\n    text: 'Account JSON'"))
        self.account_out = log_box(12)
        self.account_out.text = "Press \u201cGet new WARP key\u201d to create an account."
        out_card.add_widget(self.account_out)
        parent.add_widget(out_card)

    def on_register(self):
        self.btn_reg.disabled = True
        self.btn_reg.text = "Registering…"
        masque = self.ac_masque.active
        proxy = self.ac_proxy.text.strip()

        def work():
            try:
                res = core.register_warp(masque, proxy)
                self._register_done(res, None)
            except Exception as e:  # noqa: BLE001
                self._register_done(None, str(e))

        threading.Thread(target=work, daemon=True).start()

    @mainthread
    def _register_done(self, res, err):
        self.btn_reg.disabled = False
        self.btn_reg.text = "Get new WARP key"
        if err:
            self.account_out.text = f"Error: {err}"
            return
        self.account = res
        self.account_out.text = json.dumps(res, indent=2)
        # save config.json for usque immediately
        try:
            cfg = res.get("config", {})
            cfg["endpoint_pub_key"] = cfg.get("endpoint_pub_key", "")
            with open(self.cfg_path, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=2)
            self.clog(f"saved {self.cfg_path}")
        except Exception as e:  # noqa: BLE001
            self.clog(f"could not save config.json: {e}")

    def save_account_json(self):
        if not self.account:
            return
        p = os.path.join(self.base, "warp-account.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(self.account, fh, indent=2)
        self.clog(f"saved {p}")

    # ---------------------------------------------------------- Link
    def _build_link(self, parent):
        from kivy.uix.spinner import Spinner
        from kivy.uix.boxlayout import BoxLayout as BL

        card = Builder.load_string("Card:\n    id: c")
        self.lv = {}
        specs = [("protocol", ["masque", "wireguard"]), ("scan", ["fast", "balanced", "deep"]),
                 ("ip", ["v4", "v6"]), ("transport", ["h2", "h3"])]
        for key, opts in specs:
            row = BL(size_hint_y=None, height='52dp', spacing='8dp')
            lbl = Label(text=key, size_hint_x=0.3, color=(0.55, 0.6, 0.78, 1))
            sp = Spinner(text=opts[0], values=opts)
            sp.bind(text=lambda *_: self._gen_link())
            self.lv[key] = sp
            row.add_widget(lbl)
            row.add_widget(sp)
            card.add_widget(row)
        self.lv_name = Builder.load_string("Field:\n    label: 'Name'\n    text: 'my-config'")
        self.lv_name.ids.ti.bind(text=lambda *_: self._gen_link())
        card.add_widget(self.lv_name)
        self.link_field = Builder.load_string("Field:\n    label: 'aether:// link'")
        card.add_widget(self.link_field)
        btn_row = BL(size_hint_y=None, height='46dp', spacing='8dp')
        b1 = Builder.load_string("BigButton:\n    text: 'Copy link'")
        b1.bind(on_release=lambda *_: self._copy(self.link_field.text))
        b2 = Builder.load_string("GhostButton:\n    text: 'Parse into fields'")
        b2.bind(on_release=lambda *_: self._load_link())
        btn_row.add_widget(b1)
        btn_row.add_widget(b2)
        card.add_widget(btn_row)
        parent.add_widget(card)

    def _gen_link(self, *_):
        try:
            link = core.build_link(self.lv["protocol"].text, self.lv["scan"].text,
                                    self.lv["ip"].text, self.lv["transport"].text,
                                    self.lv_name.text)
            self.link_field.text = link
        except Exception:
            pass

    def _load_link(self):
        try:
            d = core.parse_link(self.link_field.text)
        except ValueError as e:
            self.clog(str(e))
            return
        for k, v in d.items():
            if k in self.lv:
                self.lv[k].text = v
            elif k == "name":
                self.lv_name.text = v

    def _copy(self, text):
        from kivy.core.clipboard import Clipboard
        Clipboard.copy(text)

    # ---------------------------------------------------------- Scan
    def _build_scan(self, parent):
        from kivy.uix.boxlayout import BoxLayout as BL
        from kivy.uix.progressbar import ProgressBar

        card = Builder.load_string("Card:\n    id: c")
        self.e_prefix = Builder.load_string(
            "Field:\n    label: 'IP prefixes, comma separated'\n    text: '162.159.198'")
        card.add_widget(self.e_prefix)
        btn_row = BL(size_hint_y=None, height='46dp', spacing='8dp')
        self.btn_scan = Builder.load_string("BigButton:\n    text: 'Scan & verify'")
        self.btn_scan.bind(on_release=lambda *_: self.on_scan())
        btn_use = Builder.load_string("GhostButton:\n    text: 'Use selected'")
        btn_use.bind(on_release=lambda *_: self.use_selected())
        btn_row.add_widget(self.btn_scan)
        btn_row.add_widget(btn_use)
        card.add_widget(btn_row)
        self.scan_status = Label(text="Finds WARP endpoint IPs presenting the pinned key.",
                                  color=(0.55, 0.6, 0.78, 1), size_hint_y=None, height='40dp',
                                  halign='left', valign='top')
        self.scan_status.bind(size=lambda w, *_: setattr(w, 'text_size', w.size))
        card.add_widget(self.scan_status)
        parent.add_widget(card)

        res_card = Builder.load_string("Card:\n    id: c")
        res_card.add_widget(Builder.load_string("SectionLabel:\n    text: 'Results (tap to select)'"))
        from kivy.uix.gridlayout import GridLayout
        self.results_grid = GridLayout(cols=1, size_hint_y=None, spacing='2dp')
        self.results_grid.bind(minimum_height=self.results_grid.setter('height'))
        res_card.add_widget(self.results_grid)
        parent.add_widget(res_card)

    def on_scan(self):
        try:
            pin = core.pin_from_config(self.cfg_path)
        except Exception as e:  # noqa: BLE001
            self.scan_status.text = f"cannot read config.json: {e}"
            return
        prefixes = [p.strip() for p in self.e_prefix.text.split(",") if p.strip()]
        if not prefixes:
            return
        self.btn_scan.disabled = True
        self.btn_scan.text = "Scanning…"
        self.scan_status.text = f"scanning {len(prefixes) * 254} hosts…"

        def work():
            res = core.scan_prefixes(prefixes, pin, core.SNI)
            self._scan_done(res)

        threading.Thread(target=work, daemon=True).start()

    @mainthread
    def _scan_done(self, res):
        self.btn_scan.disabled = False
        self.btn_scan.text = "Scan & verify"
        self.scan_rows = res[:60]
        self.selected_row = None
        good = [r for r in res if r[2]]
        self.scan_status.text = f"{len(res)} answered, {len(good)} verified (pinned key OK)."
        self.results_grid.clear_widgets()
        for i, (ip, ms, ok) in enumerate(self.scan_rows):
            btn = Button(text=f"{i+1:02d}  {ip}   {ms:.0f} ms   {'VERIFIED' if ok else 'mismatch'}",
                         size_hint_y=None, height='34dp',
                         background_normal='', background_down='',
                         background_color=(0.08, 0.3, 0.2, 1) if ok else (0.3, 0.1, 0.1, 1),
                         color=(0.9, 0.95, 0.9, 1))
            btn.row_index = i
            btn.bind(on_release=self._select_row)
            self.results_grid.add_widget(btn)

    def _select_row(self, btn):
        self.selected_row = self.scan_rows[btn.row_index]

    def use_selected(self):
        if not self.selected_row:
            self.clog("select a result row first")
            return
        ip, _ms, ok = self.selected_row
        if not ok:
            self.clog("that IP does not present the pinned key")
            return
        try:
            with open(self.cfg_path, encoding="utf-8") as fh:
                data = json.load(fh)
            with open(self.cfg_path + ".bak", "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            data.setdefault("config", {})
            data["config"]["endpoint_h2_v4"] = ip
            data["config"]["endpoint_v4"] = ip
            with open(self.cfg_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as e:  # noqa: BLE001
            self.clog(f"could not update config: {e}")
            return
        self.clog(f"endpoint set to {ip} (backup saved). Reconnect to apply.")

    # ---------------------------------------------------------- Settings
    def _build_settings(self, parent):
        from kivy.uix.checkbox import CheckBox
        from kivy.uix.spinner import Spinner
        from kivy.uix.boxlayout import BoxLayout as BL

        card = Builder.load_string("Card:\n    id: c")
        self.s_bind = Builder.load_string("Field:\n    label: 'Bind address'\n    text: '127.0.0.1'")
        self.s_port = Builder.load_string("Field:\n    label: 'SOCKS port'\n    text: '10820'")
        self.s_sni = Builder.load_string(f"Field:\n    label: 'SNI'\n    hint: '{core.SNI}'")
        self.s_extra = Builder.load_string("Field:\n    label: 'Extra usque args'")
        for f in (self.s_bind, self.s_port, self.s_sni, self.s_extra):
            card.add_widget(f)

        row = BL(size_hint_y=None, height='52dp', spacing='8dp')
        row.add_widget(Label(text="mode", size_hint_x=0.3, color=(0.55, 0.6, 0.78, 1)))
        self.s_mode_spinner = Spinner(text="socks", values=["socks", "l4-socks"])
        self.s_mode_spinner.bind(text=lambda sp, v: setattr(self, "s_mode", v))
        self.s_mode = "socks"
        row.add_widget(self.s_mode_spinner)
        card.add_widget(row)

        h2row = BL(size_hint_y=None, height='36dp', spacing='8dp')
        self.s_h2 = CheckBox(active=True, size_hint_x=None, width='36dp')
        h2row.add_widget(self.s_h2)
        lbl = Label(text="HTTP/2 over TCP (--http2, use if QUIC/UDP is blocked)",
                    color=(0.85, 0.88, 0.95, 1), halign='left', valign='middle')
        lbl.bind(size=lambda w, *_: setattr(w, 'text_size', w.size))
        h2row.add_widget(lbl)
        card.add_widget(h2row)

        btn_save = Builder.load_string("BigButton:\n    text: 'Save settings'")
        btn_save.bind(on_release=lambda *_: self._save_settings())
        card.add_widget(btn_save)
        parent.add_widget(card)

    def _load_settings(self):
        data = core.load_settings(self.settings_path)
        if not data:
            return
        self.s_bind.text = data.get("bind", self.s_bind.text)
        self.s_port.text = data.get("port", self.s_port.text)
        self.s_sni.text = data.get("sni", self.s_sni.text)
        self.s_extra.text = data.get("extra", self.s_extra.text)
        self.s_mode_spinner.text = data.get("mode", self.s_mode_spinner.text)
        self.s_h2.active = bool(data.get("http2", True))

    def _save_settings(self):
        data = {"bind": self.s_bind.text, "port": self.s_port.text, "sni": self.s_sni.text,
                "extra": self.s_extra.text, "mode": self.s_mode_spinner.text, "http2": self.s_h2.active}
        core.save_settings(data, self.settings_path)
        self.clog("settings saved")


from kivy.uix.button import Button  # noqa: E402  (used in _scan_done)

if __name__ == "__main__":
    AetherApp().run()
