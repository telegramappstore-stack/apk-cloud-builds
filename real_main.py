"""ProxyScout - finds proxies / V2Ray configs, verifies them for real, and connects through them as a VPN
(Android VpnService + bundled Xray core). On a PC it runs with a simulated connection."""
import os
import threading
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, RoundedRectangle
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget
from kivy.utils import platform

import engine as en
import proxycore as pc
import xraytest as xt

MAX_TEST = 400           # servers tested per scan
V2_VERIFY_MAX = 120      # V2Ray configs verified with the Xray core per scan
MAX_SHOWN = 80
HIST = 60                # seconds in the speed graph
GREEN, AMBER, ORANGE = [0.25, 0.85, 0.55, 1], [0.98, 0.78, 0.30, 1], [0.98, 0.55, 0.30, 1]
RED, GREY, BLUE = [0.95, 0.35, 0.40, 1], [0.50, 0.55, 0.68, 1], [0.30, 0.55, 1.0, 1]
SURF, SURF2 = [0.085, 0.11, 0.18, 1], [0.14, 0.17, 0.27, 1]

KV = r"""
#:import dp kivy.metrics.dp
#:import sp kivy.metrics.sp

<LeftLabel@Label>:
    text_size: self.width, None
    halign: 'left'
    valign: 'middle'

<WrapLabel@Label>:
    text_size: self.width, None
    size_hint_y: None
    height: self.texture_size[1] + dp(4)
    halign: 'left'

<Card>:
    canvas.before:
        Color:
            rgba: self.bg
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: self.radius

<PillButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    color: 1, 1, 1, 1
    font_size: sp(14)
    canvas.before:
        Color:
            rgba: self.bg if self.state == 'normal' else self.bg_down
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(16)]

<Pill>:
    bold: True
    font_size: sp(13)
    color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgba: self.bg
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(11)]

<Chip@ToggleButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    font_size: sp(13)
    allow_no_selection: False
    color: (1, 1, 1, 1) if self.state == 'down' else (0.55, 0.60, 0.72, 1)
    canvas.before:
        Color:
            rgba: (0.30, 0.55, 1, 1) if self.state == 'down' else (0.085, 0.11, 0.18, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(13)]

<Stat>:
    orientation: 'vertical'
    Label:
        text: root.value
        font_size: sp(19)
        bold: True
        color: root.accent
    Label:
        text: root.caption
        font_size: sp(11)
        color: 0.55, 0.60, 0.72, 1

<ServerRow>:
    size_hint_y: None
    height: dp(66)
    padding: dp(16), dp(8), dp(12), dp(8)
    spacing: dp(10)
    bg: (0.14, 0.17, 0.27, 1) if self.state == 'down' else (0.085, 0.11, 0.18, 1)
    BoxLayout:
        orientation: 'vertical'
        LeftLabel:
            text: root.title
            font_size: sp(16)
            bold: True
            color: 1, 1, 1, 1
        LeftLabel:
            text: root.subtitle
            font_size: sp(12)
            color: 0.55, 0.60, 0.72, 1
    Pill:
        size_hint: None, None
        size: dp(80), dp(30)
        pos_hint: {'center_y': .5}
        text: root.ping_text
        bg: root.ping_bg

<ConnScreen>:
    name: 'conn'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(20), dp(12), dp(20), dp(14)
        spacing: dp(12)
        BoxLayout:
            size_hint_y: None
            height: dp(40)
            spacing: dp(10)
            PillButton:
                size_hint_x: None
                width: dp(80)
                text: 'Back'
                bg: 0.14, 0.17, 0.27, 1
                bg_down: 0.20, 0.24, 0.36, 1
                on_release: app.back_home()
            LeftLabel:
                text: root.title_text
                font_size: sp(15)
                bold: True
                color: 1, 1, 1, 1
        FloatLayout:
            size_hint_y: None
            height: dp(190)
            PowerButton:
                size_hint: None, None
                size: dp(156), dp(156)
                pos_hint: {'center_x': .5, 'center_y': .5}
                color: root.ring
                on_release: app.toggle_connection()
        Label:
            size_hint_y: None
            height: dp(54)
            markup: True
            text: root.big_text
            font_size: sp(22)
            color: root.ring
            halign: 'center'
        BoxLayout:
            size_hint_y: None
            height: dp(54)
            Stat:
                value: root.down_text
                caption: 'Download'
                accent: 0.25, 0.78, 0.95, 1
            Stat:
                value: root.up_text
                caption: 'Upload'
                accent: 0.70, 0.50, 1, 1
            Stat:
                value: root.ping_text
                caption: 'Ping via tunnel'
                accent: 0.25, 0.85, 0.55, 1
        SpeedGraph:
            size_hint_y: None
            height: dp(84)
            down: root.down_hist
            up: root.up_hist
        WrapLabel:
            text: root.detail_text
            font_size: sp(12)
            color: 0.55, 0.60, 0.72, 1
        WrapLabel:
            text: root.error_text
            font_size: sp(11)
            color: 0.95, 0.45, 0.50, 1
        WrapLabel:
            text: root.local_text
            font_size: sp(12)
            color: 0.45, 0.70, 1, 1
        Widget:
        BoxLayout:
            size_hint_y: None
            height: dp(46)
            spacing: dp(10)
            PillButton:
                text: root.local_btn
                bg: 0.14, 0.17, 0.27, 1
                bg_down: 0.20, 0.24, 0.36, 1
                on_release: app.toggle_local()
            PillButton:
                text: 'Copy config'
                bg: 0.14, 0.17, 0.27, 1
                bg_down: 0.20, 0.24, 0.36, 1
                on_release: app.copy_current()

ScreenManager:
    Screen:
        name: 'home'
        BoxLayout:
            orientation: 'vertical'
            padding: dp(20), dp(12), dp(20), dp(14)
            spacing: dp(12)

            BoxLayout:
                size_hint_y: None
                height: dp(46)
                LeftLabel:
                    text: 'ProxyScout'
                    font_size: sp(26)
                    bold: True
                    color: 1, 1, 1, 1
                PillButton:
                    size_hint: None, None
                    size: dp(104), dp(34)
                    pos_hint: {'center_y': .5}
                    text: 'VPN ON'
                    opacity: 1 if app.vpn_on else 0
                    disabled: not app.vpn_on
                    bg: 0.16, 0.62, 0.40, 1
                    bg_down: 0.12, 0.50, 0.32, 1
                    on_release: app.open_conn()

            BoxLayout:
                size_hint_y: None
                height: dp(36)
                spacing: dp(8)
                Chip:
                    text: 'All'
                    group: 'tab'
                    state: 'down'
                    on_state: app.set_tab('all') if self.state == 'down' else None
                Chip:
                    text: 'V2Ray'
                    group: 'tab'
                    on_state: app.set_tab('v2ray') if self.state == 'down' else None
                Chip:
                    text: 'SOCKS5'
                    group: 'tab'
                    on_state: app.set_tab('socks5') if self.state == 'down' else None
                Chip:
                    text: 'HTTP'
                    group: 'tab'
                    on_state: app.set_tab('http') if self.state == 'down' else None

            LeftLabel:
                size_hint_y: None
                height: dp(22)
                text: app.status_text
                font_size: sp(12)
                color: 0.55, 0.60, 0.72, 1

            Widget:
                size_hint_y: None
                height: dp(4)
                canvas:
                    Color:
                        rgba: 0.085, 0.11, 0.18, 1
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [dp(2)]
                    Color:
                        rgba: 0.30, 0.55, 1, 1
                    RoundedRectangle:
                        pos: self.pos
                        size: max(self.height, self.width * app.progress), self.height
                        radius: [dp(2)]

            ScrollView:
                bar_width: dp(3)
                do_scroll_x: False
                BoxLayout:
                    id: rows
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: dp(8)

            BoxLayout:
                size_hint_y: None
                height: dp(54)
                spacing: dp(10)
                PillButton:
                    font_size: sp(16)
                    text: 'Stop' if app.scanning else 'Find servers'
                    bg: (0.92, 0.30, 0.36, 1) if app.scanning else (0.30, 0.55, 1, 1)
                    bg_down: (0.75, 0.22, 0.28, 1) if app.scanning else (0.22, 0.43, 0.88, 1)
                    on_release: app.toggle_scan()
                PillButton:
                    size_hint_x: None
                    width: dp(60)
                    font_size: sp(18)
                    text: '...'
                    bg: 0.14, 0.17, 0.27, 1
                    bg_down: 0.20, 0.24, 0.36, 1
                    on_release: app.open_menu()
    ConnScreen:
        id: conn
"""


def fmt_bytes(n):
    n = float(max(0, n))
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def fmt_time(sec):
    sec = int(max(0, sec))
    return "%02d:%02d:%02d" % (sec // 3600, sec % 3600 // 60, sec % 60)


class Card(BoxLayout):
    bg = ListProperty(SURF)
    radius = ListProperty([dp(16)])


class Stat(BoxLayout):
    value = StringProperty("0")
    caption = StringProperty("")
    accent = ListProperty([1, 1, 1, 1])


class PillButton(Button):
    bg = ListProperty(BLUE)
    bg_down = ListProperty([0.22, 0.43, 0.88, 1])


class Pill(Label):
    bg = ListProperty(GREY)


class PowerButton(ButtonBehavior, Widget):
    color = ListProperty(GREY)

    def __init__(self, **kw):
        super().__init__(**kw)
        for name in ("pos", "size", "color", "state"):
            self.bind(**{name: self._draw})

    def _draw(self, *_):
        self.canvas.clear()
        cx, cy = self.center
        r = min(self.size) / 2.0 - dp(4)
        c = self.color
        with self.canvas:
            Color(c[0], c[1], c[2], 0.22 if self.state == "down" else 0.10)
            Ellipse(pos=(cx - r, cy - r), size=(2 * r, 2 * r))
            Color(*c)
            Line(circle=(cx, cy, r), width=dp(3))
            Line(circle=(cx, cy, r * 0.36, 40, 320), width=dp(4), cap="round")
            Line(points=[cx, cy + r * 0.06, cx, cy + r * 0.52], width=dp(4), cap="round")


class SpeedGraph(Widget):
    down = ListProperty([])
    up = ListProperty([])

    def __init__(self, **kw):
        super().__init__(**kw)
        for name in ("pos", "size", "down", "up"):
            self.bind(**{name: self._draw})

    def _draw(self, *_):
        self.canvas.clear()
        x0, y0 = self.pos
        w, h = self.size
        pad = dp(10)
        with self.canvas:
            Color(*SURF)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(14)])
            peak = max([50000.0] + list(self.down) + list(self.up))
            for data, col in ((self.up, (0.70, 0.50, 1, 1)), (self.down, (0.25, 0.78, 0.95, 1))):
                if len(data) > 1:
                    off, pts = HIST - len(data), []
                    for i, v in enumerate(data):
                        pts += [x0 + pad + (w - 2 * pad) * (off + i) / float(HIST - 1),
                                y0 + pad + (h - 2 * pad) * v / peak]
                    Color(*col)
                    Line(points=pts, width=dp(1.8))


class ServerRow(ButtonBehavior, Card):
    title = StringProperty("")
    subtitle = StringProperty("")
    ping_text = StringProperty("")
    ping_bg = ListProperty(GREY)

    def __init__(self, proxy, **kw):
        super().__init__(**kw)
        self.proxy = proxy
        ms = proxy.ms
        if proxy.kind == "v2ray":
            self.title = (proxy.name or proxy.addr)[:28]
            kind = "%s  %s" % ((proxy.proto or "v2ray").upper(), (proxy.sec or "none").upper())
            verified = bool(proxy.ok_real)
            self.subtitle = kind + ("  verified" if verified else "  unverified")
            self.ping_text = ("%d ms" % ms) if (ms and verified) else "?"
            good = verified and ms
        else:
            self.title = proxy.addr
            self.subtitle = "SOCKS5" if proxy.kind == "socks5" else "HTTP"
            self.ping_text = ("%d ms" % ms) if ms else "-"
            good = ms
        self.ping_bg = [0.2, 0.25, 0.37, 1] if not good else ([0.13, 0.55, 0.36, 1] if ms < 500 else
                                                              [0.70, 0.52, 0.10, 1] if ms < 1200 else [0.75, 0.38, 0.12, 1])
        self.bind(on_release=lambda *_: App.get_running_app().connect_to(self.proxy))


class ConnScreen(Screen):
    title_text = StringProperty("")
    big_text = StringProperty("")
    ring = ListProperty(GREY)
    down_text = StringProperty("0 B/s")
    up_text = StringProperty("0 B/s")
    ping_text = StringProperty("-")
    detail_text = StringProperty("")
    error_text = StringProperty("")
    local_text = StringProperty("")
    local_btn = StringProperty("Local proxy")
    down_hist = ListProperty([])
    up_hist = ListProperty([])


# ------------------------------------------------------------------ Android helpers
def _android_activity():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


def android_share(text):
    from jnius import autoclass, cast
    Intent = autoclass("android.content.Intent")
    String = autoclass("java.lang.String")
    it = Intent()
    it.setAction(Intent.ACTION_SEND)
    it.putExtra(Intent.EXTRA_TEXT, String(text))
    it.setType("text/plain")
    _android_activity().startActivity(Intent.createChooser(it, cast("java.lang.CharSequence", String("Share"))))


def _sort_key(p):
    unverified = p.kind == "v2ray" and not p.ok_real
    return (unverified, p.ms or 10 ** 9)


class ProxyScoutApp(App):
    title = "ProxyScout"
    progress = NumericProperty(0)
    scanning = BooleanProperty(False)
    vpn_on = BooleanProperty(False)
    status_text = StringProperty("Tap 'Find servers' to search.")

    def build(self):
        Window.clearcolor = (0.043, 0.059, 0.10, 1)
        Window.bind(on_keyboard=self._on_key)
        self.working, self.total, self.tested = [], 0, 0
        self.tab = "all"
        self.stop_evt = threading.Event()
        self.ping_busy = False
        self.engine = en.get_engine()
        self.local = xt.LocalProxy()
        self.xray_ok = xt.find_xray() is not None
        self.current = None
        self._last_rx = self._last_tx = 0
        self._last_tick = self._last_ping = 0.0
        self._ping_running, self._direct = False, None
        self._refresh = Clock.create_trigger(self._refresh_list, 0.4)
        return Builder.load_string(KV)

    def on_start(self):
        self.cache_path = os.path.join(self.user_data_dir, "last_scan.json")
        self.working = pc.load_results(self.cache_path)
        if self.working:
            self.status_text = "Last scan: %d servers (not re-tested)." % len(self.working)
        self._refresh_list()
        Clock.schedule_interval(self._tick, 1.0)

    def on_pause(self):
        return True

    def on_stop(self):
        try:
            self.local.stop()
        except Exception:
            pass

    def _on_key(self, window, key, *args):
        if key == 27 and self.root.current == "conn":              # Android back button
            self.back_home()
            return True
        return False

    # ================================================================== list / tabs
    def set_tab(self, tab):
        self.tab = tab
        self._refresh_list()

    def _refresh_list(self, *_):
        rows = self.root.ids.rows
        rows.clear_widgets()
        shown = [p for p in self.working if self.tab == "all" or p.kind == self.tab][:MAX_SHOWN]
        for p in shown:
            rows.add_widget(ServerRow(p))
        if not shown:
            rows.add_widget(Label(text="Nothing here yet.", size_hint_y=None, height=dp(80),
                                  color=(0.5, 0.55, 0.68, 1), font_size=dp(14)))

    # ================================================================== scanning
    def toggle_scan(self):
        if self.scanning:
            self.stop_evt.set()
            self.status_text = "Stopping..."
        else:
            self.scan(False)

    def scan(self, from_clipboard):
        if self.scanning:
            return
        clip = ""
        if from_clipboard:
            try:
                clip = Clipboard.paste() or ""
            except Exception:
                clip = ""
            if not clip.strip():
                self.status_text = "Clipboard is empty. Copy ip:port lines or vless/vmess/trojan/ss links first."
                return
        self.scanning = True
        self.stop_evt = threading.Event()
        self.working, self.total, self.tested = [], 0, 0
        self.progress = 0
        self._refresh_list()
        threading.Thread(target=self._worker, args=(from_clipboard, clip, self.stop_evt), daemon=True).start()

    def _ui(self, fn, *args):
        Clock.schedule_once(lambda dt: fn(*args), 0)

    def _worker(self, from_clipboard, clip, stop):
        kinds = ["socks5", "http", "v2ray"]
        try:
            if from_clipboard:
                cands = pc.parse_proxies(clip, ("socks5", "http")) + pc.parse_v2ray(clip)
            else:
                self._ui(self._say, "Downloading lists (freeproxy.world + V2Ray lists)...")
                cands = pc.fetch_candidates(kinds, log=lambda m: self._ui(self._say, m), stop=stop)
            if stop.is_set():
                return
            if not cands:
                self._ui(self._say, "Nothing downloaded - the sites may be blocked. Copy a list, then ... > Paste list.")
                return
            sample = pc.pick_sample(cands, MAX_TEST)
            self._ui(self._begin, len(sample))
            pend, simple = [], []                                   # collected here: UI callbacks lag behind

            def on_res(p, ok):
                if ok:
                    (pend if p.kind == "v2ray" and self.xray_ok else simple).append(p)
                self._ui(self._result, p, ok)

            pc.test_many(sample, on_res, stop)
            if stop.is_set():
                return
            if pend:                                                # 1) V2Ray: verify with the real Xray core
                pend.sort(key=lambda p: p.ms or 10 ** 9)
                pend = pend[:V2_VERIFY_MAX]
                self._ui(self._say, "Verifying %d V2Ray configs with the Xray core..." % len(pend))
                count = [0]

                def on_real(p, ms):
                    count[0] += 1
                    self._ui(self._verified, p, ms, count[0], len(pend))
                xt.real_delay_many(pend, stop, on_real)
            if simple and not stop.is_set():                        # 2) SOCKS5/HTTP: ping again from this phone
                simple.sort(key=lambda p: p.ms or 10 ** 9)
                top = simple[:40]
                self._ui(self._say, "Measuring real ping (%d best)..." % len(top))
                pc.ping_many(top, lambda p, r: self._ui(self._pinged, p, r), stop, samples=3, workers=16)
        except Exception as e:
            self._ui(self._say, "Error: %s: %s" % (type(e).__name__, e))
        finally:
            self._ui(self._finish, stop)

    def _say(self, text):
        self.status_text = text

    def _begin(self, total):
        self.total = total
        self.status_text = "Testing %d servers..." % total

    def _result(self, p, ok):
        self.tested += 1
        if self.total:
            self.progress = self.tested / float(self.total)
        if ok and not (p.kind == "v2ray" and self.xray_ok):        # V2Ray waits for the real check
            self.working.append(p)
            self.working.sort(key=_sort_key)
            self._refresh()
        self.status_text = "Testing... %d / %d  -  %d passed" % (self.tested, self.total, len(self.working))

    def _verified(self, p, ms, i, n):
        if ms is not None:
            p.ms, p.ok_real = ms, True
            self.working.append(p)
            self.working.sort(key=_sort_key)
            self._refresh()
        self.status_text = "Xray check %d / %d  -  %d V2Ray verified" % (
            i, n, sum(1 for x in self.working if x.kind == "v2ray"))

    def _pinged(self, p, r):
        p.tcp = r["tcp"]
        if r["ms"] is None:
            if p in self.working:
                self.working.remove(p)                             # answered once, then 0/3: flaky
        else:
            p.ms = r["ms"]
        self.working.sort(key=_sort_key)
        self._refresh()

    def _finish(self, stop):
        if stop is not self.stop_evt:
            return
        self.scanning = False
        stopped = stop.is_set()
        if self.total and not stopped:
            self.progress = 1
        self._refresh_list()
        if self.working:
            pc.save_results(self.cache_path, self.working)
        n = len(self.working)
        v2 = sum(1 for x in self.working if x.kind == "v2ray")
        if stopped:
            self.status_text = "Stopped. %d servers." % n
        elif self.tested:
            note = "" if self.xray_ok else "  (V2Ray unverified: Xray core missing)"
            self.status_text = ("%d ready (%d V2Ray verified). Tap one to connect.%s" % (n, v2, note)) if n else \
                "None passed. Search again - free lists change fast."

    def reping(self):
        """Measure again from this phone: SOCKS5/HTTP by timing requests, V2Ray through the Xray core."""
        if self.ping_busy or self.scanning or not self.working:
            self.status_text = "Nothing to ping yet." if not self.working else "Busy..."
            return
        self.ping_busy = True
        evt = threading.Event()
        items = list(self.working[:MAX_SHOWN])
        self.status_text = "Pinging %d servers from this phone..." % len(items)

        def work():
            try:
                simple = [p for p in items if p.kind != "v2ray"]
                v2 = [p for p in items if p.kind == "v2ray" and self.xray_ok]
                if v2:
                    xt.real_delay_many(v2, evt, lambda p, ms: self._ui(self._repinged_v2, p, ms))
                if simple:
                    pc.ping_many(simple, lambda p, r: self._ui(self._pinged, p, r), evt, samples=3, workers=16)
            finally:
                self._ui(self._reping_done)
        threading.Thread(target=work, daemon=True).start()

    def _repinged_v2(self, p, ms):
        if ms is None:
            if p in self.working:
                self.working.remove(p)
        else:
            p.ms, p.ok_real = ms, True
        self.working.sort(key=_sort_key)
        self._refresh()

    def _reping_done(self):
        self.ping_busy = False
        if self.working:
            pc.save_results(self.cache_path, self.working)
        self.status_text = "Ping updated: %d servers answered." % len(self.working)

    # ================================================================== menu
    def open_menu(self):
        mv = ModalView(size_hint=(0.9, None), height=dp(430), background="", background_color=(0, 0, 0, 0.6))
        card = Card(orientation="vertical", padding=dp(16), spacing=dp(10), bg=SURF)
        items = (("Paste a list from the clipboard", lambda: self.scan(True)),
                 ("Re-ping all servers", self.reping),
                 ("Copy Telegram proxy links", lambda: self.copy_all("tg")),
                 ("Copy config list (v2rayNG / NPV)", lambda: self.copy_all("v2ray")),
                 ("Share all", self.share_all))
        for text, fn in items:
            b = PillButton(text=text, size_hint_y=None, height=dp(46), bg=SURF2, bg_down=[0.20, 0.24, 0.36, 1])
            b.bind(on_release=lambda *_, f=fn: (mv.dismiss(), f()))
            card.add_widget(b)
        note = Label(text="SOCKS5/HTTP: freeproxy.world.  V2Ray: public GitHub lists, verified with the Xray core.\n"
                          "Ping is measured by this phone. Free proxies can read unencrypted traffic.",
                     font_size=dp(11), color=(0.5, 0.55, 0.68, 1), halign="center")
        note.bind(size=lambda w, s: setattr(w, "text_size", (s[0], None)))
        card.add_widget(note)
        mv.add_widget(card)
        mv.open()

    # ================================================================== connection screen
    def _conn(self):
        return self.root.ids.conn

    def connect_to(self, proxy):
        if self.engine.state in ("starting", "running"):
            self.engine.disconnect()
        self.current = proxy
        c = self._conn()
        c.down_hist, c.up_hist, c.error_text, c.ping_text = [], [], "", "-"
        c.title_text = (proxy.name or proxy.addr) if proxy.kind == "v2ray" else "%s  %s" % (proxy.kind.upper(), proxy.addr)
        self._last_rx = self._last_tx = 0
        self._last_tick, self._last_ping, self._direct = time.time(), 0.0, None
        self.root.current = "conn"
        self.engine.connect(proxy)
        self._tick(0)

    def open_conn(self):
        if self.current:
            self.root.current = "conn"

    def back_home(self):
        self.root.current = "home"                                 # a running VPN stays on

    def toggle_connection(self):
        if self.engine.state in ("starting", "running"):
            self.engine.disconnect()
        elif self.current:
            self.connect_to(self.current)

    def toggle_local(self):
        """Local proxy (no VPN): SOCKS5 127.0.0.1:10818 + HTTP 127.0.0.1:10819 - for Psiphon's upstream proxy, Telegram, ..."""
        if self.local.state in ("running", "starting"):
            threading.Thread(target=self.local.stop, daemon=True).start()
        elif self.current:
            threading.Thread(target=self.local.start, args=(self.current,), daemon=True).start()

    def copy_current(self):
        if self.current:
            self.copy_text(pc.plain_link(self.current), "Config copied.")
            self._conn().detail_text = "Config copied to the clipboard."

    def _tick(self, dt):
        s = self.engine.poll()
        st = s["state"]
        self.vpn_on = st == "running"
        c = self._conn()
        now = time.time()
        step = max(0.2, now - self._last_tick)
        self._last_tick = now
        if st == "running":
            down = max(0.0, (s["rx"] - self._last_rx) / step)
            up = max(0.0, (s["tx"] - self._last_tx) / step)
            self._last_rx, self._last_tx = s["rx"], s["tx"]
            c.down_hist = (c.down_hist + [down])[-HIST:]
            c.up_hist = (c.up_hist + [up])[-HIST:]
            c.down_text, c.up_text = fmt_bytes(down) + "/s", fmt_bytes(up) + "/s"
            if now - self._last_ping > 6 and not self._ping_running:
                self._ping_running = True
                threading.Thread(target=self._ping_job, daemon=True).start()
        else:
            self._last_rx = self._last_tx = 0
            if st != "starting":
                c.down_text = c.up_text = "0 B/s"
        label, ring = {"stopped": ("Disconnected", GREY), "starting": ("Connecting...", AMBER),
                       "running": ("Connected", GREEN), "error": ("Failed", RED)}.get(st, ("...", GREY))
        c.ring = ring
        c.big_text = "[b]%s[/b]\n[size=15sp]%s[/size]" % (label, fmt_time(s["uptime"]) if st == "running" else
                                                         ("simulation" if self.engine.simulated else "tap the button"))
        if st == "running":
            c.detail_text = "Used: down %s   up %s   | server tcp %s%s" % (
                fmt_bytes(s["rx"]), fmt_bytes(s["tx"]), ("%d ms" % self._direct) if self._direct is not None else "-",
                "   (simulated)" if self.engine.simulated else "")
        elif st == "starting":
            c.detail_text = "Starting the Xray core and the VPN tunnel..."
        elif st == "stopped":
            c.detail_text = ""
        c.error_text = (s["error"] + (("\n" + s["log"][-300:]) if s.get("log") else "")) if st == "error" else ""
        ls = self.local.state
        c.local_btn = "Stop local proxy" if ls in ("running", "starting") else "Local proxy"
        c.local_text = {
            "running": "Local proxy ON\nHTTP    127.0.0.1:%d\nSOCKS5  127.0.0.1:%d\nPsiphon cannot import servers; its only hook is an "
                       "upstream proxy (Settings > Proxy, wording varies by version) - enter the HTTP address above."
                       % (xt.LOCAL_HTTP, xt.LOCAL_SOCKS),
            "starting": "Starting the local proxy...", "error": "Local proxy: " + self.local.error}.get(ls, "")

    def _ping_job(self):
        try:
            via = self.engine.tunnel_ping()
            direct = self.engine.direct_ping()
            self._ui(self._ping_done, via, direct)
        finally:
            self._ping_running = False

    def _ping_done(self, via, direct):
        self._last_ping = time.time()
        self._direct = direct
        self._conn().ping_text = ("%d ms" % via) if via else "no reply"

    # ================================================================== export
    def copy_text(self, text, msg):
        try:
            Clipboard.copy(text)
            self.status_text = msg
        except Exception as e:
            self.status_text = "Copy failed: %s" % e

    def copy_all(self, fmt):
        items = [p for p in self.working if fmt != "v2ray" or p.kind != "v2ray" or p.ok_real or not self.xray_ok][:100]
        text = pc.export_text(items, fmt)
        if not text:
            self.status_text = ("Nothing to export yet - search first." if not items else
                                "Telegram links need SOCKS5 proxies; none found yet.")
            return
        self.copy_text(text, "Copied %d links. Paste into Telegram, or in your VPN app: + > import from clipboard." % len(text.splitlines()))

    def share_all(self):
        text = pc.export_text(self.working[:100], "plain")
        if not text:
            self.status_text = "Nothing to share yet - search first."
            return
        if platform == "android":
            try:
                android_share(text)
                return
            except Exception as e:
                self.status_text = "Share failed (%s) - copied instead." % type(e).__name__
        self.copy_text(text, "Copied %d servers to the clipboard." % len(text.splitlines()))


if __name__ == "__main__":
    ProxyScoutApp().run()
