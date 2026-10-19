"""ProxyScout - finds proxies / V2Ray configs, measures their real ping from this phone, and connects through
them as a VPN (Android VpnService + bundled Xray core). On a PC it runs with a simulated connection."""
import os
import threading
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Line, RoundedRectangle
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget
from kivy.utils import platform

import engine as en
import proxycore as pc

MAX_TEST = 400          # proxies tested per scan
MAX_SHOWN = 60
HIST = 60               # seconds of history in the speed graph
GREEN, AMBER, RED, GREY = [0.25, 0.85, 0.55, 1], [0.98, 0.78, 0.30, 1], [0.95, 0.35, 0.40, 1], [0.55, 0.60, 0.72, 1]

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
            radius: [dp(14)]

<Chip@ToggleButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    font_size: sp(13)
    color: (1, 1, 1, 1) if self.state == 'down' else (0.62, 0.68, 0.80, 1)
    canvas.before:
        Color:
            rgba: (0.22, 0.52, 1, 1) if self.state == 'down' else (0.12, 0.15, 0.25, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]

<StatCard>:
    orientation: 'vertical'
    padding: dp(8), dp(8)
    Label:
        text: root.value
        font_size: sp(20)
        bold: True
        color: root.accent
    Label:
        text: root.caption
        font_size: sp(11)
        color: 0.62, 0.68, 0.80, 1

<ProxyRow>:
    size_hint_y: None
    height: dp(70)
    padding: dp(14), dp(8), dp(10), dp(8)
    spacing: dp(8)
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
            color: root.sub_color
    PillButton:
        size_hint: None, None
        size: dp(88), dp(42)
        pos_hint: {'center_y': .5}
        text: 'Connect'
        bg: 0.22, 0.52, 1, 1
        bg_down: 0.16, 0.40, 0.85, 1
        on_release: root.on_connect()
    PillButton:
        size_hint: None, None
        size: dp(62), dp(42)
        pos_hint: {'center_y': .5}
        text: 'Copy'
        bg: 0.18, 0.22, 0.34, 1
        bg_down: 0.24, 0.29, 0.44, 1
        on_release: root.on_copy()

<ConnScreen>:
    name: 'conn'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(16), dp(10), dp(16), dp(10)
        spacing: dp(10)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            PillButton:
                size_hint_x: None
                width: dp(84)
                text: 'Back'
                bg: 0.18, 0.22, 0.34, 1
                bg_down: 0.24, 0.29, 0.44, 1
                on_release: app.back_home()
            LeftLabel:
                text: root.title_text
                font_size: sp(15)
                bold: True
                color: 1, 1, 1, 1
        FloatLayout:
            size_hint_y: None
            height: dp(200)
            canvas:
                Color:
                    rgba: root.ring_dim
                Ellipse:
                    pos: self.center_x - dp(88), self.center_y - dp(88)
                    size: dp(176), dp(176)
                Color:
                    rgba: root.ring
                Line:
                    circle: self.center_x, self.center_y, dp(80)
                    width: dp(5)
            Label:
                markup: True
                text: root.big_text
                font_size: sp(22)
                color: root.ring
                halign: 'center'
        BoxLayout:
            size_hint_y: None
            height: dp(74)
            spacing: dp(10)
            StatCard:
                value: root.down_text
                caption: 'download'
                accent: 0.25, 0.78, 0.95, 1
            StatCard:
                value: root.up_text
                caption: 'upload'
                accent: 0.70, 0.50, 1, 1
            StatCard:
                value: root.ping_text
                caption: 'ping via tunnel'
                accent: 0.25, 0.85, 0.55, 1
        SpeedGraph:
            size_hint_y: None
            height: dp(100)
            down: root.down_hist
            up: root.up_hist
        WrapLabel:
            text: root.detail_text
            font_size: sp(12)
            color: 0.62, 0.68, 0.80, 1
        WrapLabel:
            text: root.error_text
            font_size: sp(11)
            color: 0.95, 0.45, 0.50, 1
        Widget:
        PillButton:
            size_hint_y: None
            height: dp(54)
            font_size: sp(17)
            text: root.btn_text
            bg: root.btn_bg
            bg_down: root.btn_bg_down
            on_release: app.toggle_connection()

ScreenManager:
    Screen:
        name: 'home'
        BoxLayout:
            orientation: 'vertical'
            padding: dp(16), dp(10), dp(16), dp(10)
            spacing: dp(10)

            BoxLayout:
                size_hint_y: None
                height: dp(58)
                BoxLayout:
                    orientation: 'vertical'
                    LeftLabel:
                        text: 'ProxyScout'
                        font_size: sp(28)
                        bold: True
                        color: 1, 1, 1, 1
                    LeftLabel:
                        text: 'Find a proxy, check its real ping, connect'
                        font_size: sp(12)
                        color: 0.62, 0.68, 0.80, 1
                PillButton:
                    size_hint: None, None
                    size: dp(104), dp(36)
                    pos_hint: {'center_y': .5}
                    text: 'VPN ON'
                    opacity: 1 if app.vpn_on else 0
                    disabled: not app.vpn_on
                    bg: 0.16, 0.62, 0.40, 1
                    bg_down: 0.12, 0.50, 0.32, 1
                    on_release: app.open_conn()

            BoxLayout:
                size_hint_y: None
                height: dp(76)
                spacing: dp(10)
                StatCard:
                    value: str(app.n_found)
                    caption: 'candidates'
                    accent: 0.62, 0.68, 0.80, 1
                StatCard:
                    value: str(app.n_tested)
                    caption: 'tested'
                    accent: 0.98, 0.78, 0.30, 1
                StatCard:
                    value: str(app.n_working)
                    caption: 'passed'
                    accent: 0.25, 0.85, 0.55, 1

            BoxLayout:
                size_hint_y: None
                height: dp(42)
                spacing: dp(8)
                Chip:
                    id: chip_socks
                    text: 'SOCKS5'
                    state: 'down'
                Chip:
                    id: chip_http
                    text: 'HTTP'
                    state: 'down'
                Chip:
                    id: chip_v2ray
                    text: 'V2Ray'
                    state: 'down'
                PillButton:
                    size_hint_x: 1.3
                    text: 'Paste list'
                    bg: 0.18, 0.22, 0.34, 1
                    bg_down: 0.24, 0.29, 0.44, 1
                    on_release: app.scan(True)

            PillButton:
                size_hint_y: None
                height: dp(54)
                font_size: sp(17)
                text: 'STOP' if app.scanning else 'SCAN FOR PROXIES'
                bg: (0.92, 0.30, 0.36, 1) if app.scanning else (0.22, 0.52, 1, 1)
                bg_down: (0.75, 0.22, 0.28, 1) if app.scanning else (0.16, 0.40, 0.85, 1)
                on_release: app.toggle_scan()

            Widget:
                size_hint_y: None
                height: dp(6)
                canvas:
                    Color:
                        rgba: 0.12, 0.15, 0.25, 1
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [dp(3)]
                    Color:
                        rgba: 0.25, 0.78, 0.95, 1
                    RoundedRectangle:
                        pos: self.pos
                        size: max(self.height, self.width * app.progress), self.height
                        radius: [dp(3)]

            BoxLayout:
                size_hint_y: None
                height: dp(36)
                spacing: dp(8)
                LeftLabel:
                    text: app.status_text
                    font_size: sp(12)
                    color: 0.62, 0.68, 0.80, 1
                PillButton:
                    size_hint: None, None
                    size: dp(96), dp(32)
                    pos_hint: {'center_y': .5}
                    text: 'Re-ping'
                    bg: 0.18, 0.22, 0.34, 1
                    bg_down: 0.24, 0.29, 0.44, 1
                    on_release: app.reping()

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
                height: dp(46)
                spacing: dp(8)
                PillButton:
                    text: 'Telegram links'
                    bg: 0.18, 0.22, 0.34, 1
                    bg_down: 0.24, 0.29, 0.44, 1
                    on_release: app.copy_all('tg')
                PillButton:
                    text: 'Config list'
                    bg: 0.18, 0.22, 0.34, 1
                    bg_down: 0.24, 0.29, 0.44, 1
                    on_release: app.copy_all('v2ray')
                PillButton:
                    text: 'Share all'
                    bg: 0.18, 0.22, 0.34, 1
                    bg_down: 0.24, 0.29, 0.44, 1
                    on_release: app.share_all()

            LeftLabel:
                size_hint_y: None
                height: dp(40)
                text: 'SOCKS5/HTTP from freeproxy.world, V2Ray from public GitHub lists. Ping = measured by this phone on your own internet. Free proxies can read unencrypted traffic - no banking or logins.'
                font_size: sp(10)
                color: 0.45, 0.50, 0.62, 1
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
    bg = ListProperty([0.10, 0.13, 0.21, 1])
    radius = ListProperty([dp(16)])


class StatCard(Card):
    value = StringProperty("0")
    caption = StringProperty("")
    accent = ListProperty([1, 1, 1, 1])


class PillButton(Button):
    bg = ListProperty([0.22, 0.52, 1, 1])
    bg_down = ListProperty([0.16, 0.40, 0.85, 1])


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
            Color(0.10, 0.13, 0.21, 1)
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


class ProxyRow(Card):
    title = StringProperty("")
    subtitle = StringProperty("")
    sub_color = ListProperty([0.6, 0.65, 0.75, 1])

    def __init__(self, proxy, **kw):
        super().__init__(**kw)
        self.proxy = proxy
        ms = proxy.ms
        self.sub_color = GREY if not ms else (GREEN if ms < 800 else AMBER if ms < 2000 else [0.98, 0.55, 0.30, 1])
        if proxy.kind == "v2ray":
            self.title = (proxy.name or proxy.addr)[:30]
            kind = "%s %s" % ((proxy.proto or "v2ray").upper(), (proxy.sec or "none").upper())
        else:
            self.title = proxy.addr
            kind = "SOCKS5" if proxy.kind == "socks5" else "HTTP"
        parts = [kind, ("ping %d ms" % ms) if ms else "no reply"]
        if proxy.tcp is not None:
            parts.append("tcp %d" % proxy.tcp)
        self.subtitle = "  ·  ".join(parts)

    def on_connect(self):
        App.get_running_app().connect_to(self.proxy)

    def on_copy(self):
        App.get_running_app().copy_text(pc.plain_link(self.proxy), "Copied " + (self.proxy.name or self.proxy.addr))


class ConnScreen(Screen):
    title_text = StringProperty("")
    big_text = StringProperty("")
    ring = ListProperty(GREY)
    ring_dim = ListProperty([0.55, 0.60, 0.72, 0.12])
    down_text = StringProperty("0 B/s")
    up_text = StringProperty("0 B/s")
    ping_text = StringProperty("-")
    detail_text = StringProperty("")
    error_text = StringProperty("")
    btn_text = StringProperty("CONNECT")
    btn_bg = ListProperty([0.22, 0.52, 1, 1])
    btn_bg_down = ListProperty([0.16, 0.40, 0.85, 1])
    down_hist = ListProperty([])
    up_hist = ListProperty([])


# ------------------------------------------------------------------ Android helpers
def _android_activity():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


def android_view(url):
    from jnius import autoclass
    Intent = autoclass("android.content.Intent")
    Uri = autoclass("android.net.Uri")
    _android_activity().startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))


def android_share(text):
    from jnius import autoclass, cast
    Intent = autoclass("android.content.Intent")
    String = autoclass("java.lang.String")
    it = Intent()
    it.setAction(Intent.ACTION_SEND)
    it.putExtra(Intent.EXTRA_TEXT, String(text))
    it.setType("text/plain")
    _android_activity().startActivity(Intent.createChooser(it, cast("java.lang.CharSequence", String("Share proxies"))))


class ProxyScoutApp(App):
    title = "ProxyScout"
    n_found = NumericProperty(0)
    n_tested = NumericProperty(0)
    n_working = NumericProperty(0)
    progress = NumericProperty(0)
    scanning = BooleanProperty(False)
    vpn_on = BooleanProperty(False)
    status_text = StringProperty("Press SCAN to look for working proxies.")

    def build(self):
        Window.clearcolor = (0.04, 0.06, 0.11, 1)
        Window.bind(on_keyboard=self._on_key)
        self.working, self.total = [], 0
        self.stop_evt = threading.Event()
        self.ping_busy = False
        self.engine = en.get_engine()
        self.current = None
        self._last_rx = self._last_tx = 0
        self._last_tick = 0.0
        self._last_ping = 0.0
        self._ping_running = False
        self._direct = None
        self._refresh = Clock.create_trigger(self._refresh_list, 0.4)
        return Builder.load_string(KV)

    def on_start(self):
        self.cache_path = os.path.join(self.user_data_dir, "last_scan.json")
        self.working = pc.load_results(self.cache_path)
        self.n_working = len(self.working)
        if self.working:
            self.status_text = "Showing the last scan (%d, not re-tested). Press SCAN to refresh." % len(self.working)
        self._refresh_list()
        Clock.schedule_interval(self._tick, 1.0)

    def on_pause(self):
        return True

    def _on_key(self, window, key, *args):
        if key == 27 and self.root.current == "conn":              # Android back button
            self.back_home()
            return True
        return False

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
        ids = self.root.ids
        kinds = [k for k, chip in (("socks5", ids.chip_socks), ("http", ids.chip_http),
                                   ("v2ray", ids.chip_v2ray)) if chip.state == "down"]
        if not kinds:
            self.status_text = "Select SOCKS5, HTTP and/or V2Ray first."
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
        self.working = []
        self.n_found = self.n_tested = self.n_working = 0
        self.progress = 0
        self._refresh_list()
        threading.Thread(target=self._worker, args=(kinds, from_clipboard, clip, self.stop_evt), daemon=True).start()

    def _ui(self, fn, *args):
        Clock.schedule_once(lambda dt: fn(*args), 0)

    def _worker(self, kinds, from_clipboard, clip, stop):
        try:
            if from_clipboard:
                simple = tuple(k for k in kinds if k != "v2ray")
                cands = pc.parse_proxies(clip, simple) if simple else []
                if "v2ray" in kinds:
                    cands += pc.parse_v2ray(clip)
                cands = [p for p in cands if p.kind in kinds]
            else:
                self._ui(self._say, "Downloading lists (freeproxy.world for SOCKS5/HTTP)...")
                cands = pc.fetch_candidates(kinds, log=lambda m: self._ui(self._say, m), stop=stop)
            if stop.is_set():
                return
            if not cands:
                self._ui(self._say, "Nothing downloaded. The sites may be blocked - copy a list and press 'Paste list'.")
                return
            sample = pc.pick_sample(cands, MAX_TEST)
            self._ui(self._begin, len(cands), len(sample))
            pc.test_many(sample, lambda p, ok: self._ui(self._result, p, ok), stop)
            if not stop.is_set() and self.working:
                top = list(self.working[:40])
                self._ui(self._say, "Measuring real ping from this phone (%d best)..." % len(top))
                pc.ping_many(top, lambda p, r: self._ui(self._pinged, p, r), stop, samples=3, workers=16)
        except Exception as e:
            self._ui(self._say, "Error: %s: %s" % (type(e).__name__, e))
        finally:
            self._ui(self._finish, stop)

    def _say(self, text):
        self.status_text = text

    def _begin(self, found, total):
        self.n_found, self.total = found, total
        self.status_text = "Testing %d proxies..." % total

    def _result(self, p, ok):
        self.n_tested += 1
        if self.total:
            self.progress = self.n_tested / float(self.total)
        if ok:
            self.working.append(p)
            self.working.sort(key=lambda x: x.ms or 10 ** 9)
            self.n_working = len(self.working)
            self._refresh()
        self.status_text = "Testing... %d / %d tested, %d passed" % (self.n_tested, self.total, self.n_working)

    def _pinged(self, p, r):
        """Result of the 3-sample measurement made by this phone."""
        p.tcp = r["tcp"]
        if r["ms"] is None:
            if p in self.working:
                self.working.remove(p)                             # answered once, then 0/3: flaky, drop it
        else:
            p.ms = r["ms"]
        self.working.sort(key=lambda x: x.ms or 10 ** 9)
        self.n_working = len(self.working)
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
        if stopped:
            self.status_text = "Stopped. %d passed." % self.n_working
        elif self.n_tested:
            self.status_text = ("Done: %d passed (ping measured by this phone, median of 3)." % self.n_working
                                if self.n_working else
                                "Done: none of %d passed. Scan again - free lists change fast." % self.n_tested)

    def reping(self):
        """Measure the ping of the listed proxies again, from this phone's own connection."""
        if self.ping_busy or self.scanning or not self.working:
            self.status_text = "Nothing to ping yet." if not self.working else "Busy..."
            return
        self.ping_busy = True
        evt = threading.Event()
        items = list(self.working[:MAX_SHOWN])
        self.status_text = "Pinging %d proxies from this phone..." % len(items)

        def work():
            try:
                pc.ping_many(items, lambda p, r: self._ui(self._pinged, p, r), evt, samples=3, workers=16)
            finally:
                self._ui(self._reping_done)
        threading.Thread(target=work, daemon=True).start()

    def _reping_done(self):
        self.ping_busy = False
        if self.working:
            pc.save_results(self.cache_path, self.working)
        self.status_text = "Ping updated: %d answered (median of 3, measured by this phone)." % len(self.working)

    def _refresh_list(self, *_):
        rows = self.root.ids.rows
        rows.clear_widgets()
        for p in self.working[:MAX_SHOWN]:
            rows.add_widget(ProxyRow(p))

    # ================================================================== connection screen
    def _conn(self):
        return self.root.ids.conn

    def connect_to(self, proxy):
        if self.engine.state in ("starting", "running"):
            self.engine.disconnect()
        self.current = proxy
        c = self._conn()
        c.down_hist, c.up_hist, c.error_text = [], [], ""
        c.title_text = (proxy.name or proxy.addr) if proxy.kind == "v2ray" else "%s  %s" % (proxy.kind.upper(), proxy.addr)
        c.ping_text = "-"
        self._last_rx = self._last_tx = 0
        self._last_tick = time.time()
        self._last_ping = 0.0
        self._direct = None
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
        label, ring, btn, bg, bgd = {
            "stopped": ("Disconnected", GREY, "CONNECT", [0.22, 0.52, 1, 1], [0.16, 0.40, 0.85, 1]),
            "starting": ("Connecting...", AMBER, "CANCEL", [0.92, 0.30, 0.36, 1], [0.75, 0.22, 0.28, 1]),
            "running": ("Connected", GREEN, "DISCONNECT", [0.92, 0.30, 0.36, 1], [0.75, 0.22, 0.28, 1]),
            "error": ("Failed", RED, "TRY AGAIN", [0.22, 0.52, 1, 1], [0.16, 0.40, 0.85, 1]),
        }.get(st, ("...", GREY, "CONNECT", [0.22, 0.52, 1, 1], [0.16, 0.40, 0.85, 1]))
        c.ring, c.ring_dim = ring, ring[:3] + [0.12]
        c.btn_text, c.btn_bg, c.btn_bg_down = btn, bg, bgd
        c.big_text = "[b]%s[/b]\n[size=15sp]%s[/size]" % (label, fmt_time(s["uptime"]) if st == "running" else
                                                         ("simulation" if self.engine.simulated else " "))
        if st == "running":
            c.detail_text = "Used: down %s   up %s   | server tcp %s%s" % (
                fmt_bytes(s["rx"]), fmt_bytes(s["tx"]), ("%d ms" % self._direct) if self._direct is not None else "-",
                "   (simulated)" if self.engine.simulated else "")
        elif st == "starting":
            c.detail_text = "Starting Xray core and the VPN tunnel..."
        c.error_text = (s["error"] + (("\n" + s["log"][-300:]) if s.get("log") else "")) if st == "error" else ""

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
        items = self.working[:100]
        text = pc.export_text(items, fmt)
        if not text:
            self.status_text = ("Nothing to export yet - scan first." if not items else
                                "Telegram links need SOCKS5 proxies; none found yet.")
            return
        self.copy_text(text, "Copied %d links. Paste into Telegram, or in your VPN app: + > import from clipboard." % len(text.splitlines()))

    def share_all(self):
        text = pc.export_text(self.working[:100], "plain")
        if not text:
            self.status_text = "Nothing to share yet - scan first."
            return
        if platform == "android":
            try:
                android_share(text)
                return
            except Exception as e:
                self.status_text = "Share failed (%s) - copied instead." % type(e).__name__
        self.copy_text(text, "Copied %d proxies to the clipboard." % len(text.splitlines()))


if __name__ == "__main__":
    ProxyScoutApp().run()
