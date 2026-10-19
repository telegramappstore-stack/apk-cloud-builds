"""Aminium - find free proxies / V2Ray configs, test them against your real internet, connect with the built-in Xray core.

Connect modes
  VPN          whole phone goes through the proxy (Android VpnService + tun2socks + Xray)
  Local proxy  Xray listens on 127.0.0.1:10808 (SOCKS5) / :10809 (HTTP) for apps like Telegram or Psiphon
"""
import math
import os
import threading
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, Rectangle
from kivy.graphics.texture import Texture
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget

import androidbridge as ab
import proxycore as pc
import xraycore as xc

MAX_TEST = 400
MAX_SHOWN = 60
HISTORY = 60                     # seconds of speed graph


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def fmt_rate(n):
    return fmt_bytes(n) + "/s"


def fmt_clock(sec):
    sec = int(sec)
    return "%02d:%02d:%02d" % (sec // 3600, sec // 60 % 60, sec % 60)


# ------------------------------------------------------------------ textures (generated, no image files needed)
def _texture(w, h, fn):
    tex = Texture.create(size=(w, h), colorfmt="rgba")
    buf = bytearray()
    for y in range(h):
        for x in range(w):
            buf += bytes(fn(x / float(max(1, w - 1)), y / float(max(1, h - 1))))
    tex.blit_buffer(bytes(buf), colorfmt="rgba", bufferfmt="ubyte")
    tex.mag_filter = "linear"
    tex.min_filter = "linear"
    return tex


_cache = {}


def glow_texture():
    if "glow" not in _cache:
        def fn(u, v):
            d = math.hypot(u - 0.5, v - 0.5) * 2.0
            return (255, 255, 255, int(max(0.0, 1.0 - d) ** 2 * 255))
        _cache["glow"] = _texture(64, 64, fn)
    return _cache["glow"]


def sky_texture():
    if "sky" not in _cache:
        def fn(u, v):                       # v: 0 bottom .. 1 top
            return (int(5 + 12 * v), int(7 + 8 * v), int(18 + 30 * v), 255)
        _cache["sky"] = _texture(2, 64, fn)
    return _cache["sky"]


KV = r"""
#:import dp kivy.metrics.dp
#:import sp kivy.metrics.sp
#:import FadeTransition kivy.uix.screenmanager.FadeTransition

<LeftLabel@Label>:
    text_size: self.width, None
    halign: 'left'
    valign: 'middle'

<Glass>:
    canvas.before:
        Color:
            rgba: 1, 1, 1, self.fill
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(18)]
        Color:
            rgba: 1, 1, 1, self.edge
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(18)
            width: 1

<PillButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    color: 1, 1, 1, 1
    font_size: sp(14)
    canvas.before:
        Color:
            rgba: self.bg[0], self.bg[1], self.bg[2], self.glow
        RoundedRectangle:
            pos: self.x - dp(3), self.y - dp(3)
            size: self.width + dp(6), self.height + dp(6)
            radius: [dp(17)]
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
    font_size: sp(14)
    color: (1, 1, 1, 1) if self.state == 'down' else (0.62, 0.68, 0.80, 1)
    canvas.before:
        Color:
            rgba: (0.18, 0.55, 1, 0.9) if self.state == 'down' else (1, 1, 1, 0.07)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(13)]

<StatCard>:
    orientation: 'vertical'
    padding: dp(4), dp(8)
    Label:
        text: root.value
        font_size: sp(21)
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
        size: dp(92), dp(42)
        pos_hint: {'center_y': .5}
        text: 'Connect'
        bg: 0.18, 0.55, 1, 1
        bg_down: 0.12, 0.42, 0.85, 1
        glow: 0.22
        on_release: root.on_connect()
    PillButton:
        size_hint: None, None
        size: dp(58), dp(42)
        pos_hint: {'center_y': .5}
        text: 'More'
        bg: 0.20, 0.24, 0.38, 1
        bg_down: 0.26, 0.31, 0.46, 1
        glow: 0
        on_release: root.on_more()

<LiveBadge>:
    size_hint: None, None
    size: dp(132), dp(34)
    text: 'CONNECTED'
    bold: True
    font_size: sp(12)
    color: 0.25, 0.92, 0.62, 1
    canvas.before:
        Color:
            rgba: 0.25, 0.92, 0.62, 0.14
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(17)]
        Color:
            rgba: 0.25, 0.92, 0.62, 0.35 + 0.65 * app.pulse
        Ellipse:
            pos: self.x + dp(12), self.center_y - dp(4)
            size: dp(8), dp(8)

<HomeScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(16), dp(12), dp(16), dp(10)
        spacing: dp(10)

        BoxLayout:
            orientation: 'vertical'
            size_hint_y: None
            height: dp(62)
            LeftLabel:
                text: '[color=ffffff]Amin[/color][color=45e0ff]ium[/color]'
                markup: True
                font_size: sp(32)
                bold: True
            LeftLabel:
                text: 'Find, test and connect - free proxies and V2Ray'
                font_size: sp(12)
                color: 0.62, 0.68, 0.80, 1

        BoxLayout:
            size_hint_y: None
            height: dp(74)
            spacing: dp(8)
            StatCard:
                value: str(app.n_found)
                caption: 'found'
                accent: 0.62, 0.68, 0.80, 1
            StatCard:
                value: str(app.n_tested)
                caption: 'tested'
                accent: 0.98, 0.78, 0.30, 1
            StatCard:
                value: str(app.n_working)
                caption: 'passed'
                accent: 0.25, 0.90, 0.60, 1
            StatCard:
                value: app.direct_text
                caption: 'your ping'
                accent: 0.35, 0.88, 1, 1

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
                bg: 0.20, 0.24, 0.38, 1
                bg_down: 0.26, 0.31, 0.46, 1
                glow: 0
                on_release: app.scan(True)

        PillButton:
            size_hint_y: None
            height: dp(54)
            font_size: sp(17)
            text: 'STOP' if app.scanning else 'SCAN FOR PROXIES'
            bg: (0.95, 0.32, 0.40, 1) if app.scanning else (0.18, 0.55, 1, 1)
            bg_down: (0.78, 0.24, 0.30, 1) if app.scanning else (0.12, 0.42, 0.85, 1)
            glow: (0.12 + 0.25 * app.pulse) if app.scanning else 0.2
            on_release: app.toggle_scan()

        Widget:
            size_hint_y: None
            height: dp(6)
            canvas:
                Color:
                    rgba: 1, 1, 1, 0.08
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(3)]
                Color:
                    rgba: 0.30, 0.85, 1, 1
                RoundedRectangle:
                    pos: self.pos
                    size: max(self.height, self.width * app.progress), self.height
                    radius: [dp(3)]

        LeftLabel:
            size_hint_y: None
            height: dp(34)
            text: app.status_text
            font_size: sp(12)
            color: 0.62, 0.68, 0.80, 1

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
            height: dp(48)
            spacing: dp(8)
            PillButton:
                text: 'Telegram links'
                bg: 0.20, 0.24, 0.38, 1
                bg_down: 0.26, 0.31, 0.46, 1
                glow: 0
                on_release: app.copy_all('tg')
            PillButton:
                text: 'Config list'
                bg: 0.20, 0.24, 0.38, 1
                bg_down: 0.26, 0.31, 0.46, 1
                glow: 0
                on_release: app.copy_all('v2ray')
            PillButton:
                text: 'Share all'
                bg: 0.20, 0.24, 0.38, 1
                bg_down: 0.26, 0.31, 0.46, 1
                glow: 0
                on_release: app.share_all()

        LeftLabel:
            size_hint_y: None
            height: dp(30)
            text: 'Free public proxies are slow, short-lived and can read unencrypted traffic. Do not use them for banking or logins.'
            font_size: sp(10)
            color: 0.45, 0.50, 0.62, 1

<LiveScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(20), dp(16), dp(20), dp(18)
        spacing: dp(12)

        BoxLayout:
            size_hint_y: None
            height: dp(54)
            spacing: dp(8)
            BoxLayout:
                orientation: 'vertical'
                LeftLabel:
                    text: app.live_title
                    font_size: sp(18)
                    bold: True
                    color: 1, 1, 1, 1
                LeftLabel:
                    text: app.live_sub
                    font_size: sp(12)
                    color: 0.62, 0.68, 0.80, 1
            LiveBadge:
                pos_hint: {'center_y': .5}

        Orb:
            t: app.anim_t
            Label:
                pos_hint: {'center_x': .5, 'center_y': .54}
                size_hint: None, None
                size: dp(200), dp(50)
                text: app.live_timer
                font_size: sp(34)
                bold: True
                color: 1, 1, 1, 1
            Label:
                pos_hint: {'center_x': .5, 'center_y': .40}
                size_hint: None, None
                size: dp(200), dp(24)
                text: 'connected time'
                font_size: sp(12)
                color: 0.62, 0.68, 0.80, 1

        BoxLayout:
            size_hint_y: None
            height: dp(78)
            spacing: dp(10)
            Glass:
                orientation: 'vertical'
                padding: dp(10), dp(6)
                Label:
                    text: 'DOWNLOAD'
                    font_size: sp(10)
                    color: 0.35, 0.88, 1, 1
                    bold: True
                Label:
                    text: app.live_down
                    font_size: sp(20)
                    bold: True
                Label:
                    text: app.live_tot_down
                    font_size: sp(11)
                    color: 0.62, 0.68, 0.80, 1
            Glass:
                orientation: 'vertical'
                padding: dp(10), dp(6)
                Label:
                    text: 'UPLOAD'
                    font_size: sp(10)
                    color: 0.70, 0.55, 1, 1
                    bold: True
                Label:
                    text: app.live_up
                    font_size: sp(20)
                    bold: True
                Label:
                    text: app.live_tot_up
                    font_size: sp(11)
                    color: 0.62, 0.68, 0.80, 1

        BoxLayout:
            size_hint_y: None
            height: dp(62)
            spacing: dp(10)
            Glass:
                orientation: 'vertical'
                padding: dp(10), dp(4)
                Label:
                    text: app.live_total
                    font_size: sp(18)
                    bold: True
                    color: 0.25, 0.90, 0.60, 1
                Label:
                    text: 'used this session'
                    font_size: sp(11)
                    color: 0.62, 0.68, 0.80, 1
            Glass:
                orientation: 'vertical'
                padding: dp(10), dp(4)
                Label:
                    text: app.live_ping
                    font_size: sp(18)
                    bold: True
                    color: 0.98, 0.78, 0.30, 1
                Label:
                    text: 'ping through tunnel'
                    font_size: sp(11)
                    color: 0.62, 0.68, 0.80, 1

        Glass:
            size_hint_y: None
            height: dp(96)
            padding: dp(8)
            Graph:
                id: graph

        Glass:
            size_hint_y: None
            height: dp(76) if app.live_mode == 'proxy' else 0
            opacity: 1 if app.live_mode == 'proxy' else 0
            disabled: app.live_mode != 'proxy'
            padding: dp(12), dp(8)
            spacing: dp(8)
            LeftLabel:
                text: 'Local proxy ready\nSOCKS5 127.0.0.1:10808   HTTP 127.0.0.1:10809'
                font_size: sp(11)
                color: 0.80, 0.86, 1, 1
            PillButton:
                size_hint: None, None
                size: dp(78), dp(40)
                pos_hint: {'center_y': .5}
                text: 'Copy'
                bg: 0.20, 0.24, 0.38, 1
                bg_down: 0.26, 0.31, 0.46, 1
                glow: 0
                on_release: app.copy_text('127.0.0.1:10809', 'HTTP proxy address copied: 127.0.0.1:10809')
            PillButton:
                size_hint: None, None
                size: dp(92), dp(40)
                pos_hint: {'center_y': .5}
                text: 'Psiphon'
                bg: 0.18, 0.55, 1, 1
                bg_down: 0.12, 0.42, 0.85, 1
                glow: 0
                on_release: app.open_psiphon()

        PillButton:
            size_hint_y: None
            height: dp(58)
            font_size: sp(18)
            text: 'DISCONNECT'
            bg: 0.95, 0.32, 0.40, 1
            bg_down: 0.78, 0.24, 0.30, 1
            glow: 0.15 + 0.2 * app.pulse
            on_release: app.disconnect()

FloatLayout:
    Aurora:
        t: app.anim_t
    ScreenManager:
        id: sm
        transition: FadeTransition(duration=0.22)
        HomeScreen:
            name: 'home'
        LiveScreen:
            name: 'live'
"""


# ------------------------------------------------------------------ widgets
class Glass(BoxLayout):
    fill = NumericProperty(0.06)
    edge = NumericProperty(0.10)


class StatCard(Glass):
    value = StringProperty("0")
    caption = StringProperty("")
    accent = ListProperty([1, 1, 1, 1])


class PillButton(Button):
    bg = ListProperty([0.18, 0.55, 1, 1])
    bg_down = ListProperty([0.12, 0.42, 0.85, 1])
    glow = NumericProperty(0.18)


class LiveBadge(Label):
    pass


class HomeScreen(Screen):
    pass


class LiveScreen(Screen):
    pass


class Aurora(Widget):
    """Animated backdrop: deep gradient with slow drifting colour glows."""
    t = NumericProperty(0)

    def __init__(self, **kw):
        super().__init__(**kw)
        glow = glow_texture()
        with self.canvas:
            Color(1, 1, 1, 1)
            self._sky = Rectangle(texture=sky_texture())
            self._blobs = []
            for rgba, phase, speed in (((0.10, 0.65, 1.0, 0.30), 0.0, 0.10),
                                       ((0.50, 0.28, 1.0, 0.32), 2.1, 0.08),
                                       ((0.10, 0.90, 0.65, 0.14), 4.2, 0.06)):
                col = Color(*rgba)
                rect = Rectangle(texture=glow, size=(1, 1))
                self._blobs.append((col, rect, phase, speed))
        self.bind(pos=self._layout, size=self._layout, t=self._layout)

    def _layout(self, *_):
        self._sky.pos, self._sky.size = self.pos, self.size
        w, h = self.size
        s = max(w, h) * 0.95
        for _col, rect, phase, speed in self._blobs:
            a = self.t * speed * 6.0 + phase
            cx = self.x + w * (0.5 + 0.36 * math.cos(a))
            cy = self.y + h * (0.5 + 0.38 * math.sin(a * 0.8 + phase))
            rect.pos = (cx - s / 2, cy - s / 2)
            rect.size = (s, s)


class Orb(FloatLayout):
    """The living connection ring: glow, expanding ripples and two spinning arcs."""
    t = NumericProperty(0)

    def __init__(self, **kw):
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw, t=self._draw)

    def _draw(self, *_):
        if self.get_root_window() is None:
            return
        cx, cy = self.center
        r = min(self.width, self.height) * 0.5 * 0.82
        if r <= 0:
            return
        c = self.canvas.before
        c.clear()
        breathe = 0.5 + 0.5 * math.sin(self.t * 2.0)
        with c:
            Color(0.20, 0.85, 1.0, 0.30 + 0.18 * breathe)
            g = r * 3.2
            Rectangle(texture=glow_texture(), pos=(cx - g / 2, cy - g / 2), size=(g, g))
            for i in range(3):
                ph = (self.t * 0.30 + i / 3.0) % 1.0
                Color(0.30, 0.90, 1.0, (1.0 - ph) * 0.30)
                Line(circle=(cx, cy, r * (0.80 + 0.50 * ph)), width=dp(1.4))
            Color(0.05, 0.09, 0.19, 0.92)
            Ellipse(pos=(cx - r * 0.80, cy - r * 0.80), size=(r * 1.60, r * 1.60))
            Color(1, 1, 1, 0.08)
            Line(circle=(cx, cy, r * 0.80), width=dp(5))
            ang = (self.t * 110.0) % 360.0
            Color(0.25, 0.88, 1.0, 1)
            Line(circle=(cx, cy, r * 0.80, ang, ang + 110), width=dp(5), cap="round")
            Color(0.58, 0.40, 1.0, 1)
            Line(circle=(cx, cy, r * 0.80, ang + 180, ang + 260), width=dp(5), cap="round")


class Graph(Widget):
    down = ListProperty([])
    up = ListProperty([])

    def __init__(self, **kw):
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw, down=self._draw, up=self._draw)

    def _draw(self, *_):
        self.canvas.clear()
        if self.width < 4 or self.height < 4:
            return
        peak = max(max(self.down, default=0), max(self.up, default=0), 20 * 1024.0)
        step = self.width / float(HISTORY - 1)
        with self.canvas:
            Color(1, 1, 1, 0.06)
            for i in range(1, 4):
                y = self.y + self.height * i / 4.0
                Line(points=[self.x, y, self.right, y], width=1)
            for series, rgb in ((self.up, (0.58, 0.40, 1.0)), (self.down, (0.30, 0.88, 1.0))):
                if len(series) < 2:
                    continue
                n = len(series)
                pts = []
                for i, v in enumerate(series):
                    pts += [self.right - (n - 1 - i) * step, self.y + 2 + (self.height - 4) * (v / peak)]
                Color(rgb[0], rgb[1], rgb[2], 0.18)
                Line(points=pts, width=dp(4), joint="round")
                Color(rgb[0], rgb[1], rgb[2], 1)
                Line(points=pts, width=dp(1.6), joint="round")


class ProxyRow(Glass):
    title = StringProperty("")
    subtitle = StringProperty("")
    sub_color = ListProperty([0.6, 0.65, 0.75, 1])

    def __init__(self, proxy, **kw):
        super().__init__(**kw)
        self.proxy = proxy
        ms = proxy.ms or 0
        self.sub_color = ([0.25, 0.90, 0.60, 1] if ms < 800 else
                          [0.98, 0.78, 0.30, 1] if ms < 2000 else [0.98, 0.55, 0.30, 1])
        if proxy.kind == "v2ray":
            self.title = (proxy.name or proxy.addr)[:30]
            self.subtitle = "%s  ·  %s  ·  %d ms" % ((proxy.proto or "v2ray").upper(), (proxy.sec or "none").upper(), ms)
        else:
            self.title = proxy.addr
            self.subtitle = "%s  ·  %d ms" % ("SOCKS5" if proxy.kind == "socks5" else "HTTP", ms)

    def on_connect(self):
        App.get_running_app().connect(self.proxy, "vpn")

    def on_more(self):
        App.get_running_app().show_actions(self.proxy)


# ------------------------------------------------------------------ app
class AminiumApp(App):
    title = "Aminium"
    n_found = NumericProperty(0)
    n_tested = NumericProperty(0)
    n_working = NumericProperty(0)
    progress = NumericProperty(0)
    scanning = BooleanProperty(False)
    status_text = StringProperty("Press SCAN to look for working proxies.")
    direct_text = StringProperty("...")
    anim_t = NumericProperty(0)
    pulse = NumericProperty(0)

    connected = BooleanProperty(False)
    connecting = BooleanProperty(False)
    live_mode = StringProperty("")
    live_title = StringProperty("")
    live_sub = StringProperty("")
    live_timer = StringProperty("00:00:00")
    live_down = StringProperty("-")
    live_up = StringProperty("-")
    live_tot_down = StringProperty("")
    live_tot_up = StringProperty("")
    live_total = StringProperty("-")
    live_ping = StringProperty("...")

    # ---------------------------------------------------------------- lifecycle
    def build(self):
        Window.clearcolor = (0.02, 0.03, 0.07, 1)
        self.working = []
        self.total = 0
        self.direct_val = None
        self.xray = None
        self.cur = None
        self.busy = None
        self.stop_evt = threading.Event()
        self._refresh = Clock.create_trigger(self._refresh_list, 0.4)
        self._tick_ev = self._ping_ev = None
        Window.bind(on_keyboard=self._on_key)
        Clock.schedule_interval(self._anim, 1 / 20.0)
        return Builder.load_string(KV)

    @property
    def home(self):
        return self.root.ids.sm.get_screen("home")

    @property
    def live(self):
        return self.root.ids.sm.get_screen("live")

    def _anim(self, dt):
        self.anim_t += dt
        self.pulse = 0.5 + 0.5 * math.sin(self.anim_t * 2.4)

    def _on_key(self, win, key, *args):
        return key == 27 and self.connected          # Back must not leave the connection screen by accident

    def on_start(self):
        self.cache_path = os.path.join(self.user_data_dir, "last_scan.json")
        self.working = pc.load_results(self.cache_path)
        self.n_working = len(self.working)
        if self.working:
            self.status_text = "Showing the last scan (%d proxies, not re-tested). Press SCAN to refresh." % len(self.working)
        self._refresh_list()
        if ab.is_android():
            ab.request_notifications()
        self._measure_direct()

    def on_pause(self):
        return True

    def on_stop(self):
        self.disconnect(quiet=True)

    def _ui(self, fn, *args):
        Clock.schedule_once(lambda dt: fn(*args), 0)

    def _measure_direct(self):
        def work():
            ms = pc.direct_ping()
            self._ui(self._set_direct, ms)
        threading.Thread(target=work, daemon=True).start()

    def _set_direct(self, ms):
        self.direct_val = ms
        self.direct_text = ("%d ms" % ms) if ms else "n/a"

    # ---------------------------------------------------------------- scanning
    def toggle_scan(self):
        if self.scanning:
            self.stop_evt.set()
            self.status_text = "Stopping..."
        else:
            self.scan(False)

    def scan(self, from_clipboard):
        if self.scanning or self.connected or self.connecting:
            return
        ids = self.home.ids
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
        self._measure_direct()
        threading.Thread(target=self._worker, args=(kinds, from_clipboard, clip, self.stop_evt), daemon=True).start()

    def _worker(self, kinds, from_clipboard, clip, stop):
        try:
            if from_clipboard:
                simple = tuple(k for k in kinds if k != "v2ray")
                cands = pc.parse_proxies(clip, simple) if simple else []
                if "v2ray" in kinds:
                    cands += pc.parse_v2ray(clip)
                cands = [p for p in cands if p.kind in kinds]
            else:
                self._ui(self._say, "Downloading proxy lists...")
                cands = pc.fetch_candidates(kinds, log=lambda m: self._ui(self._say, m), stop=stop)
            if stop.is_set():
                return
            if not cands:
                self._ui(self._say, "No proxies found. The list sources may be blocked - copy a list and press 'Paste list'.")
                return
            sample = pc.pick_sample(cands, MAX_TEST)
            self._ui(self._begin, len(cands), len(sample))
            pc.test_many(sample, lambda p, ok: self._ui(self._result, p, ok), stop)
        except Exception as e:
            self._ui(self._say, "Error: %s: %s" % (type(e).__name__, e))
        finally:
            self._ui(self._finish, stop)

    def _say(self, text):
        self.status_text = text

    def _begin(self, found, total):
        self.n_found = found
        self.total = total
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

    def _finish(self, stop):
        if stop is not self.stop_evt:
            return
        self.scanning = False
        stopped = stop.is_set()
        self.progress = 1 if (self.total and not stopped) else self.progress
        self._refresh_list()
        if self.working:
            pc.save_results(self.cache_path, self.working)
        if stopped:
            self.status_text = "Stopped. %d passed." % self.n_working
        elif self.n_tested:
            self.status_text = ("Done: %d passed out of %d tested." % (self.n_working, self.n_tested)
                                if self.n_working else
                                "Done: none of %d passed. Scan again - free lists change fast." % self.n_tested)

    def _refresh_list(self, *_):
        rows = self.home.ids.rows
        rows.clear_widgets()
        for p in self.working[:MAX_SHOWN]:
            rows.add_widget(ProxyRow(p))

    # ---------------------------------------------------------------- connecting
    def _busy_show(self, text):
        self._busy_hide()
        v = ModalView(size_hint=(0.82, None), height=dp(96), auto_dismiss=False,
                      background="", background_color=(0, 0, 0, 0.55))
        box = Glass(fill=0.12, padding=dp(16))
        box.add_widget(Label(text=text, font_size="15sp", halign="center", text_size=(dp(250), None)))
        v.add_widget(box)
        v.open()
        self.busy = v

    def _busy_hide(self):
        if self.busy is not None:
            self.busy.dismiss()
            self.busy = None

    def _label(self, p):
        return (p.name or p.addr) if p.kind == "v2ray" else "%s %s" % ("SOCKS5" if p.kind == "socks5" else "HTTP", p.addr)

    def connect(self, p, mode="vpn", after=None):
        if self.connected or self.connecting or self.scanning:
            return
        binary = ab.xray_binary()
        if not binary:
            where = ab.native_lib_listing() if ab.is_android() else "PC: set AMINIUM_XRAY"
            self.status_text = "Xray core not found - this APK was built without libxray.so. [%s]" % where[:160]
            return
        if mode == "vpn" and not ab.is_android():
            mode = "proxy"
        self.connecting = True
        self._busy_show("Connecting to\n%s ..." % self._label(p)[:34])
        if mode == "vpn":
            try:
                ab.vpn_prepare(lambda ok: Clock.schedule_once(lambda dt: self._after_permission(ok, p, binary, after), 0))
            except Exception as e:
                self._connect_failed("VPN permission request failed: %s" % e)
        else:
            self._start_core(p, binary, "proxy", after)

    def _after_permission(self, ok, p, binary, after):
        if not ok:
            self._connect_failed("VPN permission was denied. Choose 'Local proxy only' if you do not want a VPN.")
            return
        self._start_core(p, binary, "vpn", after)

    def _start_core(self, p, binary, mode, after):
        threading.Thread(target=self._core_worker, args=(p, binary, mode, after), daemon=True).start()

    def _core_worker(self, p, binary, mode, after):
        xr = xc.Xray(binary, self.user_data_dir)
        try:
            xr.start(p, xc.SOCKS_PORT, xc.HTTP_PORT)
            # prove the path works end to end through Xray before we show "connected"
            if pc.check_socks5("127.0.0.1", xc.SOCKS_PORT, timeout=10) is None:
                raise xc.XrayError("it connected but carries no traffic (dead, blocked or wrong credentials). %s" % xr.tail())
        except Exception as e:
            xr.stop()
            self._ui(self._connect_failed, str(e))
            return
        self._ui(self._core_ready, xr, p, mode, after)

    def _connect_failed(self, msg):
        self.connecting = False
        self._busy_hide()
        self.status_text = "Connection failed: %s" % msg[:200]

    def _core_ready(self, xr, p, mode, after):
        self.xray, self.cur = xr, p
        if mode == "vpn":
            try:
                cfg = os.path.join(self.user_data_dir, "tun.yml")
                with open(cfg, "w") as f:
                    f.write(ab.hev_config(xc.SOCKS_PORT))
                ab.start_service("vpn", cfg)
            except Exception as e:
                self._vpn_fallback("could not start the VPN service (%s)" % type(e).__name__, after)
                return
            self._poll_tunnel(0, after)
        else:
            self._start_proxy_service()
            self._go_live("proxy", after)

    def _start_proxy_service(self):
        if ab.is_android():
            try:
                ab.start_service("proxy")                 # foreground notification keeps the core alive in the background
            except Exception:
                pass

    def _poll_tunnel(self, tries, after):
        try:
            running, up, err = ab.tunnel_state()
        except Exception as e:
            self._vpn_fallback("VPN layer missing (%s)" % type(e).__name__, after)
            return
        if up:
            self._go_live("vpn", after)
        elif err or (tries >= 2 and not running) or tries >= 10:
            self._vpn_fallback(err or "the VPN did not come up", after)
        else:
            Clock.schedule_once(lambda dt: self._poll_tunnel(tries + 1, after), 0.6)

    def _vpn_fallback(self, reason, after):
        """The tunnel part failed (usually a missing libhev-socks5-tunnel.so): keep the core and serve as a local proxy."""
        try:
            ab.stop_service()
        except Exception:
            pass
        self._start_proxy_service()
        self._go_live("proxy", after, note="VPN unavailable: %s. Running as local proxy instead." % reason[:120])

    def _go_live(self, mode, after, note=""):
        self.connecting = False
        self._busy_hide()
        self.connected = True
        self.live_mode = mode
        p = self.cur
        self.live_title = self._label(p)[:32]
        self.live_sub = "VPN  ·  whole phone" if mode == "vpn" else "Local proxy  ·  127.0.0.1:%d / %d" % (xc.SOCKS_PORT, xc.HTTP_PORT)
        self.live_timer = "00:00:00"
        self.live_down = self.live_up = "-"
        self.live_tot_down = self.live_tot_up = ""
        self.live_total = "0 B"
        self.live_ping = "..."
        base = ab.traffic_bytes() if ab.is_android() else None
        self._base = base or (0, 0)
        self._have_traffic = base is not None
        self._prev = (0, 0)
        self._t0 = self._tprev = time.monotonic()
        self.live.ids.graph.down = []
        self.live.ids.graph.up = []
        self.root.ids.sm.current = "live"
        if note:
            self.status_text = note
        self._tick_ev = Clock.schedule_interval(self._tick, 1.0)
        self._ping_ev = Clock.schedule_interval(self._ping_live, 6.0)
        Clock.schedule_once(self._ping_live, 1.0)
        if mode == "proxy":
            self.copy_text("127.0.0.1:%d" % xc.HTTP_PORT, "Local proxy ready. HTTP address copied: 127.0.0.1:%d" % xc.HTTP_PORT)
        if after == "psiphon":
            self.open_psiphon()

    def _tick(self, dt):
        if self.xray is not None and not self.xray.alive:
            self.disconnect("The Xray core stopped: %s" % (self.xray.tail() or "unknown reason"))
            return
        now = time.monotonic()
        self.live_timer = fmt_clock(now - self._t0)
        if not self._have_traffic:
            self.live_down = self.live_up = "n/a"
            return
        t = ab.traffic_bytes()
        if t is None:
            return
        rx, tx = max(0, t[0] - self._base[0]), max(0, t[1] - self._base[1])
        span = max(0.2, now - self._tprev)
        dr, ur = max(0, rx - self._prev[0]) / span, max(0, tx - self._prev[1]) / span
        self._prev, self._tprev = (rx, tx), now
        self.live_down, self.live_up = fmt_rate(dr), fmt_rate(ur)
        self.live_tot_down, self.live_tot_up = "total " + fmt_bytes(rx), "total " + fmt_bytes(tx)
        self.live_total = fmt_bytes(rx + tx)
        g = self.live.ids.graph
        g.down = (g.down + [dr])[-HISTORY:]
        g.up = (g.up + [ur])[-HISTORY:]

    def _ping_live(self, *_):
        if not self.connected:
            return

        def work():
            ms = pc.check_socks5("127.0.0.1", xc.SOCKS_PORT, timeout=6)
            self._ui(self._set_ping, ms)
        threading.Thread(target=work, daemon=True).start()

    def _set_ping(self, ms):
        if self.connected:
            self.live_ping = ("%d ms" % ms) if ms else "timeout"

    def disconnect(self, msg=None, quiet=False):
        if not self.connected and self.xray is None:
            return
        for ev in (self._tick_ev, self._ping_ev):
            if ev is not None:
                ev.cancel()
        self._tick_ev = self._ping_ev = None
        used = self.live_total
        was_live = self.connected
        self.connected = self.connecting = False
        self.live_mode = ""
        if ab.is_android():
            try:
                ab.stop_service()
            except Exception:
                pass
        xr, self.xray = self.xray, None
        if xr is not None:
            xr.stop()
        if quiet:
            return
        self._busy_hide()
        self.root.ids.sm.current = "home"
        self.status_text = msg or ("Disconnected. This session used %s in %s." % (used, self.live_timer) if was_live else "Disconnected.")

    # ---------------------------------------------------------------- actions / export
    def show_actions(self, p):
        items = [("Connect  -  VPN (whole phone)", lambda: self.connect(p, "vpn")),
                 ("Connect  -  local proxy only", lambda: self.connect(p, "proxy")),
                 ("Use in Psiphon (via local proxy)", lambda: self.connect(p, "proxy", after="psiphon"))]
        if p.kind == "socks5":
            items.append(("Open in Telegram", lambda: self.open_telegram(p)))
        if p.kind == "v2ray":
            items.append(("Export to v2rayNG / NekoBox / Hiddify", lambda: self.connect_v2ray(p)))
        items.append(("Copy link", lambda: self.copy_text(pc.plain_link(p), "Copied " + (p.name or p.addr))))
        sheet = ModalView(size_hint=(0.9, None), background="", background_color=(0, 0, 0, 0.6))
        box = Glass(orientation="vertical", fill=0.16, padding=dp(14), spacing=dp(8), size_hint_y=None)
        for text, fn in items:
            b = PillButton(text=text, size_hint_y=None, height=dp(46), glow=0, bg=[0.20, 0.24, 0.38, 1], bg_down=[0.26, 0.31, 0.46, 1])
            b.bind(on_release=lambda _b, f=fn: (sheet.dismiss(), f()))
            box.add_widget(b)
        box.height = dp(28) + len(items) * dp(54)
        sheet.height = box.height
        sheet.add_widget(box)
        sheet.open()

    def open_psiphon(self):
        self.copy_text("127.0.0.1:%d" % xc.HTTP_PORT, "HTTP proxy address copied (127.0.0.1:%d)." % xc.HTTP_PORT)
        name = None
        if ab.is_android():
            try:
                name = ab.launch_first(ab.PSIPHON_APPS)
            except Exception:
                name = None
        self.status_text = ("In %s: Settings > Proxy settings > use a custom proxy: host 127.0.0.1, port %d."
                            % (name, xc.HTTP_PORT) if name else
                            "Psiphon is not installed. Proxy is ready at 127.0.0.1:%d (HTTP)." % xc.HTTP_PORT)

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
        self.copy_text(text, "Copied %d links. Paste into Telegram, or in your VPN app: + > import from clipboard."
                       % len(text.splitlines()))

    def share_all(self):
        text = pc.export_text(self.working[:100], "plain")
        if not text:
            self.status_text = "Nothing to share yet - scan first."
            return
        if ab.is_android():
            try:
                ab.share(text)
                return
            except Exception as e:
                self.status_text = "Share failed (%s) - copied instead." % type(e).__name__
        self.copy_text(text, "Copied %d proxies to the clipboard." % len(text.splitlines()))

    def connect_v2ray(self, p):
        """Hands the config to another installed VPN client: copies the link and opens the client."""
        try:
            Clipboard.copy(p.link)
        except Exception as e:
            self.status_text = "Copy failed: %s" % e
            return
        name = None
        if ab.is_android():
            try:
                name = ab.launch_first(ab.V2_APPS)
            except Exception:
                name = None
        self.status_text = ("Config copied. In %s: tap + > Import config from clipboard, then connect." % name if name else
                            "Config copied. Install v2rayNG, NekoBox or Hiddify, then import it from the clipboard.")

    def open_telegram(self, p):
        link = pc.tg_link(p)
        if not link:
            return
        if ab.is_android():
            try:
                ab.view(link)
                return
            except Exception:
                pass
        self.copy_text(pc.tg_web_link(p), "Telegram link copied - open it in Telegram.")


if __name__ == "__main__":
    AminiumApp().run()
