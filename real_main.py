"""
Aminium - Cloudflare panel installer for Android (Python + Kivy).
Core logic lives in core.py (GPL-3.0, ported from BPB-Wizard).
"""
import re
import threading

from kivy.animation import Animation
from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics.texture import Texture
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import (BooleanProperty, ListProperty, NumericProperty,
                             ObjectProperty, StringProperty)
from kivy.uix.behaviors import ButtonBehavior, ToggleButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import FadeTransition, Screen, ScreenManager
from kivy.uix.textinput import TextInput
from kivy.utils import platform

import core


# --------------------------------------------------------------------- helpers
def open_url(url):
    if platform == "android":
        try:
            from jnius import autoclass
            Intent = autoclass("android.content.Intent")
            Uri = autoclass("android.net.Uri")
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            PythonActivity.mActivity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            return
        except Exception:
            pass
    import webbrowser
    webbrowser.open(url)


def make_gradient(c1, c2, w=64, h=64, mode="diag"):
    """RGBA gradient texture. mode: 'v' (top->bottom), 'h' (left->right), 'diag' (TL->BR)."""
    buf = bytearray()
    for y in range(h):  # y = 0 is the bottom row
        for x in range(w):
            if mode == "v":
                t = 1 - y / (h - 1)
            elif mode == "h":
                t = x / (w - 1)
            else:
                t = (x / (w - 1) + (1 - y / (h - 1))) / 2
            buf += bytes(int((c1[i] + (c2[i] - c1[i]) * t) * 255) for i in range(4))
    tex = Texture.create(size=(w, h), colorfmt="rgba")
    tex.blit_buffer(bytes(buf), colorfmt="rgba", bufferfmt="ubyte")
    tex.mag_filter = "linear"
    tex.min_filter = "linear"
    tex.wrap = "clamp_to_edge"
    return tex


def make_glow(size=64):
    """White radial blob whose alpha fades to 0 at the edge (tinted later via Color)."""
    buf = bytearray()
    c = (size - 1) / 2
    for y in range(size):
        for x in range(size):
            d = (((x - c) ** 2 + (y - c) ** 2) ** 0.5) / c
            a = max(0.0, 1.0 - d)
            buf += bytes((255, 255, 255, int(255 * a * a)))
    tex = Texture.create(size=(size, size), colorfmt="rgba")
    tex.blit_buffer(bytes(buf), colorfmt="rgba", bufferfmt="ubyte")
    tex.mag_filter = "linear"
    tex.min_filter = "linear"
    tex.wrap = "clamp_to_edge"
    return tex


# ------------------------------------------------------------------- widgets
class PillButton(ButtonBehavior, Label):
    primary = BooleanProperty(True)


class Seg(ToggleButtonBehavior, Label):
    value = StringProperty("")


class Field(TextInput):
    pass


class StepHead(BoxLayout):
    num = StringProperty("")
    title = StringProperty("")


class PermRow(BoxLayout):
    title = StringProperty("")
    why = StringProperty("")
    status = StringProperty("")
    chip_text = StringProperty("")
    chip_bg = ListProperty([0, 0, 0, 0])
    chip_fg = ListProperty([1, 1, 1, 1])

    def on_status(self, *_):
        text, bg, fg = {
            "checking": ("...", (0.93, 0.94, 0.99, 1), (0.42, 0.44, 0.58, 1)),
            "OK": ("Granted", (0.87, 0.97, 0.90, 1), (0.09, 0.55, 0.25, 1)),
            "MISSING": ("Missing", (0.99, 0.89, 0.89, 1), (0.82, 0.20, 0.22, 1)),
            "n/a": ("Not tested", (0.93, 0.94, 0.99, 1), (0.42, 0.44, 0.58, 1)),
        }.get(self.status, ("", (0, 0, 0, 0), (1, 1, 1, 1)))
        self.chip_text, self.chip_bg, self.chip_fg = text, list(bg), list(fg)


# ------------------------------------------------------------------- screens
class SplashScreen(Screen):
    logo_scale = NumericProperty(0.55)
    logo_alpha = NumericProperty(0)
    text_alpha = NumericProperty(0)
    ring1 = NumericProperty(0)
    ring2 = NumericProperty(0)
    drift = NumericProperty(0)
    progress = NumericProperty(0)
    status = StringProperty("Preparing secure engine")

    def on_enter(self, *_):
        Animation(logo_scale=1, logo_alpha=1, d=0.8, t="out_back").start(self)
        (Animation(d=0.35) + Animation(text_alpha=1, d=0.8, t="out_quad")).start(self)

        a1 = Animation(ring1=1, d=2.2, t="out_quad") + Animation(ring1=0, d=0.01)
        a1.repeat = True
        a1.start(self)
        Clock.schedule_once(self._start_ring2, 1.1)

        drift = Animation(drift=1, d=4, t="in_out_sine") + Animation(drift=-1, d=4, t="in_out_sine")
        drift.repeat = True
        drift.start(self)

        prog = (Animation(d=0.5)
                + Animation(progress=0.35, d=0.9, t="out_quad")
                + Animation(progress=0.72, d=1.1, t="in_out_quad")
                + Animation(progress=1.0, d=0.9, t="in_out_quad"))
        prog.bind(on_complete=lambda *a: Clock.schedule_once(
            lambda dt: App.get_running_app().show_main(), 0.35))
        prog.start(self)

    def _start_ring2(self, *_):
        a2 = Animation(ring2=1, d=2.2, t="out_quad") + Animation(ring2=0, d=0.01)
        a2.repeat = True
        a2.start(self)

    def on_progress(self, _inst, v):
        self.status = ("Preparing secure engine" if v < 0.35
                       else "Loading components" if v < 0.72
                       else "Almost ready")

    def on_leave(self, *_):
        Animation.cancel_all(self)
        Clock.unschedule(self._start_ring2)


class MainScreen(Screen):
    busy = BooleanProperty(False)
    panel_url = StringProperty("")
    log_text = StringProperty("")

    def on_kv_post(self, base_widget):
        self.perm_rows = {}
        for key, level, label, why in core.PERMISSIONS:
            row = PermRow(title=f"{label}  ({level})", why=why)
            self.perm_rows[key] = row
            self.ids.perm_box.add_widget(row)
        self.ids.name_field.text = core.rand_subdomain()
        self._result_card = self.ids.result_card          # strong ref
        self.ids.result_slot.remove_widget(self._result_card)
        self._warned_name = False
        self.log("Welcome to Aminium. Start with step 1.")

    # ---- log / ui helpers (thread-safe)
    @mainthread
    def log(self, msg):
        self.log_text += f"\u2022 {msg}\n"
        Clock.schedule_once(lambda dt: setattr(self.ids.log_scroll, "scroll_y", 0), 0.05)

    @mainthread
    def _set_perm(self, key, status):
        self.perm_rows[key].status = status

    @mainthread
    def _set_accounts(self, accounts):
        box = self.ids.acc_box
        box.clear_widgets()
        for i, (label, acc_id) in enumerate(accounts.items()):
            b = Seg(text=label, value=acc_id, group="acc", allow_no_selection=False)
            if i == 0:
                b.state = "down"
            box.add_widget(b)

    @mainthread
    def _set_url(self, url):
        self.panel_url = url
        self.ids.url_field.text = url
        slot = self.ids.result_slot
        if self._result_card.parent is None:
            self._result_card.opacity = 0
            slot.add_widget(self._result_card)
            Animation(opacity=1, d=0.5).start(self._result_card)
        Clock.schedule_once(lambda dt: setattr(self.ids.scroll, "scroll_y", 0.18), 0.1)

    @mainthread
    def _set_busy(self, v):
        self.busy = v

    def toast(self, msg):
        App.get_running_app().toast(msg)

    def _run(self, fn):
        self._set_busy(True)

        def wrapper():
            try:
                fn()
            except Exception as e:  # network errors, API errors...
                self.log(f"ERROR: {e}")
                self._toast_main(str(e)[:90])
            finally:
                self._set_busy(False)
        threading.Thread(target=wrapper, daemon=True).start()

    @mainthread
    def _toast_main(self, msg):
        self.toast(msg)

    # ---- actions
    def open_cloudflare(self):
        open_url(core.build_token_url())

    def paste_token(self):
        txt = (Clipboard.paste() or "").strip()
        if txt:
            self.ids.token.text = txt
            self.toast("Pasted")

    def toggle_show(self):
        t = self.ids.token
        t.password = not t.password
        self.ids.show_btn.text = "Show" if t.password else "Hide"

    def on_check(self):
        token = self.ids.token.text.strip()
        if not token:
            return self.toast("Paste your API token first")
        self._run(lambda: core.run_check(token, self.log, self._set_perm, self._set_accounts))

    def randomize(self):
        self.ids.name_field.text = core.rand_subdomain()

    def _selected_account(self):
        for w in Seg.get_widgets("acc"):
            if w.state == "down":
                return w.value
        return None

    def on_deploy(self):
        ids = self.ids
        token = ids.token.text.strip()
        name = ids.name_field.text.strip().lower()
        if not token:
            return self.toast("Paste your API token first")
        if not core.NAME_RE.match(name):
            return self.toast("Name: a-z, 0-9 and '-' (not at the start/end)")
        if any(w in name for w in ("bpb", "vpn", "proxy")) and not self._warned_name:
            self._warned_name = True
            return self.toast("Cloudflare may flag this name. Tap Install again to continue")
        acc = self._selected_account()
        if not acc:
            return self.toast("Tap 'Check token' first")

        rename = None
        if ids.seg_rename.state == "down":
            label = ids.label_field.text.strip()
            if not re.fullmatch(r"[A-Za-z0-9 _-]{1,24}", label):
                return self.toast("Rename: letters, digits, space, - and _ (max 24)")
            rename = label

        source = None
        if ids.seg_custom.state == "down":
            source = ids.src_field.text.strip()
            if not source.lower().startswith("https://"):
                return self.toast("Own URL must start with https://")

        dtype = "pages" if ids.seg_pages.state == "down" else "workers"
        save_dir = App.get_running_app().user_data_dir

        def job():
            url = core.run_deploy(token, acc, name, dtype, rename, source, self.log, save_dir)
            self._set_url(url)
        self._run(job)

    def copy_url(self):
        if self.panel_url:
            Clipboard.copy(self.panel_url)
            self.toast("Link copied")

    def open_panel(self):
        if self.panel_url:
            open_url(self.panel_url)


# ------------------------------------------------------------------------ UI
KV = r"""
#:set PRIMARY (0.40, 0.33, 0.96, 1)
#:set CYAN (0.10, 0.74, 0.95, 1)
#:set INK (0.106, 0.122, 0.231, 1)
#:set MUTED (0.42, 0.44, 0.58, 1)
#:set TINT (0.945, 0.953, 0.992, 1)
#:set LINE (0.88, 0.90, 0.97, 1)

<Title@Label>:
    color: INK
    bold: True
    font_size: sp(17)
    size_hint_y: None
    text_size: self.width, None
    height: self.texture_size[1] + dp(2)
    halign: 'left'

<Hint@Label>:
    color: MUTED
    font_size: sp(13)
    markup: True
    size_hint_y: None
    text_size: self.width, None
    height: self.texture_size[1] + dp(2)
    halign: 'left'

<Card@BoxLayout>:
    orientation: 'vertical'
    size_hint_y: None
    height: self.minimum_height
    padding: dp(18)
    spacing: dp(12)
    canvas.before:
        Color:
            rgba: 0.36, 0.38, 0.80, 0.05
        RoundedRectangle:
            pos: self.x - dp(3), self.y - dp(6)
            size: self.width + dp(6), self.height + dp(6)
            radius: [dp(28)]
        Color:
            rgba: 0.36, 0.38, 0.80, 0.07
        RoundedRectangle:
            pos: self.x - dp(1), self.y - dp(3)
            size: self.width + dp(2), self.height + dp(2)
            radius: [dp(25)]
        Color:
            rgba: 1, 1, 1, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(24)]

<PillButton>:
    size_hint_y: None
    height: dp(52)
    bold: True
    font_size: sp(15)
    color: (1, 1, 1, 1) if self.primary else PRIMARY
    opacity: 0.45 if self.disabled else (0.85 if self.state == 'down' else 1)
    canvas.before:
        Color:
            rgba: 1, 1, 1, (1 if self.primary else 0)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [self.height / 2]
            texture: app.tex_bar
        Color:
            rgba: 0.40, 0.33, 0.96, (0 if self.primary else 0.10)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [self.height / 2]

<Seg>:
    size_hint_y: None
    height: dp(46)
    bold: True
    font_size: sp(14)
    halign: 'center'
    valign: 'middle'
    shorten: True
    shorten_from: 'right'
    text_size: self.width - dp(20), self.height
    color: (1, 1, 1, 1) if self.state == 'down' else MUTED
    canvas.before:
        Color:
            rgba: TINT[0], TINT[1], TINT[2], (1 if self.state == 'normal' else 0)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(16)]
        Color:
            rgba: 1, 1, 1, (1 if self.state == 'down' else 0)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(16)]
            texture: app.tex_bar

<Field>:
    multiline: False
    write_tab: False
    background_normal: ''
    background_active: ''
    background_disabled_normal: ''
    background_color: 0, 0, 0, 0
    foreground_color: INK
    disabled_foreground_color: MUTED
    cursor_color: PRIMARY
    hint_text_color: 0.65, 0.67, 0.78, 1
    font_size: sp(15)
    size_hint_y: None
    height: dp(52)
    padding: [dp(16), max(0, (self.height - self.line_height) / 2)]
    opacity: 0.55 if self.disabled else 1
    canvas.before:
        Color:
            rgba: PRIMARY if self.focus else LINE
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(16)]
        Color:
            rgba: (1, 1, 1, 1) if self.focus else TINT
        RoundedRectangle:
            pos: self.x + dp(1.5), self.y + dp(1.5)
            size: self.width - dp(3), self.height - dp(3)
            radius: [dp(14.5)]

<StepHead>:
    size_hint_y: None
    height: dp(34)
    spacing: dp(12)
    Label:
        size_hint_x: None
        width: dp(32)
        text: root.num
        bold: True
        font_size: sp(15)
        color: 1, 1, 1, 1
        canvas.before:
            Color:
                rgba: 1, 1, 1, 1
            Ellipse:
                pos: self.center_x - dp(16), self.center_y - dp(16)
                size: dp(32), dp(32)
                texture: app.tex_brand
    Title:
        text: root.title
        valign: 'middle'
        size_hint_y: 1

<PermRow>:
    size_hint_y: None
    height: dp(50)
    spacing: dp(8)
    BoxLayout:
        orientation: 'vertical'
        Label:
            text: root.title
            color: INK
            bold: True
            font_size: sp(14)
            halign: 'left'
            valign: 'bottom'
            text_size: self.size
        Label:
            text: root.why
            color: MUTED
            font_size: sp(12)
            halign: 'left'
            valign: 'top'
            text_size: self.size
    AnchorLayout:
        size_hint_x: None
        width: dp(86)
        anchor_x: 'right'
        anchor_y: 'center'
        Label:
            size_hint: None, None
            size: dp(82), dp(26)
            text: root.chip_text
            color: root.chip_fg
            bold: True
            font_size: sp(12)
            canvas.before:
                Color:
                    rgba: root.chip_bg
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(13)]

# ------------------------------------------------------------------ splash
<SplashScreen>:
    canvas.before:
        Color:
            rgba: 1, 1, 1, 1
        Rectangle:
            pos: self.pos
            size: self.size
            texture: app.tex_bg
        Color:
            rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.30
        Rectangle:
            texture: app.tex_glow
            size: self.width * 1.5, self.width * 1.5
            pos: self.x - self.width * 0.55 + dp(34) * root.drift, self.top - self.width * 0.85
        Color:
            rgba: CYAN[0], CYAN[1], CYAN[2], 0.32
        Rectangle:
            texture: app.tex_glow
            size: self.width * 1.6, self.width * 1.6
            pos: self.right - self.width * 1.0 - dp(34) * root.drift, self.y - self.width * 0.7
    FloatLayout:
        Widget:
            id: logo
            size_hint: None, None
            size: dp(112) * root.logo_scale, dp(112) * root.logo_scale
            center_x: root.center_x
            center_y: root.center_y + dp(70)
            opacity: root.logo_alpha
            canvas.before:
                Color:
                    rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.35 * (1 - root.ring1)
                Line:
                    circle: self.center_x, self.center_y, dp(62) + dp(78) * root.ring1
                    width: dp(1.6)
                Color:
                    rgba: CYAN[0], CYAN[1], CYAN[2], 0.35 * (1 - root.ring2)
                Line:
                    circle: self.center_x, self.center_y, dp(62) + dp(78) * root.ring2
                    width: dp(1.6)
                Color:
                    rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.16
                RoundedRectangle:
                    pos: self.x - dp(6), self.y - dp(16)
                    size: self.width + dp(12), self.height + dp(8)
                    radius: [dp(42)]
                Color:
                    rgba: 1, 1, 1, 1
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(34) * root.logo_scale]
                    texture: app.tex_brand
                Color:
                    rgba: 1, 1, 1, 0.22
                RoundedRectangle:
                    pos: self.x + dp(8), self.center_y + dp(4)
                    size: self.width - dp(16), self.height / 2 - dp(10)
                    radius: [dp(26), dp(26), dp(14), dp(14)]
                Color:
                    rgba: 1, 1, 1, 1
                Line:
                    points: [self.center_x - self.width * 0.27, self.center_y - self.height * 0.26, self.center_x, self.center_y + self.height * 0.28, self.center_x + self.width * 0.27, self.center_y - self.height * 0.26]
                    width: dp(7) * root.logo_scale
                    cap: 'round'
                    joint: 'round'
                Line:
                    points: [self.center_x - self.width * 0.13, self.center_y - self.height * 0.07, self.center_x + self.width * 0.13, self.center_y - self.height * 0.07]
                    width: dp(6) * root.logo_scale
                    cap: 'round'
        Label:
            text: 'Aminium'
            bold: True
            font_size: sp(40)
            color: INK
            opacity: root.text_alpha
            size_hint: None, None
            size: self.texture_size
            center_x: root.center_x
            y: root.center_y - dp(34) - dp(12) * (1 - root.text_alpha)
        Label:
            text: 'Cloudflare panel installer'
            font_size: sp(15)
            color: MUTED
            opacity: root.text_alpha
            size_hint: None, None
            size: self.texture_size
            center_x: root.center_x
            y: root.center_y - dp(78) - dp(12) * (1 - root.text_alpha)
        Label:
            text: root.status + '...'
            font_size: sp(13)
            color: MUTED
            size_hint: None, None
            size: self.texture_size
            center_x: root.center_x
            y: root.y + root.height * 0.2 + dp(26)
        Widget:
            size_hint: None, None
            size: root.width * 0.56, dp(6)
            center_x: root.center_x
            y: root.y + root.height * 0.2
            canvas:
                Color:
                    rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.12
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(3)]
                Color:
                    rgba: 1, 1, 1, 1
                RoundedRectangle:
                    pos: self.pos
                    size: max(dp(6), self.width * root.progress), self.height
                    radius: [dp(3)]
                    texture: app.tex_bar
        Label:
            text: '%d%%' % int(root.progress * 100)
            font_size: sp(12)
            bold: True
            color: PRIMARY
            size_hint: None, None
            size: self.texture_size
            center_x: root.center_x
            y: root.y + root.height * 0.2 - dp(26)

# -------------------------------------------------------------------- main
<MainScreen>:
    canvas.before:
        Color:
            rgba: 1, 1, 1, 1
        Rectangle:
            pos: self.pos
            size: self.size
            texture: app.tex_bg
        Color:
            rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.16
        Rectangle:
            texture: app.tex_glow
            size: self.width * 1.3, self.width * 1.3
            pos: self.right - self.width * 0.8, self.top - self.width * 0.7
    FloatLayout:
        ScrollView:
            id: scroll
            do_scroll_x: False
            bar_width: 0
            scroll_type: ['bars', 'content']
            BoxLayout:
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                padding: dp(16), app.inset_top + dp(14), dp(16), app.inset_bottom + dp(28)
                spacing: dp(16)

                BoxLayout:
                    size_hint_y: None
                    height: dp(64)
                    spacing: dp(14)
                    padding: dp(4), 0, 0, 0
                    Widget:
                        size_hint_x: None
                        width: dp(52)
                        canvas:
                            Color:
                                rgba: PRIMARY[0], PRIMARY[1], PRIMARY[2], 0.18
                            RoundedRectangle:
                                pos: self.x - dp(2), self.center_y - dp(32)
                                size: dp(56), dp(54)
                                radius: [dp(18)]
                            Color:
                                rgba: 1, 1, 1, 1
                            RoundedRectangle:
                                pos: self.x, self.center_y - dp(26)
                                size: dp(52), dp(52)
                                radius: [dp(17)]
                                texture: app.tex_brand
                            Color:
                                rgba: 1, 1, 1, 1
                            Line:
                                points: [self.center_x - dp(14), self.center_y - dp(13), self.center_x, self.center_y + dp(14), self.center_x + dp(14), self.center_y - dp(13)]
                                width: dp(3.4)
                                cap: 'round'
                                joint: 'round'
                            Line:
                                points: [self.center_x - dp(7), self.center_y - dp(3), self.center_x + dp(7), self.center_y - dp(3)]
                                width: dp(3)
                                cap: 'round'
                    BoxLayout:
                        orientation: 'vertical'
                        Label:
                            text: 'Aminium'
                            bold: True
                            font_size: sp(26)
                            color: INK
                            halign: 'left'
                            valign: 'bottom'
                            text_size: self.size
                        Label:
                            text: 'Panel installer for Cloudflare'
                            font_size: sp(13)
                            color: MUTED
                            halign: 'left'
                            valign: 'top'
                            text_size: self.size

                Card:
                    StepHead:
                        num: '1'
                        title: 'Create your API token'
                    Hint:
                        text: 'The token needs these permissions. The button opens Cloudflare with all of them pre-selected.'
                    BoxLayout:
                        id: perm_box
                        orientation: 'vertical'
                        size_hint_y: None
                        height: self.minimum_height
                    PillButton:
                        text: 'Open Cloudflare'
                        on_release: root.open_cloudflare()
                    Hint:
                        text: 'Then tap [b]Continue to summary > Create Token[/b] and copy it. Use an API Token, not the Global API Key.'

                Card:
                    StepHead:
                        num: '2'
                        title: 'Paste your token'
                    Field:
                        id: token
                        hint_text: 'Cloudflare API token'
                        password: True
                    BoxLayout:
                        size_hint_y: None
                        height: dp(52)
                        spacing: dp(10)
                        PillButton:
                            text: 'Paste'
                            primary: False
                            size_hint_x: 0.28
                            on_release: root.paste_token()
                        PillButton:
                            id: show_btn
                            text: 'Show'
                            primary: False
                            size_hint_x: 0.28
                            on_release: root.toggle_show()
                        PillButton:
                            text: 'Check token'
                            disabled: root.busy
                            on_release: root.on_check()
                    BoxLayout:
                        id: acc_box
                        orientation: 'vertical'
                        size_hint_y: None
                        height: self.minimum_height
                        spacing: dp(8)

                Card:
                    StepHead:
                        num: '3'
                        title: 'Options'
                    Hint:
                        text: 'Deploy as'
                    BoxLayout:
                        size_hint_y: None
                        height: dp(46)
                        spacing: dp(8)
                        Seg:
                            id: seg_workers
                            text: 'Workers (recommended)'
                            group: 'dtype'
                            state: 'down'
                            allow_no_selection: False
                        Seg:
                            id: seg_pages
                            text: 'Pages'
                            group: 'dtype'
                            allow_no_selection: False
                    Hint:
                        text: 'Project name'
                    BoxLayout:
                        size_hint_y: None
                        height: dp(52)
                        spacing: dp(10)
                        Field:
                            id: name_field
                            hint_text: 'my-project-name'
                        PillButton:
                            text: 'Randomize'
                            primary: False
                            size_hint_x: None
                            width: dp(120)
                            on_release: root.randomize()
                    Hint:
                        text: "Random names are safest. Cloudflare may restrict names with 'bpb', 'vpn' or 'proxy'."
                    Hint:
                        text: 'Panel source'
                    BoxLayout:
                        size_hint_y: None
                        height: dp(46)
                        spacing: dp(8)
                        Seg:
                            id: seg_official
                            text: 'Official release'
                            group: 'src'
                            state: 'down'
                            allow_no_selection: False
                        Seg:
                            id: seg_custom
                            text: 'My own URL'
                            group: 'src'
                            allow_no_selection: False
                    Field:
                        id: src_field
                        hint_text: 'https://github.com/YOU/REPO/releases/latest/download/worker.js'
                        disabled: seg_official.state == 'down'
                    Hint:
                        text: "Experimental: rename 'BPB' inside the panel"
                    BoxLayout:
                        size_hint_y: None
                        height: dp(46)
                        spacing: dp(8)
                        Seg:
                            id: seg_keep
                            text: 'Keep original'
                            group: 'brand'
                            state: 'down'
                            allow_no_selection: False
                        Seg:
                            id: seg_rename
                            text: 'Rename'
                            group: 'brand'
                            allow_no_selection: False
                    Field:
                        id: label_field
                        text: 'Aminium'
                        hint_text: 'New name'
                        disabled: seg_keep.state == 'down'

                PillButton:
                    height: dp(58)
                    font_size: sp(17)
                    text: 'Installing...' if root.busy else 'Install panel'
                    disabled: root.busy
                    on_release: root.on_deploy()

                BoxLayout:
                    id: result_slot
                    orientation: 'vertical'
                    size_hint_y: None
                    height: self.minimum_height
                    Card:
                        id: result_card
                        StepHead:
                            num: 'OK'
                            title: 'Your panel is ready'
                        Field:
                            id: url_field
                            readonly: True
                        BoxLayout:
                            size_hint_y: None
                            height: dp(52)
                            spacing: dp(10)
                            PillButton:
                                text: 'Copy link'
                                primary: False
                                on_release: root.copy_url()
                            PillButton:
                                text: 'Open panel'
                                on_release: root.open_panel()

                Card:
                    Title:
                        text: 'Activity log'
                    BoxLayout:
                        size_hint_y: None
                        height: dp(220)
                        padding: dp(12)
                        canvas.before:
                            Color:
                                rgba: TINT
                            RoundedRectangle:
                                pos: self.pos
                                size: self.size
                                radius: [dp(16)]
                        ScrollView:
                            id: log_scroll
                            bar_width: dp(3)
                            do_scroll_x: False
                            Label:
                                text: root.log_text
                                color: INK
                                font_size: sp(12.5)
                                halign: 'left'
                                valign: 'top'
                                size_hint_y: None
                                text_size: self.width, None
                                height: max(self.texture_size[1], log_scroll.height)

        Label:
            id: toast
            opacity: 0
            size_hint: None, None
            size: self.texture_size[0] + dp(40), self.texture_size[1] + dp(24)
            pos_hint: {'center_x': 0.5}
            y: app.inset_bottom + dp(36)
            color: 1, 1, 1, 1
            font_size: sp(14)
            canvas.before:
                Color:
                    rgba: 0.106, 0.122, 0.231, 0.94
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(20)]
"""


# ------------------------------------------------------------------------ app
class AminiumApp(App):
    title = "Aminium"
    inset_top = NumericProperty(0)
    inset_bottom = NumericProperty(0)
    tex_bg = ObjectProperty(None)
    tex_brand = ObjectProperty(None)
    tex_bar = ObjectProperty(None)
    tex_glow = ObjectProperty(None)

    def build(self):
        Window.clearcolor = (0.96, 0.97, 1, 1)
        Window.softinput_mode = "below_target"

        self.tex_bg = make_gradient((0.925, 0.935, 1.0, 1), (0.99, 0.992, 1.0, 1), 2, 64, "v")
        self.tex_brand = make_gradient((0.42, 0.30, 0.97, 1), (0.10, 0.74, 0.95, 1), 64, 64, "diag")
        self.tex_bar = make_gradient((0.42, 0.30, 0.97, 1), (0.10, 0.74, 0.95, 1), 64, 2, "h")
        self.tex_glow = make_glow(64)

        Builder.load_string(KV)
        self.sm = ScreenManager(transition=FadeTransition(duration=0.5))
        self.sm.add_widget(SplashScreen(name="splash"))
        self.sm.add_widget(MainScreen(name="main"))
        return self.sm

    def on_start(self):
        self._inset_tries = 0
        Clock.schedule_once(self.update_insets, 0.3)

    def update_insets(self, *_):
        """Android 15/16 draw the app edge-to-edge, so keep content clear of the system bars."""
        if platform != "android":
            return
        try:
            from jnius import autoclass
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            decor = PythonActivity.mActivity.getWindow().getDecorView()
            wi = decor.getRootWindowInsets()
            if wi is None:
                raise RuntimeError("insets not ready")
            Type = autoclass("android.view.WindowInsets$Type")
            bars = wi.getInsets(Type.systemBars() | Type.displayCutout())
            self.inset_top, self.inset_bottom = bars.top, bars.bottom
        except Exception:
            self._inset_tries += 1
            if self._inset_tries < 8:
                Clock.schedule_once(self.update_insets, 0.4)
            else:
                self.inset_top, self.inset_bottom = dp(32), dp(24)

    def show_main(self):
        self.sm.current = "main"

    def toast(self, msg):
        t = self.sm.get_screen("main").ids.toast
        Animation.cancel_all(t)
        t.text = msg
        t.opacity = 0
        (Animation(opacity=1, d=0.18) + Animation(d=2.2) + Animation(opacity=0, d=0.35)).start(t)


if __name__ == "__main__":
    AminiumApp().run()
