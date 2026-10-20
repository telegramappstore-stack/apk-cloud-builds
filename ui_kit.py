"""ui_kit - themes, animated text, the animated start-up screen and the theme swatch used by Amizoo."""
import math
import os
import random
import time

from kivy.animation import Animation
from kivy.clock import Clock
from kivy.graphics import Color, Ellipse, Line, Rectangle, RoundedRectangle
from kivy.graphics.texture import Texture
from kivy.metrics import dp, sp
from kivy.properties import BooleanProperty, NumericProperty, StringProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget

LOGO = ""          # set by main.py before the KV is loaded


def _t(name, bg, surf, surf2, line, txt, muted, acc, acc_dn):
    return dict(name=name, bg=bg, surf=surf, surf2=surf2, line=line, txt=txt, muted=muted, acc=acc, acc_dn=acc_dn)


THEMES = {
    "light": _t("Light", (0.955, 0.965, 0.985, 1), (1, 1, 1, 1), (0.91, 0.93, 0.98, 1), (0.87, 0.90, 0.95, 1),
                (0.09, 0.12, 0.22, 1), (0.42, 0.47, 0.60, 1), (0.13, 0.45, 0.96, 1), (0.09, 0.36, 0.82, 1)),
    "midnight": _t("Midnight", (0.04, 0.05, 0.10, 1), (0.08, 0.10, 0.18, 1), (0.13, 0.16, 0.27, 1), (0.17, 0.20, 0.32, 1),
                   (0.93, 0.95, 1.00, 1), (0.58, 0.63, 0.78, 1), (0.30, 0.55, 1.00, 1), (0.22, 0.42, 0.85, 1)),
    "ocean": _t("Ocean", (0.92, 0.97, 0.98, 1), (1, 1, 1, 1), (0.84, 0.94, 0.96, 1), (0.77, 0.90, 0.93, 1),
                (0.04, 0.20, 0.26, 1), (0.30, 0.50, 0.56, 1), (0.00, 0.62, 0.74, 1), (0.00, 0.48, 0.58, 1)),
    "sunset": _t("Sunset", (1.00, 0.96, 0.93, 1), (1.00, 0.995, 0.985, 1), (0.99, 0.90, 0.84, 1), (0.96, 0.85, 0.78, 1),
                 (0.25, 0.12, 0.10, 1), (0.60, 0.42, 0.38, 1), (0.96, 0.38, 0.25, 1), (0.80, 0.28, 0.17, 1)),
    "neon": _t("Neon", (0.07, 0.04, 0.13, 1), (0.12, 0.08, 0.22, 1), (0.18, 0.12, 0.32, 1), (0.25, 0.17, 0.42, 1),
               (0.96, 0.93, 1.00, 1), (0.68, 0.60, 0.85, 1), (0.62, 0.38, 1.00, 1), (0.48, 0.27, 0.85, 1)),
    "forest": _t("Forest", (0.93, 0.97, 0.94, 1), (1, 1, 1, 1), (0.85, 0.94, 0.87, 1), (0.78, 0.89, 0.81, 1),
                 (0.07, 0.20, 0.12, 1), (0.33, 0.50, 0.38, 1), (0.10, 0.65, 0.40, 1), (0.07, 0.50, 0.30, 1)),
}


# ---------------------------------------------------------------------------------- animated text
class FadeLabel(Label):
    """Set `value` instead of `text`: the old text fades out and the new one fades in.
    Fast streams of updates (progress counters, the uptime clock) are swapped instantly so nothing flickers."""
    value = StringProperty("")

    def __init__(self, **kw):
        self._last, self._anim = 0.0, None
        super().__init__(**kw)

    def on_value(self, _, v):
        now = time.time()
        fast, self._last = now - self._last < 0.6, now
        if self._anim is not None:
            self._anim.cancel(self)
            self._anim = None
        old = self.text
        if not old:
            self.text, self.opacity = v, 0
            self._anim = Animation(opacity=1, d=0.45, t="out_quad")
            self._anim.start(self)
            return
        if fast or len(os.path.commonprefix([old, v])) >= 6:
            self.text, self.opacity = v, 1
            return
        out = Animation(opacity=0, d=0.12)
        out.bind(on_complete=self._swap)
        self._anim = out
        out.start(self)

    def _swap(self, *_):
        self.text = self.value
        self._anim = Animation(opacity=1, d=0.3, t="out_quad")
        self._anim.start(self)


# ---------------------------------------------------------------------------------- animated start-up screen
class SplashScreen(Screen):
    TITLE = "Amizoo"
    TAGS = ("Hunting for the fastest servers", "Warming up the Xray core",
            "Building your secure tunnel", "Almost there")
    progress = NumericProperty(0)

    def __init__(self, **kw):
        super().__init__(**kw)
        self._t, self._ev, self._tag_ev, self._cb = 0.0, None, None, None
        self._started, self._finished, self._tag_i = 0.0, False, 0
        self._grad = Texture.create(size=(1, 2), colorfmt="rgba")
        self._grad.blit_buffer(bytes([56, 30, 115, 255, 13, 18, 46, 255]), colorfmt="rgba", bufferfmt="ubyte")
        self._grad.mag_filter = "linear"
        self._parts = [(random.random(), random.uniform(0.05, 0.14), random.uniform(3, 8), random.random())
                       for _ in range(12)]
        fl = FloatLayout()
        self.add_widget(fl)
        self.bg = Widget()                       # own canvas: a Screen's canvas.before must never be cleared
        fl.add_widget(self.bg)
        with self.bg.canvas:                     # built ONCE; every frame only updates these instructions
            Color(1, 1, 1, 1)
            self._rect = Rectangle(texture=self._grad)
            self._rings = [(Color(1, 1, 1, 0), Line(circle=(0, 0, 1), width=dp(1.6))) for _ in range(3)]
            self._dots = [(Color(1, 1, 1, 0), Ellipse(size=(dp(p[2]), dp(p[2])))) for p in self._parts]
            self._c_track = Color(1, 1, 1, 0)
            self._track = RoundedRectangle(radius=[dp(2.5)])
            self._c_fill = Color(1, 1, 1, 0)
            self._fill = RoundedRectangle(radius=[dp(2.5)])
        self.logo = Image(source=LOGO, mipmap=True, size_hint=(None, None), size=(dp(124), dp(124)), opacity=1,
                          pos_hint={"center_x": .5, "center_y": .6})
        fl.add_widget(self.logo)
        row = BoxLayout(size_hint=(None, None), size=(dp(34) * len(self.TITLE), dp(64)),
                        pos_hint={"center_x": .5, "center_y": .40})
        fl.add_widget(row)
        self.letters = []
        for ch in self.TITLE:
            holder = FloatLayout()
            lab = Label(text=ch, bold=True, font_size=sp(44), color=(1, 1, 1, 1), opacity=0,
                        pos_hint={"center_x": .5, "center_y": -.3})
            holder.add_widget(lab)
            row.add_widget(holder)
            self.letters.append(lab)
        self.tag = FadeLabel(size_hint=(1, None), height=dp(28), font_size=sp(15), color=(1, 1, 1, .85),
                             pos_hint={"center_x": .5, "center_y": .29})
        fl.add_widget(self.tag)

    # -- timeline
    def start(self, on_done):
        self._cb, self._started = on_done, time.time()
        self._ev = Clock.schedule_interval(self._frame, 1 / 30.0)
        Clock.schedule_once(self._pop_logo, 0.15)
        for i, lab in enumerate(self.letters):
            Clock.schedule_once(lambda dt, l=lab: Animation(
                opacity=1, pos_hint={"center_x": .5, "center_y": .5}, d=0.6, t="out_back").start(l), 0.9 + i * 0.09)
        Clock.schedule_once(self._next_tag, 1.5)
        self._tag_ev = Clock.schedule_interval(self._next_tag, 0.95)
        Animation(progress=1, d=3.2, t="in_out_sine").start(self)
        Clock.schedule_once(self.finish, 3.8)

    def _pop_logo(self, *_):
        big, base = (dp(140), dp(140)), (dp(124), dp(124))
        (Animation(size=big, d=0.35, t="out_quad") + Animation(size=base, d=0.55, t="out_back")).start(self.logo)

    def _next_tag(self, *_):
        self.tag.value = self.TAGS[min(self._tag_i, len(self.TAGS) - 1)]
        self._tag_i += 1

    def finish(self, *_):
        if self._finished:
            return
        self._finished = True
        Clock.unschedule(self.finish)
        Clock.unschedule(self._next_tag)
        cb, self._cb = self._cb, None
        if cb:
            cb()

    def on_touch_down(self, touch):
        if self._cb and time.time() - self._started > 1.2:
            self.finish()                                           # tap to skip
        return super().on_touch_down(touch)

    def on_leave(self, *_):
        for ev in (self._ev, self._tag_ev):
            if ev is not None:
                ev.cancel()
        self._ev = self._tag_ev = None

    # -- background: gradient, expanding rings, floating particles, progress bar
    def _frame(self, dt):
        self._t += dt
        w, h = self.bg.size
        if not w or not h:
            return
        x0, y0 = self.bg.pos
        t = self._t
        self._rect.pos, self._rect.size = (x0, y0), (w, h)
        gain = min(1.0, t / 1.0)
        cx, cy = x0 + w * .5, y0 + h * .6
        for k, (col, line) in enumerate(self._rings):
            ph = (t * 0.45 + k / 3.0) % 1.0
            col.a = 0.22 * (1 - ph) * gain
            line.circle = (cx, cy, dp(62) + ph * min(w, h) * 0.62)
        for (fx, spd, size, off), (col, dot) in zip(self._parts, self._dots):
            y = (t * spd + off) % 1.0
            col.a = 0.30 * math.sin(math.pi * y)
            dot.pos = (x0 + fx * w + math.sin(t + off * 9) * dp(10), y0 + y * h)
        bg_ = min(1.0, max(0.0, (t - 0.2) / 0.5))
        bw, bh = w * .5, dp(5)
        bx, by = x0 + (w - bw) / 2, y0 + h * .14
        self._c_track.a, self._c_fill.a = 0.25 * bg_, 0.95 * bg_
        self._track.pos, self._track.size = (bx, by), (bw, bh)
        self._fill.pos, self._fill.size = (bx, by), (max(bh, bw * self.progress), bh)


# ---------------------------------------------------------------------------------- theme swatch
class ThemeSwatch(ButtonBehavior, Widget):
    selected = BooleanProperty(False)

    def __init__(self, key, **kw):
        super().__init__(**kw)
        self.key, self.th = key, THEMES[key]
        self.lbl = Label(text=self.th["name"], bold=True, font_size=sp(13), color=self.th["txt"],
                         halign="center", valign="middle")
        self.add_widget(self.lbl)
        for n in ("pos", "size", "selected"):
            self.bind(**{n: self._draw})
        self._draw()

    def _draw(self, *_):
        t, (x, y), (w, h) = self.th, self.pos, self.size
        pad = dp(8)
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*t["bg"])
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(14)])
            Color(*(t["acc"] if self.selected else t["line"]))
            Line(rounded_rectangle=(x, y, w, h, dp(14)), width=dp(2.4) if self.selected else 1)
            Color(*t["surf"])
            RoundedRectangle(pos=(x + pad, y + h * .40), size=(w - 2 * pad, h * .46), radius=[dp(9)])
            Color(*t["acc"])
            Ellipse(pos=(x + pad * 1.6, y + h * .52), size=(h * .22, h * .22))
            RoundedRectangle(pos=(x + pad * 1.6 + h * .30, y + h * .56), size=(w * .32, h * .06), radius=[dp(3)])
            Color(*t["line"])
            RoundedRectangle(pos=(x + pad * 1.6 + h * .30, y + h * .67), size=(w * .22, h * .05), radius=[dp(3)])
        self.lbl.size = (w, h * .34)
        self.lbl.text_size = self.lbl.size
        self.lbl.pos = (x, y + dp(2))
