
"""NetFree - Kivy UI (Android). The proxy engine lives in engine.py and runs inside the background service (service.py),
so the connection (and the VPN) stay up after this window is closed."""
import ipaddress, json, os, queue, re, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

from engine import CF, SNIS, fetch_proxies, lan_ip, load_cfg, merge_nets, probe_ip, proxy_probe, rpc, sample_ips, save_cfg
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.text import Label as CoreLabel, LabelBase
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.metrics import dp, sp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, ObjectProperty
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.progressbar import ProgressBar
from kivy.uix.recycleboxlayout import RecycleBoxLayout
from kivy.uix.recycleview import RecycleView
from kivy.uix.screenmanager import NoTransition, Screen, ScreenManager
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.uix.textinput import TextInput
from kivy.utils import platform

BG, CARD, TXT, MUT = (.05, .07, .13, 1), (.09, .125, .2, 1), (.9, .91, .92, 1), (.58, .64, .72, 1)
ACC, GRN, RED, GRY, AMB = (.145, .388, .922, 1), (.063, .725, .506, 1), (.937, .267, .267, 1), (.392, .455, .545, 1), (.96, .62, .04, 1)
NAV = [("quick", "سریع"), ("dash", "داشبورد"), ("scan", "اسکن IP"), ("online", "پروکسی"), ("pool", "استخر"), ("log", "لاگ")]

# ---- Persian text: Kivy has no RTL shaping on Android -> reshape + bidi each line ourselves
_AR = re.compile(r"[\u0600-\u06FF]")
try:
    import arabic_reshaper
    from bidi.algorithm import get_display

    def fa(s):
        return "\n".join(get_display(arabic_reshaper.reshape(l)) if _AR.search(l) else l for l in str(s).split("\n"))
except Exception:
    def fa(s): return str(s)


FONT = "Roboto"


def setup_font():
    """Use a font that has Persian glyphs: fonts/Vazirmatn-Regular.ttf if you ship it, else Android's system Arabic font."""
    global FONT
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "fonts", "Vazirmatn-Regular.ttf"), os.path.join(here, "fonts", "font.ttf"), "/system/fonts/NotoNaskhArabic-Regular.ttf",
              "/system/fonts/NotoSansArabic-Regular.ttf", "/system/fonts/DroidNaskh-Regular.ttf",
              "C:/Windows/Fonts/tahoma.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        if os.path.exists(p):
            LabelBase.register(name="Roboto", fn_regular=p); FONT = p; return


def fmt(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# ---- widgets
class RBtn(Button):
    bg = ListProperty(ACC)
    circle = BooleanProperty(False)

    def __init__(s, **k):
        k.setdefault("background_normal", ""); k.setdefault("background_down", ""); k["background_color"] = (0, 0, 0, 0)
        k.setdefault("font_name", FONT)
        super().__init__(**k)
        with s.canvas.before:
            s._c = Color(*s.bg); s._r = RoundedRectangle(pos=s.pos, size=s.size, radius=[dp(12)])
        s.bind(pos=s._u, size=s._u, bg=s._u, state=s._u, circle=s._u); s._u()

    def _u(s, *a):
        k, b = (.75 if s.state == "down" else 1), s.bg
        s._c.rgba = (b[0] * k, b[1] * k, b[2] * k, b[3] if len(b) > 3 else 1)
        s._r.pos, s._r.size = s.pos, s.size
        s._r.radius = [min(s.width, s.height) / 2 if s.circle else dp(12)]


def B(text, cb, color=ACC, h=44, size=13):
    return RBtn(text=fa(text), on_release=lambda *_: cb(), bg=color, font_size=sp(size), size_hint_y=None, height=dp(h))


class WL(Label):
    """Wrapping label. Persian paragraphs are word-wrapped in logical order BEFORE reshaping, so lines read correctly."""
    def __init__(s, text="", size=13, color=TXT, bold=False, center=False, smart=True, **k):
        k.setdefault("font_name", FONT)
        super().__init__(font_size=sp(size), color=color, bold=bold, size_hint_y=None,
                         halign="center" if center else "right", valign="middle", **k)
        s.smart, s.raw, s._ready = smart, "", False
        s.bind(width=s._on_w, texture_size=s._on_h); s.set(text)

    def _on_w(s, *a): s._ready = True; s.text_size = (s.width, None); s._layout()
    def _on_h(s, *a): s.height = max(dp(22), s.texture_size[1] + dp(6))
    def set(s, t): s.raw = str(t); s._layout()

    def _layout(s):
        if not (s.smart and s._ready and _AR.search(s.raw)):
            s.text = fa(s.raw); return
        cl, mw, out = CoreLabel(font_name=s.font_name, font_size=s.font_size), s.width - dp(4), []
        for para in s.raw.split("\n"):
            cur = ""
            for w in para.split(" "):
                t = (cur + " " + w) if cur else w
                if cur and cl.get_extents(fa(t))[0] > mw: out.append(cur); cur = w
                else: cur = t
            out.append(cur)
        s.text = "\n".join(fa(l) for l in out)


class Card(BoxLayout):
    def __init__(s, **k):
        k.setdefault("orientation", "vertical"); k.setdefault("padding", dp(12)); k.setdefault("spacing", dp(8)); k.setdefault("size_hint_y", None)
        super().__init__(**k)
        s.bind(minimum_height=s.setter("height"))
        with s.canvas.before:
            Color(*CARD); s._r = RoundedRectangle(pos=s.pos, size=s.size, radius=[dp(14)])
        s.bind(pos=s._u, size=s._u)

    def _u(s, *a): s._r.pos, s._r.size = s.pos, s.size


class Row(Button):
    idx, sel, cb = NumericProperty(0), BooleanProperty(False), ObjectProperty(None, allownone=True)

    def __init__(s, **k):
        k.setdefault("background_normal", ""); k.setdefault("background_down", ""); k.setdefault("font_name", FONT)
        super().__init__(**k)
        s.halign, s.valign, s.font_size = "left", "middle", sp(12)
        s.bind(size=lambda *_: setattr(s, "text_size", (s.width - dp(16), s.height)), sel=s._c); s._c()

    def _c(s, *a): s.background_color = ACC if s.sel else (.12, .16, .25, 1)

    def on_release(s):
        if s.cb: s.cb(s.idx)


class Table(BoxLayout):
    """Scrollable, tap-to-select list. Each row: {key, title, sub, score, color}."""
    def __init__(s, h=340):
        super().__init__(orientation="vertical", size_hint_y=None, height=dp(h))
        s.rows, s.sel_key = [], None
        s.rv = RecycleView(bar_width=dp(4), viewclass=Row)
        s.lay = RecycleBoxLayout(default_size=(None, dp(58)), default_size_hint=(1, None), size_hint_y=None, orientation="vertical", spacing=dp(3))
        s.lay.bind(minimum_height=s.lay.setter("height"))
        s.rv.add_widget(s.lay); s.add_widget(s.rv)

    def set_rows(s, rows): s.rows = rows; s._data()

    def _tap(s, i):
        if i < len(s.rows): s.sel_key = s.rows[i]["key"]; s._data()

    def _data(s):
        s.rv.data = [{"text": fa(r["title"] + "\n" + r["sub"]), "idx": i, "sel": r["key"] == s.sel_key, "cb": s._tap,
                      "color": r.get("color", TXT)} for i, r in enumerate(s.rows)]

    def selected(s): return next((r for r in s.rows if r["key"] == s.sel_key), None)


# ---- main screen
class UI(BoxLayout):
    def __init__(self, **k):
        super().__init__(orientation="vertical", **k)
        with self.canvas.before:
            Color(*BG); self._bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=lambda *_: setattr(self._bg, "pos", self.pos), size=lambda *_: setattr(self._bg, "size", self.size))
        self.cfg = load_cfg()
        self.q, self.stop = queue.Queue(), threading.Event()
        self.st, self.alive, self._opts = None, True, {}
        self.qst, self.cur, self.qlock, self._qkey, self._qmsg = "idle", "quick", (0, ""), None, ""
        self.tbl, self.data, self.dirty, self.prog, self.pool_views, self.logs = {}, {}, set(), {}, [], []
        self._lan, self._lan_t, self.prev, self._pt = "127.0.0.1", 0, (0, 0, time.time()), 0
        self.qlog = lambda m: self.q.put(("log", m))
        self.sm = ScreenManager(transition=NoTransition()); self.add_widget(self.sm)
        for key, fn in (("quick", self.page_quick), ("dash", self.page_dash), ("scan", self.page_scan),
                        ("online", self.page_online), ("pool", self.page_pool), ("log", self.page_log)):
            self.page(key, fn)
        nav = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(3), padding=dp(3)); self.nav = {}
        for key, t in NAV:
            b = RBtn(text=fa(t), font_size=sp(12), bg=CARD, on_release=lambda b, key=key: self.show(key)); nav.add_widget(b); self.nav[key] = b
        self.add_widget(nav); self.show("quick")
        Clock.schedule_interval(self.poll, 0.5); Clock.schedule_interval(self.tick, 0.4)
        threading.Thread(target=self.poller, daemon=True).start()

    # ----- layout helpers -----
    def page(self, key, fn):
        sv = ScrollView(do_scroll_x=False, bar_width=dp(3))
        col = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(10), spacing=dp(10))
        col.bind(minimum_height=col.setter("height")); sv.add_widget(col)
        s = Screen(name=key); s.add_widget(sv); self.sm.add_widget(s); fn(col)

    @staticmethod
    def r(*ws, h=46):
        b = BoxLayout(size_hint_y=None, height=dp(h), spacing=dp(6))
        for w in ws: w.size_hint_y = 1; b.add_widget(w)
        return b

    def ent(self, val="", w=110, num=True):
        return TextInput(text=str(val), multiline=False, input_filter="int" if num else None, size_hint_x=None, width=dp(w),
                         background_color=(.14, .19, .29, 1), foreground_color=TXT, cursor_color=TXT, padding=[dp(8), dp(12)], font_size=sp(14))

    def fld(self, parent, text, val):
        t = self.ent(val); parent.add_widget(self.r(WL(text, 13), t)); return t

    def sw(self, parent, text, key, default=True):
        s = Switch(active=bool(self.cfg.get(key, default)), size_hint_x=None, width=dp(90)); parent.add_widget(self.r(WL(text, 13), s)); return s

    def spin(self, parent, text, val, values):
        s = Spinner(text=val, values=values, size_hint_x=None, width=dp(210), background_normal="", background_color=(.14, .19, .29, 1))
        parent.add_widget(self.r(WL(text, 13), s)); return s

    def head(self, c, title, sub):
        c.add_widget(WL(title, 22, bold=True)); c.add_widget(WL(sub, 12, MUT))

    def table(self, parent, key):
        t = Table(); self.tbl[key], self.data[key] = t, []; parent.add_widget(t); return t

    def show(self, k):
        self.cur = k; self.sm.current = k
        for n, b in self.nav.items(): b.bg = ACC if n == k else CARD

    def log(self, m):
        self.logs.append(time.strftime("%H:%M:%S  ") + str(m)); del self.logs[:-150]
        if hasattr(self, "log_lbl"): self.log_lbl.set("\n".join(self.logs))

    def copy(self, v):
        if v: Clipboard.copy(str(v)); self.log(f"کپی شد: {v}")

    # ----- pages -----
    def page_quick(self, c):
        c.add_widget(WL("NetFree", 26, ACC, True, center=True)); c.add_widget(WL("اتصال هوشمند و پایدار", 12, MUT, center=True))
        a = AnchorLayout(size_hint_y=None, height=dp(220))
        self.q_btn = RBtn(text=fa("اتصال"), font_size=sp(28), bg=GRY, size_hint=(None, None), size=(dp(190), dp(190)), circle=True,
                          on_release=lambda *_: self.quick_toggle())
        a.add_widget(self.q_btn); c.add_widget(a)
        self.q_status, self.q_info, self.q_speed = WL("آماده اتصال", 16, TXT, True, center=True), WL("", 12, MUT, center=True), WL("", 12, MUT, center=True)
        for w in (self.q_status, self.q_info, self.q_speed): c.add_widget(w)
        k = Card(); self.qlan = self.sw(k, "اشتراک با دستگاه‌های دیگر (هات‌اسپات)", "qlan", False)
        self.qsec = self.sw(k, "فقط مسیرهای تاییدشده (یوتیوب + سرعت)", "qsec", True); c.add_widget(k)
        self.q_addr = WL("", 17, ACC, True, center=True); c.add_widget(self.q_addr)
        c.add_widget(B("کپی آدرس", lambda: self.copy(self.q_addr.raw), GRY))
        c.add_widget(WL("با زدن دکمه، VPN واقعی (آیکون کلید) روشن می‌شود و کل گوشی از مسیر NetFree می‌رود.\n"
                        "با بستن برنامه هم اتصال ادامه دارد؛ برای قطع، دوباره برنامه را باز کنید و «قطع» را بزنید.", 11, MUT, center=True))

    def page_dash(self, c):
        self.head(c, "داشبورد اتصال", "سرویس را روشن کنید، سپس آدرس را در برنامه وارد کنید")
        k = Card(); self.v_state, self.v_speed, self.v_conn = WL("", 15, bold=True), WL("", 13), WL("", 13)
        self.s_socks, self.s_fwd = WL("", 12, MUT), WL("", 12, MUT)
        for w in (self.v_state, self.v_speed, self.v_conn, self.s_socks, self.s_fwd): k.add_widget(w)
        c.add_widget(k)

        k = Card(); k.add_widget(WL("SOCKS5 / HTTP Server", 16, bold=True))
        self.port = self.fld(k, "پورت", self.cfg.get("port", 1080)); self.lan = self.sw(k, "اشتراک روی شبکه (هات‌اسپات)", "lan", False)
        self.frag = self.sw(k, "TLS fragment", "frag"); self.doh = self.sw(k, "DNS امن (DoH)", "doh")
        self.lbl_up = WL("", 12, MUT); k.add_widget(self.lbl_up)
        self.b_socks = B("روشن کردن سرور", self.toggle_socks); k.add_widget(self.b_socks)
        k.add_widget(self.r(B("تست اتصال", self.test_socks, GRY), B("کپی آدرس", lambda: self.copy(self.addr.raw), GRY)))
        k.add_widget(B("حذف آپ‌استریم‌ها", lambda: self.cmd("clear_up"), GRY))
        self.addr = WL("", 17, ACC, True, center=True); k.add_widget(self.addr); c.add_widget(k)

        k = Card(); k.add_widget(WL("Cloudflare IP Forwarder", 16, bold=True))
        self.fport = self.fld(k, "پورت", self.cfg.get("fport", 10443)); self.flan = self.sw(k, "اشتراک روی شبکه", "flan", False)
        self.ffrag = self.sw(k, "TLS fragment", "ffrag"); self.fsni = self.spin(k, "SNI", self.cfg.get("fsni", SNIS[0]), SNIS)
        self.lbl_ip = WL("", 12, MUT); k.add_widget(self.lbl_ip)
        self.b_fwd = B("روشن کردن فوروارد", self.toggle_fwd); k.add_widget(self.b_fwd)
        k.add_widget(self.r(B("کپی آدرس", lambda: self.copy(self.faddr.raw), GRY),
                            B("حذف IPها", lambda: self.cmd("clear_ip"), GRY)))
        self.faddr = WL("", 17, ACC, True, center=True); k.add_widget(self.faddr)
        k.add_widget(WL("کانفیگ V2Ray/Xray (آدرس سرور) را روی این آدرس بگذارید؛ برنامه خودش سالم‌ترین IP را انتخاب و در صورت خرابی عوض می‌کند.", 11, MUT))
        c.add_widget(k)

    def page_scan(self, c):
        self.head(c, "اسکن IP کلودفلر", "اسکن رنج‌های بزرگ با چند نمونه، جیتر و تایید واقعی کلودفلر")
        k = Card(); self.sni1 = self.spin(k, "SNI", self.cfg.get("sni1", SNIS[0]), SNIS)
        self.n1 = self.fld(k, "تعداد IP برای تست", self.cfg.get("n1", 2000)); self.smp = self.fld(k, "نمونه برای هر IP", 3)
        self.w1 = self.fld(k, "هم‌زمان", 100); self.ver = self.sw(k, "تایید کلودفلر", "ver")
        k.add_widget(WL("رنج‌ها (هر خط یک CIDR):", 12, MUT))
        self.rng = TextInput(text="\n".join(self.cfg.get("ranges", CF)), size_hint_y=None, height=dp(150), font_size=sp(11),
                             background_color=(.14, .19, .29, 1), foreground_color=TXT, cursor_color=TXT)
        k.add_widget(self.rng)
        k.add_widget(self.r(B("شروع اسکن", self.scan, ACC), B("توقف", self.stop.set, RED)))
        k.add_widget(B("بازنشانی رنج‌ها به لیست بزرگ پیش‌فرض", self.reset_ranges, GRY))
        self.prog["scan"] = ProgressBar(max=1, size_hint_y=None, height=dp(10)); k.add_widget(self.prog["scan"]); c.add_widget(k)
        k = Card()
        k.add_widget(self.r(B("اتصال به IP انتخابی", lambda: self.connect_ip(False), GRN, size=12), B("اتصال خودکار (۵ بهترین)", lambda: self.connect_ip(True), GRN, size=12)))
        k.add_widget(self.r(B("افزودن به استخر", self.add_ip), B("کپی IP", lambda: self.copy((self.sel("scan") or {}).get("ip")), GRY)))
        self.table(k, "scan"); c.add_widget(k)

    def page_online(self, c):
        self.head(c, "پروکسی آنلاین", "دریافت لیست‌های عمومی و تست واقعی (تونل، تاخیر، سلامت TLS)")
        k = Card(); self.kind = self.spin(k, "نوع", "SOCKS5", ("SOCKS5", "HTTP"))
        self.n2 = self.fld(k, "تعداد", self.cfg.get("n2", 400)); self.w2 = self.fld(k, "هم‌زمان", 120); self.sec = self.sw(k, "فقط TLS امن", "sec", False)
        k.add_widget(self.r(B("دریافت و تست", self.online), B("توقف", self.stop.set, RED)))
        self.prog["online"] = ProgressBar(max=1, size_hint_y=None, height=dp(10)); k.add_widget(self.prog["online"]); c.add_widget(k)
        k = Card()
        k.add_widget(self.r(B("اتصال (انتخابی)", lambda: self.connect_proxy(False), GRN, size=12), B("اتصال خودکار (۵ بهترین)", lambda: self.connect_proxy(True), GRN, size=12)))
        k.add_widget(self.r(B("افزودن به استخر", self.add_proxy), B("کپی", lambda: self.copy((self.sel("online") or {}).get("addr")), GRY)))
        self.table(k, "online"); c.add_widget(k)

    def page_pool(self, c):
        self.head(c, "استخر اتصال", "هر مورد سالم‌تر و سریع‌تر باشد اولویت دارد؛ موارد خراب موقتاً کنار گذاشته می‌شوند")
        for title, key, rm, clr in (("IPهای کلودفلر (برای Forwarder)", "ip_pool", "rm_ip", "clear_ip"), ("پروکسی‌های آپ‌استریم (برای SOCKS5)", "up_pool", "rm_up", "clear_up")):
            k = Card(); k.add_widget(WL(title, 14, bold=True)); t = self.table(k, "pool_" + key); self.pool_views.append((t, key, rm))
            k.add_widget(self.r(B("حذف انتخابی", lambda t=t, rm=rm: self.pool_rm(t, rm), GRY), B("پاک کردن همه", lambda clr=clr: self.cmd(clr), RED))); c.add_widget(k)

    def page_log(self, c):
        self.head(c, "لاگ", "رویدادهای برنامه")
        self.log_lbl = WL("", 11, MUT, smart=False); self.log_lbl.halign = "left"; c.add_widget(self.log_lbl)

    # ----- quick connect -----
    def set_quick(self, st, info=None):
        self.qst = st
        t, col = {"idle": ("اتصال", GRY), "connecting": ("لغو", AMB), "connected": ("قطع", GRN), "failed": ("تلاش مجدد", RED)}[st]
        self.q_btn.text, self.q_btn.bg = fa(t), col
        if st == "connecting": self.q_status.set("در حال اتصال ..."); self.q_status.color = AMB
        elif st == "connected" and info:
            self.q_status.set("متصل - دسترسی یوتیوب تایید شد"); self.q_status.color = GRN
            self.q_info.set(f"IP خروجی: {info['ip']} ({info['loc']})   تاخیر: {info['ms']:.0f} ms")
        elif st == "failed": self.q_status.set(info or "ناموفق"); self.q_status.color = RED; self.q_info.set("")
        elif st == "idle": self.q_status.set("آماده اتصال"); self.q_status.color = TXT; self.q_info.set("")

    def quick_toggle(self):
        self._qkey = None
        if self.qst in ("connecting", "connected"):
            self.qlock = (time.time() + 4, "idle"); self.cmd("quick_stop"); self.vpn_stop(); self.set_quick("idle")
        else:
            self.qlock = (time.time() + 8, "connecting"); self.set_quick("connecting")
            port, lan, sec = self.port_of(self.port, 1080), self.qlan.active, self.qsec.active
            self.vpn_connect(port, lambda: self.cmd("quick_start", lan=lan, secure=sec, port=port))

    def sync_quick(self, now, st):
        q = st.get("quick")
        if not q: return
        want = q["st"]
        if now < self.qlock[0] and ((self.qlock[1] == "idle" and want != "idle") or (self.qlock[1] == "connecting" and want == "idle")): want = None
        if want:
            key = (want, json.dumps(q["info"], sort_keys=True) if q.get("info") else None)
            if key != self._qkey:
                self._qkey = key; self.set_quick(want, q["info"])
                if want == "failed": self.vpn_stop()
            if q.get("msg") and q["msg"] != self._qmsg and want != "idle": self.q_status.set(q["msg"])
            self._qmsg = q.get("msg", "")

    # ----- real VPN (Android VpnService, key icon) -----
    def _vpn_intent(self, action=None, port=None):
        from jnius import autoclass
        act = autoclass("org.kivy.android.PythonActivity").mActivity
        i = autoclass("android.content.Intent")(); i.setClassName(act.getPackageName(), "org.netfree.vpn.NetFreeVpn")
        if action: i.setAction(action)
        if port: i.putExtra("port", str(port))
        return act, i

    def vpn_start(self, port):
        try: act, i = self._vpn_intent(port=port); act.startService(i); self.log("VPN روشن شد")
        except Exception as e: self.log(f"VPN: {e}")

    def vpn_stop(self):
        if platform != "android": return
        try: act, i = self._vpn_intent("org.netfree.vpn.STOP"); act.startService(i)
        except Exception as e: self.log(f"VPN: {e}")

    def vpn_connect(self, port, then):
        if platform != "android": return then()
        try:
            from jnius import autoclass
            act = autoclass("org.kivy.android.PythonActivity").mActivity
            it = autoclass("android.net.VpnService").prepare(act)
        except Exception as e:
            self.log(f"VPN: {e}"); return then()
        if it is None: self.vpn_start(port); return then()
        from android import activity as aa
        self._vpn = (port, then); aa.bind(on_activity_result=self._on_result); act.startActivityForResult(it, 4711)

    def _on_result(self, req, res, data):
        if req != 4711: return
        from android import activity as aa
        aa.unbind(on_activity_result=self._on_result)
        port, then = self._vpn

        def ok(dt): self.vpn_start(port); then()

        def no(dt): self.log("مجوز VPN داده نشد"); self.qlock = (0, ""); self.set_quick("idle")
        Clock.schedule_once(ok if res == -1 else no)

    # ----- background service (RPC) -----
    def cmds(self, seq):
        """Send commands to the background service (started on demand) in order, without blocking the UI."""
        def go():
            if not rpc("ping", 1.0) and not self.start_service(): self.q.put(("log", "سرویس پس‌زمینه اجرا نشد")); return
            for name, kw in seq: rpc(name, 3.0, **kw)
        threading.Thread(target=go, daemon=True).start()

    def cmd(self, name, **kw): self.cmds([(name, kw)])

    def start_service(self):
        try:
            if platform == "android":
                from jnius import autoclass
                act = autoclass("org.kivy.android.PythonActivity").mActivity
                svc = autoclass(act.getPackageName() + ".ServiceNetfree")
                try: svc.start(act, "", "NetFree", "Connection active", "")
                except Exception: svc.start(act, "")
            else:
                subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "service.py")])
        except Exception as e:
            self.q.put(("log", f"خطا در اجرای سرویس: {e}")); return False
        for _ in range(60):
            if rpc("ping", 0.5): return True
            time.sleep(0.2)
        return False

    def poller(self):
        since = 0
        while self.alive:
            r = rpc("status", 1.5, since=since, opts=self._opts)
            if r and "nlog" in r:
                if r["nlog"] < since: since = 0
                else: since = r["nlog"]; self.q.put(("status", r))
            elif not r: self.q.put(("status", None))
            time.sleep(0.5)

    # ----- table / jobs -----
    def sel(self, key): return self.tbl[key].selected()

    def refresh_tree(self, key):
        rows = sorted(self.data[key], key=lambda r: r["score"])[:600]
        for r in rows: r["color"] = GRN if r["score"] < 300 else AMB if r["score"] < 700 else RED
        self.tbl[key].set_rows(rows)

    def start_job(self, key, jobs, fn, workers):
        self.stop.clear(); self.data[key] = []; self.refresh_tree(key); self.prog[key].value = 0
        self.log(f"تست {len(jobs)} هدف با {workers} رشته ...")

        def wrap(j): return None if self.stop.is_set() else fn(j)

        def go():
            done = 0
            with ThreadPoolExecutor(workers) as ex:
                for f in as_completed([ex.submit(wrap, j) for j in jobs]):
                    done += 1
                    try: r = f.result()
                    except Exception: r = None
                    if r: self.q.put(("row", key, r))
                    if done % 5 == 0 or done == len(jobs): self.q.put(("prog", key, done / len(jobs)))
            self.q.put(("done", key))
        threading.Thread(target=go, daemon=True).start()

    def poll(self, dt=0):
        try:
            while True:
                k, *a = self.q.get_nowait()
                if k == "row": self.data[a[0]].append(a[1]); self.dirty.add(a[0])
                elif k == "call": a[0]()
                elif k == "status":
                    self.st = a[0]
                    if a[0] and a[0]["logs"]:
                        self.logs += a[0]["logs"]; del self.logs[:-150]; self.log_lbl.set("\n".join(self.logs))
                elif k == "prog": self.prog[a[0]].value = a[1]
                elif k == "done":
                    self.dirty.add(a[0]); self.prog[a[0]].value = 1
                    self.log(f"پایان: {len(self.data[a[0]])} مورد سالم" + (" (متوقف شد)" if self.stop.is_set() else ""))
                else: self.log(a[0])
        except queue.Empty:
            pass
        for k in list(self.dirty): self.refresh_tree(k)
        self.dirty.clear()

    # ----- scan / online -----
    def reset_ranges(self): self.rng.text = "\n".join(CF); self.log(f"رنج‌ها بازنشانی شد ({len(CF)} بلوک)")

    def scan(self):
        try: n, smp, w = int(self.n1.text), max(1, int(self.smp.text)), max(1, int(self.w1.text))
        except ValueError: return self.log("مقادیر عددی نامعتبر است")
        nets = []
        for l in self.rng.text.splitlines():
            l = l.split("#")[0].strip()
            if not l: continue
            try: nets.append(ipaddress.ip_network(l, strict=False))
            except ValueError: self.log(f"رنج نامعتبر: {l}")
        nets = merge_nets(nets)
        if not nets: return self.log("رنج معتبری وارد نشده")
        out = sample_ips(nets, n)
        self.log(f"{len(nets)} رنج، {sum(x.num_addresses for x in nets):,} آدرس؛ نمونه‌برداری {len(out)} IP")
        sni, ver = self.sni1.text, self.ver.active

        def fn(ip):
            r = probe_ip(ip, sni, smp, ver)
            if r: return {"key": ip, "ip": ip, "lat": r["tls"], "score": r["score"], "title": ip,
                          "sub": f"TLS {r['tls']:.0f} | TCP {r['tcp']:.0f} | jit {r['jit']:.0f} | {r['ok']} | score {r['score']:.0f}"}
        self.start_job("scan", out, fn, w)

    def online(self):
        k = self.kind.text
        try: n, w = int(self.n2.text), max(1, int(self.w2.text))
        except ValueError: return self.log("مقادیر عددی نامعتبر است")
        only = self.sec.active
        self.log("دریافت لیست پروکسی‌ها ...")

        def go():
            jobs = fetch_proxies(k, n, self.qlog)
            if not jobs: self.q.put(("log", "لیستی دریافت نشد؛ اینترنت/دسترسی به GitHub را بررسی کنید")); return
            self.q.put(("call", lambda: self.start_job("online", jobs, fn, w)))

        def fn(hp):
            r = proxy_probe(k, *hp)
            if not r or (only and not r["secure"]): return None
            return {"key": r["addr"], "kind": k, "addr": r["addr"], "host": r["host"], "port": r["port"], "lat": r["lat"], "score": r["score"],
                    "title": f"{k}  {r['addr']}", "sub": f"ping {r['lat']:.0f} | TLS {'ok' if r['secure'] else 'x'} | jit {r['jit']:.0f} | score {r['score']:.0f}"}
        threading.Thread(target=go, daemon=True).start()

    # ----- connect actions -----
    def top(self, key, n=5): return sorted(self.data[key], key=lambda r: r["score"])[:n]

    def connect_ip(self, auto):
        rows = [r for r in (self.top("scan") if auto else [self.sel("scan")]) if r]
        if not rows: return self.log("ابتدا اسکن کنید و یک IP انتخاب کنید")
        self.log(f"{len(rows)} IP در استخر قرار گرفت")
        self.cmds([("set_ip", {"items": [{"host": r["ip"], "lat": r["lat"]} for r in rows]}), ("start_fwd", self.fwd_args())]); self.show("dash")

    def fwd_args(self): return {"lan": self.flan.active, "port": self.port_of(self.fport, 10443), "frag": self.ffrag.active, "sni": self.fsni.text}

    def socks_args(self): return {"lan": self.lan.active, "port": self.port_of(self.port, 1080), "frag": self.frag.active, "doh": self.doh.active}

    def add_ip(self):
        r = self.sel("scan")
        if r: self.cmd("add_ip", item={"host": r["ip"], "lat": r["lat"]}); self.log(f"{r['ip']} به استخر IP اضافه شد")

    def connect_proxy(self, auto):
        rows = [r for r in (self.top("online") if auto else [self.sel("online")]) if r]
        if not rows: return self.log("ابتدا تست کنید و یک پروکسی انتخاب کنید")
        self.log(f"{len(rows)} پروکسی آپ‌استریم تنظیم شد")
        self.cmds([("set_up", {"items": [{"kind": r["kind"], "host": r["host"], "port": r["port"], "lat": r["lat"]} for r in rows]}),
                   ("start_socks", self.socks_args())]); self.show("dash")

    def add_proxy(self):
        r = self.sel("online")
        if r: self.cmd("add_up", item={"kind": r["kind"], "host": r["host"], "port": r["port"], "lat": r["lat"]}); self.log(f"{r['addr']} به استخر آپ‌استریم اضافه شد")

    def pool_rm(self, t, rm):
        r = t.selected()
        if r: self.cmd(rm, host=r["ent"]["host"], port=r["ent"]["port"]); t.sel_key = None

    # ----- servers -----
    def port_of(self, e, d):
        try: return int(e.text)
        except ValueError: return d

    def toggle_socks(self):
        if (self.st or {}).get("socks"): self.cmd("stop_socks")
        else: self.cmd("start_socks", **self.socks_args())



    def toggle_fwd(self):
        if (self.st or {}).get("fwd"): self.cmd("stop_fwd")
        elif not (self.st or {}).get("ip_pool"): self.log("استخر IP خالی است؛ ابتدا از تب اسکن IP اضافه کنید")
        else: self.cmd("start_fwd", **self.fwd_args())

    def test_socks(self): self.cmd("test_socks")

    # ----- periodic UI refresh -----
    def tick(self, dt=0):
        now, st = time.time(), self.st or {}
        self._opts = {"frag": self.frag.active, "doh": self.doh.active, "ffrag": self.ffrag.active, "fsni": self.fsni.text}
        if now - self._lan_t > 30: self._lan, self._lan_t = lan_ip(), now
        srv, fwd = st.get("socks"), st.get("fwd")
        run = lambda x: bool(x) and x["state"] == "running"
        host = lambda x: self._lan if x["host"] == "0.0.0.0" else "127.0.0.1"
        for lbl, name, x in ((self.s_socks, "SOCKS5", srv), (self.s_fwd, "Forwarder", fwd)):
            lbl.set(f"{name}: {'روشن' if run(x) else 'خاموش'}"); lbl.color = GRN if run(x) else MUT
        self.b_socks.text, self.b_socks.bg = fa("خاموش کردن" if srv else "روشن کردن سرور"), RED if srv else ACC
        self.b_fwd.text, self.b_fwd.bg = fa("خاموش کردن" if fwd else "روشن کردن فوروارد"), RED if fwd else ACC
        self.addr.set(f"socks5://{host(srv)}:{srv['port']}" if srv else "")
        self.faddr.set(f"{host(fwd)}:{fwd['port']}" if fwd else "")
        ups, ips = st.get("up_pool", []), st.get("ip_pool", [])
        self.lbl_up.set(f"آپ‌استریم: {len(ups)} پروکسی (با failover خودکار)" if ups else "آپ‌استریم: مستقیم (بدون پروکسی)")
        best = min(ips, key=lambda e: (min(e["fails"], 3), e["lat"] or 9e9))["host"] if ips else ""
        self.lbl_ip.set(f"استخر: {len(ips)} IP" + (" - بهترین: " + best if ips else ""))

        srvs = [x for x in (srv, fwd) if x]
        up, dn = sum(x["up"] for x in srvs), sum(x["down"] for x in srvs)
        pu, pd, pt = self.prev; dt = max(0.05, now - pt)
        self.v_speed.set(f"Down {fmt(max(0, dn - pd) / dt)}/s    Up {fmt(max(0, up - pu) / dt)}/s"); self.prev = (up, dn, now)
        self.v_conn.set(f"{sum(x['active'] for x in srvs)} فعال | {sum(x['conns'] for x in srvs)} کل | {sum(x['fail'] for x in srvs)} خطا")
        on = any(run(x) for x in srvs)
        self.v_state.set("متصل (سرویس پس‌زمینه)" if on else ("خاموش" if self.st else "سرویس پس‌زمینه خاموش")); self.v_state.color = GRN if on else MUT
        self.q_speed.set(self.v_speed.raw); self.q_addr.set(self.addr.raw)
        self.sync_quick(now, st)

        if self.cur == "pool" and now - self._pt > 1.5:
            self._pt = now
            for t, key, rm in self.pool_views:
                rows = []
                for e in st.get(key, []):
                    cd = e["until"] - now
                    stt = "سالم" if e["fails"] == 0 else (f"استراحت {cd:.0f}s" if cd > 0 else "ناپایدار")
                    ad = f"{e['host']}:{e['port']}"
                    rows.append({"key": ad, "title": ad, "ent": e, "score": 0, "color": GRN if e["fails"] == 0 else AMB if cd <= 0 else RED,
                                 "sub": f"{e['kind']} | ping {(format(e['lat'], '.0f') if e['lat'] else '-')} | err {e['fails']} | {stt}"})
                t.set_rows(rows)

    def on_key(self, win, key, *a):
        """Back button = send to background (keeps the proxy running) instead of killing the app."""
        if key == 27:
            try:
                from jnius import autoclass
                autoclass("org.kivy.android.PythonActivity").mActivity.moveTaskToBack(True); return True
            except Exception:
                return False
        return False

    def close(self):
        """Only saves UI settings. The background service and the VPN deliberately keep running."""
        self.alive = False
        self.cfg.update(port=self.port.text, lan=self.lan.active, frag=self.frag.active, doh=self.doh.active, fport=self.fport.text,
                        flan=self.flan.active, ffrag=self.ffrag.active, fsni=self.fsni.text, sni1=self.sni1.text, n1=self.n1.text,
                        n2=self.n2.text, ver=self.ver.active, sec=self.sec.active,
                        ranges=[l for l in self.rng.text.splitlines() if l.strip()], qlan=self.qlan.active, qsec=self.qsec.active)
        save_cfg(self.cfg)

class NetFreeApp(App):
    title = "NetFree"

    def build(self):
        setup_font(); Window.clearcolor = BG; Window.softinput_mode = "below_target"
        self.ui = UI(); Window.bind(on_keyboard=self.ui.on_key); return self.ui

    def on_pause(self): return True  # keep servers alive in background

    def on_stop(self): self.ui.close()


if __name__ == "__main__":
    NetFreeApp().run()
