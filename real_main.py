"""Aether WARP - Kivy / Android.  Home = one orb. Registry = account + share settings."""
import base64, datetime, json, shlex, math, urllib.request, uuid, os, select, socket, ssl, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor
from random import random

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, Rectangle
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.utils import platform
from kivy.properties import StringProperty
from kivy.uix.widget import Widget

INTERNAL = 10899  # usque listens here (127.0.0.1 only); our relay exposes the public port
COL = {"off": (.55, .5, 1), "wait": (1, .75, .2), "on": (0, .96, .83)}


# ---------------------------------------------------------------- network helpers
def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise OSError("closed")
        b += c
    return b


def read_addr(s, atyp):
    if atyp == 1: return recv_exact(s, 4)
    if atyp == 4: return recv_exact(s, 16)
    l = recv_exact(s, 1)
    return l + recv_exact(s, l[0])


def tls_ctx():
    """Android has no system CA store for Python -> use certifi."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def x25519(k, u=9):
    p, a24 = 2 ** 255 - 19, 121665
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, "little"); x1 = u; x2, z2, x3, z3, sw = 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1; sw ^= kt
        if sw: x2, x3, z2, z3 = x3, x2, z3, z2
        sw = kt
        A, B = (x2 + z2) % p, (x2 - z2) % p; AA, BB = A * A % p, B * B % p; E = (AA - BB) % p
        C, D = (x3 + z3) % p, (x3 - z3) % p; DA, CB = D * A % p, C * B % p
        x3 = pow(DA + CB, 2, p); z3 = x1 * pow(DA - CB, 2, p) % p
        x2 = AA * BB % p; z2 = E * (AA + a24 * E) % p
    if sw: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def register_warp():
    """Ask Cloudflare for a new WARP account + WireGuard keys (pure python, no extra libs)."""
    sk = os.urandom(32); pub = x25519(sk)
    body = {"key": base64.b64encode(pub).decode(), "install_id": "", "fcm_token": "",
            "tos": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "model": "PC", "serial_number": str(uuid.uuid4()), "locale": "en_US"}
    req = urllib.request.Request("https://api.cloudflareclient.com/v0a2158/reg", json.dumps(body).encode(),
                                 {"User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.3-1922",
                                  "Content-Type": "application/json"})
    acc = json.load(urllib.request.urlopen(req, timeout=20, context=tls_ctx()))
    cfg = acc.get("config", {}); peer = (cfg.get("peers") or [{}])[0]
    ad = cfg.get("interface", {}).get("addresses", {})
    ep = peer.get("endpoint", {}).get("host", "engage.cloudflareclient.com:2408")
    wg = (f"[Interface]\nPrivateKey = {base64.b64encode(sk).decode()}\n"
          f"Address = {ad.get('v4', '')}/32, {ad.get('v6', '')}/128\nDNS = 1.1.1.1\nMTU = 1280\n\n"
          f"[Peer]\nPublicKey = {peer.get('public_key', '')}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ep}\n")
    return {"id": acc.get("id", ""), "license": acc.get("account", {}).get("license", ""), "wg": wg}


def socks_ok(port, timeout=8):
    """Plain SOCKS5 CONNECT to 1.1.1.1:443 (no TLS, no DNS) -> proves the tunnel carries traffic."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00"); recv_exact(s, 2)
        s.sendall(b"\x05\x01\x00\x01" + bytes([1, 1, 1, 1]) + (443).to_bytes(2, "big"))
        return recv_exact(s, 4)[1] == 0
    finally:
        s.close()


def socks5_trace(port, timeout=8):
    """GET cloudflare trace through local usque -> proves traffic goes via WARP."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00"); recv_exact(s, 2)
        h = b"one.one.one.one"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + (443).to_bytes(2, "big"))
        rep = recv_exact(s, 4)
        if rep[1] != 0: raise OSError("connect refused")
        read_addr(s, rep[3]); recv_exact(s, 2)
        t = tls_ctx().wrap_socket(s, server_hostname="one.one.one.one")
        t.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        d = b""
        while True:
            c = t.recv(4096)
            if not c: break
            d += c
        body = d.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
        return dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
    finally:
        s.close()


def tlv(b, i):
    l = b[i + 1]; j = i + 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[j:j + n], "big"); j += n
    return b[i], j, j + l


def spki_of(cert):
    """Pull SubjectPublicKeyInfo (DER) out of an X.509 cert without extra libs."""
    _, i, _ = tlv(cert, 0); _, pos, _ = tlv(cert, i)
    t, s_, e = tlv(cert, pos)
    if t == 0xA0: pos = e
    for _ in range(5): pos = tlv(cert, pos)[2]
    return cert[pos:tlv(cert, pos)[2]]


def pin_of(path):
    pem = json.load(open(path))["endpoint_pub_key"]
    return base64.b64decode("".join(l for l in pem.splitlines() if "-----" not in l))


def check_endpoint(ip, port, pin, sni, timeout=4.0):
    """TLS handshake -> (ms or None, key matches the one usque pins)."""
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as t:
                der = t.getpeercert(binary_form=True)
        return (time.perf_counter() - t0) * 1000, spki_of(der) == pin
    except Exception:
        return None, False


def port_free(bind, port):
    s = socket.socket()
    try:
        s.bind((bind, int(port))); return True
    except OSError:
        return False
    finally:
        s.close()


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


VPN_CLS = "org.aminium.vpn.AminiumVpnService"


def jact():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


def vpn_intent():
    from jnius import autoclass
    return autoclass("android.content.Intent")(jact(), autoclass("java.lang.Class").forName(VPN_CLS))


def fmt(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


class Meter:
    up = down = 0


class Socks5Server:
    """Public SOCKS5 (optional user/pass) -> usque. Counts bytes. TCP CONNECT only."""

    def __init__(self, bind, port, meter, user="", pw=""):
        self.m, self.user, self.pw, self.run = meter, user, pw, True
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, int(port))); self.sock.listen(128)
        threading.Thread(target=self.loop, daemon=True).start()

    def stop(self):
        self.run = False
        try: self.sock.close()
        except OSError: pass

    def loop(self):
        while self.run:
            try: c, _ = self.sock.accept()
            except OSError: break
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        up = None
        try:
            c.settimeout(20)
            recv_exact(c, 1); methods = recv_exact(c, recv_exact(c, 1)[0])
            if self.user:
                if 2 not in methods: c.sendall(b"\x05\xff"); return
                c.sendall(b"\x05\x02"); recv_exact(c, 1)
                u = recv_exact(c, recv_exact(c, 1)[0]).decode(errors="replace")
                p = recv_exact(c, recv_exact(c, 1)[0]).decode(errors="replace")
                if (u, p) != (self.user, self.pw): c.sendall(b"\x01\x01"); return
                c.sendall(b"\x01\x00")
            else:
                if 0 not in methods: c.sendall(b"\x05\xff"); return
                c.sendall(b"\x05\x00")
            head = recv_exact(c, 4)
            addr = read_addr(c, head[3]); port = recv_exact(c, 2)
            if head[1] != 1: c.sendall(b"\x05\x07\x00\x01" + b"\0" * 6); return
            up = socket.create_connection(("127.0.0.1", INTERNAL), timeout=15)
            up.sendall(b"\x05\x01\x00")
            if recv_exact(up, 2) != b"\x05\x00": raise OSError("upstream")
            up.sendall(b"\x05\x01\x00" + bytes([head[3]]) + addr + port)
            rep = recv_exact(up, 4); rest = read_addr(up, rep[3]) + recv_exact(up, 2)
            c.sendall(rep + rest)
            if rep[1] != 0: return
            c.settimeout(None); up.settimeout(None)
            while True:
                r, _, _ = select.select([c, up], [], [], 120)
                if not r: break
                for s in r:
                    d = s.recv(65536)
                    if not d: return
                    if s is c: self.m.up += len(d); up.sendall(d)
                    else: self.m.down += len(d); c.sendall(d)
        except OSError:
            pass
        finally:
            for s in (c, up):
                try: s and s.close()
                except OSError: pass


# ---------------------------------------------------------------- UI widgets
class Space(Widget):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.stars = []
        with self.canvas:
            Color(.03, .02, .10, 1); self.bg = Rectangle()
            Color(.30, .10, .55, .30); self.n1 = Ellipse()
            Color(0, .35, .55, .22); self.n2 = Ellipse()
            for _ in range(90):
                c = Color(1, 1, 1, 1); e = Ellipse()
                self.stars.append((c, e, random(), random(), random() * 2 + 1, random() * 6.28))
        self.bind(size=self.lay, pos=self.lay)
        Clock.schedule_interval(self.twinkle, 1 / 15)

    def lay(self, *a):
        w, h = self.size
        self.bg.pos, self.bg.size = self.pos, self.size
        self.n1.pos, self.n1.size = (-w * .3, h * .55), (w * 1.1, h * .6)
        self.n2.pos, self.n2.size = (w * .2, -h * .15), (w * 1.1, h * .5)
        for c, e, x, y, r, p in self.stars:
            e.pos, e.size = (x * w, y * h), (dp(r), dp(r))

    def twinkle(self, dt):
        t = time.time()
        for c, e, x, y, r, p in self.stars:
            c.a = .3 + .7 * abs(math.sin(t * .8 + p))


class Orb(Widget):
    state = StringProperty("off")

    def __init__(self, **kw):
        super().__init__(**kw)
        self.t = 0
        Clock.schedule_interval(self.tick, 1 / 30)

    def tick(self, dt):
        self.t += dt; self.draw()

    def draw(self):
        self.canvas.clear()
        cx, cy = self.center; R = min(self.width, self.height) * .30
        c, t = COL[self.state], self.t
        pulse = .5 + .5 * math.sin(t * 2) if self.state == "on" else 0
        with self.canvas:
            for i in range(7):
                Color(*c, .05 * (7 - i) / 7 * (1 + pulse))
                rr = R * (1.9 - i * .1); Ellipse(pos=(cx - rr, cy - rr), size=(2 * rr, 2 * rr))
            if self.state == "on":
                for i in range(3):
                    k = (t * .4 + i / 3) % 1
                    Color(*c, (1 - k) * .5); Line(circle=(cx, cy, R * (1.05 + k * .8)), width=dp(1.5))
            Color(*c, .9); Line(circle=(cx, cy, R * 1.12), width=dp(2))
            if self.state == "wait":
                a = (t * 240) % 360
                Color(1, 1, 1, .95); Line(circle=(cx, cy, R * 1.25, a, a + 90), width=dp(3))
            Color(.04, .03, .12, 1); Ellipse(pos=(cx - R, cy - R), size=(2 * R, 2 * R))
            Color(*c, .15 + .1 * pulse); Ellipse(pos=(cx - R, cy - R), size=(2 * R, 2 * R))
            Color(*c, 1)
            Line(circle=(cx, cy, R * .38, 50, 310), width=dp(4), cap="round")
            Line(points=[cx, cy + R * .05, cx, cy + R * .5], width=dp(4), cap="round")

    def on_touch_up(self, touch):
        cx, cy = self.center
        if self.collide_point(*touch.pos) and math.hypot(touch.x - cx, touch.y - cy) < min(self.size) * .4:
            App.get_running_app().toggle(); return True
        return super().on_touch_up(touch)


KV = """
#:import dp kivy.metrics.dp
<Txt@Label>:
    size_hint_y: None
    height: self.texture_size[1] + dp(4)
    text_size: self.width, None
    color: .85, .87, 1, 1
<Card@BoxLayout>:
    orientation: 'vertical'
    padding: dp(14)
    spacing: dp(8)
    size_hint_y: None
    height: self.minimum_height
    canvas.before:
        Color:
            rgba: 1, 1, 1, .06
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(18)]
        Color:
            rgba: .55, .5, 1, .3
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, dp(18))
            width: 1
<Btn@Button>:
    background_normal: ''
    background_color: 0, 0, 0, 0
    size_hint_y: None
    height: dp(46)
    bold: True
    canvas.before:
        Color:
            rgba: (.42, .38, 1, 1) if self.state == 'normal' else (.62, .56, 1, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(23)]
<Field@TextInput>:
    size_hint_y: None
    height: dp(44)
    multiline: False
    background_color: 1, 1, 1, .08
    foreground_color: 1, 1, 1, 1
    cursor_color: 0, .96, .83, 1
    hint_text_color: 1, 1, 1, .35
    padding: dp(12), dp(12)

FloatLayout:
    Space:
    ScreenManager:
        id: sm
        Screen:
            name: 'home'
            BoxLayout:
                orientation: 'vertical'
                padding: dp(20), dp(40), dp(20), dp(20)
                spacing: dp(10)
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    Label:
                        text: 'AMINIUM'
                        bold: True
                        font_size: '22sp'
                        halign: 'left'
                        text_size: self.size
                        valign: 'middle'
                        color: .85, .87, 1, 1
                    Btn:
                        text: 'REGISTRY'
                        size_hint_x: None
                        width: dp(120)
                        on_release: sm.current = 'reg'
                Orb:
                    id: orb
                Label:
                    id: status
                    text: 'TAP TO CONNECT'
                    size_hint_y: None
                    height: dp(30)
                    bold: True
                    font_size: '16sp'
                Card:
                    GridLayout:
                        cols: 2
                        size_hint_y: None
                        height: dp(96)
                        Txt:
                            text: 'DOWNLOAD'
                            font_size: '11sp'
                        Txt:
                            text: 'UPLOAD'
                            font_size: '11sp'
                        Label:
                            id: dl_speed
                            text: '0 B/s'
                            font_size: '20sp'
                            bold: True
                            color: 0, .96, .83, 1
                        Label:
                            id: ul_speed
                            text: '0 B/s'
                            font_size: '20sp'
                            bold: True
                            color: .7, .6, 1, 1
                        Txt:
                            id: dl_total
                            text: 'Total 0 B'
                            font_size: '12sp'
                        Txt:
                            id: ul_total
                            text: 'Total 0 B'
                            font_size: '12sp'
                    Txt:
                        id: timer
                        text: '00:00:00'
                        halign: 'center'
                        font_size: '12sp'
        Screen:
            name: 'reg'
            BoxLayout:
                orientation: 'vertical'
                padding: dp(16), dp(36), dp(16), dp(12)
                spacing: dp(10)
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    Btn:
                        text: '< BACK'
                        size_hint_x: None
                        width: dp(100)
                        on_release: sm.current = 'home'
                    Label:
                        text: 'REGISTRY'
                        bold: True
                        font_size: '20sp'
                ScrollView:
                    BoxLayout:
                        orientation: 'vertical'
                        size_hint_y: None
                        height: self.minimum_height
                        spacing: dp(12)
                        Card:
                            Txt:
                                text: 'WARP ACCOUNT'
                                bold: True
                            Txt:
                                id: acc_state
                                text: '-'
                            Btn:
                                text: 'Register new WARP account'
                                on_release: app.register()
                            Btn:
                                text: 'Delete account'
                                on_release: app.delete_account()
                            Txt:
                                text: 'config.json = made by usque register: it asks Cloudflare for a device, creates your private key and stores key + token + endpoint in the app private folder.'
                                font_size: '11sp'
                            Txt:
                                text: 'Or paste a config.json made on PC with usque.exe:'
                                font_size: '12sp'
                            Field:
                                id: in_cfg
                                hint_text: '{ ... config.json ... }'
                            Btn:
                                text: 'Save pasted config'
                                on_release: app.paste_config()
                        Card:
                            Txt:
                                text: 'GET WARP KEY'
                                bold: True
                            Txt:
                                id: warp_out
                                text: 'Creates a WireGuard WARP account (also works in the official WireGuard app).'
                                font_size: '12sp'
                            Btn:
                                text: 'Get WARP key'
                                on_release: app.get_warp()
                            Btn:
                                text: 'Copy WireGuard config'
                                on_release: app.copy_wg()
                        Card:
                            Txt:
                                text: 'CONNECTION'
                                bold: True
                            BoxLayout:
                                size_hint_y: None
                                height: dp(40)
                                Txt:
                                    text: 'HTTP/2 (use if UDP blocked)'
                                Switch:
                                    id: sw_h2
                                    size_hint_x: None
                                    width: dp(80)
                            BoxLayout:
                                size_hint_y: None
                                height: dp(40)
                                Txt:
                                    text: 'Share SOCKS5 on network'
                                Switch:
                                    id: sw_share
                                    size_hint_x: None
                                    width: dp(80)
                            Field:
                                id: in_port
                                hint_text: 'SOCKS5 port (10820)'
                                input_filter: 'int'
                            Field:
                                id: in_user
                                hint_text: 'username (optional)'
                            Field:
                                id: in_pw
                                hint_text: 'password (optional)'
                                password: True
                            Btn:
                                text: 'Save settings'
                                on_release: app.save()
                        Card:
                            Txt:
                                text: 'CONFIG & PING'
                                bold: True
                            Field:
                                id: in_sni
                                hint_text: 'SNI (e.g. zt-masque.cloudflareclient.com)'
                            Field:
                                id: in_extra
                                hint_text: 'extra usque args (optional)'
                            BoxLayout:
                                size_hint_y: None
                                height: dp(40)
                                Txt:
                                    text: 'L4 mode (l4-socks)'
                                Switch:
                                    id: sw_l4
                                    size_hint_x: None
                                    width: dp(80)
                            Field:
                                id: in_prefix
                                hint_text: 'scan prefixes: 162.159.198, 162.159.192'
                            Btn:
                                text: 'Ping current endpoint'
                                on_release: app.ping_ep()
                            Btn:
                                text: 'Scan endpoints'
                                on_release: app.scan_ep()
                            Btn:
                                text: 'Use best IP in config'
                                on_release: app.apply_ep()
                            Txt:
                                id: scan_out
                                text: 'Ping = TLS over TCP 443 (UDP/QUIC cannot be pinged).'
                                font_size: '12sp'
                        Card:
                            Txt:
                                text: 'SHARE TO V2RAY'
                                bold: True
                            Txt:
                                id: link
                                text: '-'
                            Btn:
                                text: 'Copy socks5:// link'
                                on_release: app.copy_link()
                            Btn:
                                text: 'Copy v2ray outbound JSON'
                                on_release: app.copy_outbound()
                        Card:
                            Txt:
                                text: 'LOG'
                                bold: True
                            Txt:
                                id: log
                                text: ''
                                font_size: '11sp'
"""


# ---------------------------------------------------------------- app
class AetherApp(App):
    def build(self):
        self.title = "AMINIUM"
        Window.clearcolor = (.02, .02, .06, 1)
        Window.bind(on_keyboard=self.on_key)
        self.meter, self.proc, self.srv, self.state, self.t0 = Meter(), None, None, "off", 0
        self.logs, self.last = [], (0, 0)
        self.cfgp = os.path.join(self.user_data_dir, "config.json")
        self.setp = os.path.join(self.user_data_dir, "settings.json")
        self.root = Builder.load_string(KV)
        self.load()
        Clock.schedule_interval(self.stats, 1)
        return self.root

    # ---- helpers
    @property
    def ids(self): return self.root.ids

    def on_key(self, w, key, *a):
        if key == 27 and self.ids.sm.current == "reg":
            self.ids.sm.current = "home"; return True

    def exe(self):
        try:
            from jnius import autoclass
            ctx = autoclass("org.kivy.android.PythonActivity").mActivity
            return os.path.join(ctx.getApplicationInfo().nativeLibraryDir, "libusque.so")
        except Exception:
            return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "usque.exe" if os.name == "nt" else "usque")

    def log(self, msg):
        def add(dt):
            self.logs = (self.logs + [f"[{time.strftime('%H:%M:%S')}] {msg}"])[-25:]
            self.ids.log.text = "\n".join(self.logs)
        Clock.schedule_once(add)

    def set_state(self, st, note=None):
        def do(dt):
            self.state = st
            self.ids.orb.state = st
            self.ids.status.text = note or {"off": "TAP TO CONNECT", "wait": "CONNECTING...", "on": "CONNECTED"}[st]
            self.ids.status.color = COL[st] + (1,)
            if st == "on": self.t0, self.meter.up, self.meter.down = time.time(), 0, 0
            self.refresh_link()
        Clock.schedule_once(do)

    def cfg(self):
        return {"h2": self.ids.sw_h2.active, "share": self.ids.sw_share.active,
                "port": self.ids.in_port.text or "10820",
                "user": self.ids.in_user.text.strip(), "pw": self.ids.in_pw.text,
                "sni": self.ids.in_sni.text.strip(), "extra": self.ids.in_extra.text.strip(),
                "l4": self.ids.sw_l4.active, "prefix": self.ids.in_prefix.text.strip()}

    def load(self):
        try: d = json.load(open(self.setp))
        except (OSError, ValueError): d = {}
        self.ids.sw_h2.active = d.get("h2", True)
        self.ids.sw_share.active = d.get("share", False)
        self.ids.in_port.text = str(d.get("port", "10820"))
        self.ids.in_user.text, self.ids.in_pw.text = d.get("user", ""), d.get("pw", "")
        self.ids.in_sni.text, self.ids.in_extra.text = d.get("sni", ""), d.get("extra", "")
        self.ids.sw_l4.active, self.ids.in_prefix.text = d.get("l4", False), d.get("prefix", "162.159.198")
        self.refresh_link()

    def save(self):
        json.dump(self.cfg(), open(self.setp, "w")); self.refresh_link(); self.log("Settings saved.")

    def link(self):
        c = self.cfg(); ip = lan_ip() if c["share"] else "127.0.0.1"
        auth = f"{c['user']}:{c['pw']}@" if c["user"] else ""
        return ip, c["port"], f"socks5://{auth}{ip}:{c['port']}"

    def refresh_link(self):
        ip, port, url = self.link()
        self.ids.link.text = url + ("" if self.cfg()["share"] else "\n(this phone only - enable sharing for other devices)")
        try:
            c = json.load(open(self.cfgp))
            self.ids.acc_state.text = f"Account READY\nendpoint {c.get('endpoint_v4', '?')}  id {str(c.get('id', ''))[:8]}..."
        except (OSError, ValueError):
            self.ids.acc_state.text = "No account yet - tap Register"

    def copy_link(self):
        Clipboard.copy(self.link()[2]); self.log("socks5 link copied.")

    def copy_outbound(self):
        ip, port, _ = self.link(); c = self.cfg()
        srv = {"address": ip, "port": int(port)}
        if c["user"]: srv["users"] = [{"user": c["user"], "pass": c["pw"]}]
        Clipboard.copy(json.dumps({"tag": "warp", "protocol": "socks", "settings": {"servers": [srv]}}, indent=2))
        self.log("v2ray outbound JSON copied.")

    # ---- registry
    def register(self):
        def work():
            self.log("Registering with Cloudflare...")
            try:
                p = subprocess.Popen([self.exe(), "-c", self.cfgp, "register", "-a", "-n", "aether-android"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, errors="replace")
                try: p.stdin.write("y\n"); p.stdin.close()
                except OSError: pass
                for l in p.stdout: self.log(l.rstrip())
                p.wait()
            except OSError as e:
                self.log(f"Cannot run usque: {e}")
            Clock.schedule_once(lambda dt: self.refresh_link())
        threading.Thread(target=work, daemon=True).start()

    def out(self, msg):
        self.log(msg.splitlines()[0])
        Clock.schedule_once(lambda dt: setattr(self.ids.scan_out, "text", msg))

    def sni(self):
        return self.ids.in_sni.text.strip() or "consumer-masque.cloudflareclient.com"

    def ping_ep(self):
        def work():
            try:
                d = json.load(open(self.cfgp)); pin = pin_of(self.cfgp)
                ip = str(d.get("endpoint_h2_v4") or d.get("endpoint_v4", "")).split(":")[0]
            except Exception as e:
                return self.out(f"Need a valid config first ({type(e).__name__})")
            r = [x for x in (check_endpoint(ip, 443, pin, self.sni()) for _ in range(3)) if x[0]]
            self.out(f"{ip}: " + (f"{min(x[0] for x in r):.0f} ms, key {'OK' if r[0][1] else 'MISMATCH'}"
                                  if r else "no answer - this IP is probably blocked"))
        threading.Thread(target=work, daemon=True).start()

    def scan_ep(self):
        def work():
            try: pin = pin_of(self.cfgp)
            except Exception as e: return self.out(f"Need a valid config first ({type(e).__name__})")
            pre = [p.strip() for p in (self.ids.in_prefix.text or "162.159.198").split(",") if p.strip()]
            self.out("Scanning... (20-60 s)")
            ips = [f"{p}.{i}" for p in pre for i in range(1, 255)]
            with ThreadPoolExecutor(48) as ex:
                res = list(ex.map(lambda ip: (ip,) + check_endpoint(ip, 443, pin, self.sni(), 2.5), ips))
            res = sorted([r for r in res if r[1]], key=lambda r: (not r[2], r[1]))
            good = [r for r in res if r[2]]; self.best = good[0][0] if good else None
            lines = [f"{ip}  {ms:.0f} ms  {'OK' if ok else 'key mismatch'}" for ip, ms, ok in res[:8]]
            self.out(f"{len(res)} answered, {len(good)} genuine.\n" + "\n".join(lines)
                     + (f"\nBest: {self.best} - tap 'Use best IP'" if self.best else ""))
        threading.Thread(target=work, daemon=True).start()

    def apply_ep(self):
        ip = getattr(self, "best", None)
        if not ip: return self.out("Run Scan first.")
        d = json.load(open(self.cfgp)); json.dump(d, open(self.cfgp + ".bak", "w"))
        d["endpoint_v4"] = d["endpoint_h2_v4"] = ip; json.dump(d, open(self.cfgp, "w"), indent=2)
        self.out(f"Endpoint set to {ip} (backup saved). Reconnect.")
        Clock.schedule_once(lambda dt: self.refresh_link())

    def get_warp(self):
        def work():
            self.log("Requesting WARP key from Cloudflare...")
            try:
                r = register_warp(); self.wg = r["wg"]
                txt = f"OK  id {r['id'][:8]}...  license {r['license'] or '-'}\nWireGuard config ready - tap Copy."
                Clock.schedule_once(lambda dt: setattr(self.ids.warp_out, "text", txt))
            except Exception as e:
                self.log(f"Get WARP failed: {type(e).__name__}: {e}")
        threading.Thread(target=work, daemon=True).start()

    def copy_wg(self):
        Clipboard.copy(getattr(self, "wg", "")); self.log("WireGuard config copied.")

    def paste_config(self):
        try:
            json.loads(self.ids.in_cfg.text)
            open(self.cfgp, "w").write(self.ids.in_cfg.text); self.log("config.json saved.")
        except ValueError:
            self.log("That is not valid JSON.")
        self.refresh_link()

    def delete_account(self):
        if self.state == "off" and os.path.exists(self.cfgp): os.remove(self.cfgp)
        self.refresh_link()

    # ---- connect
    def toggle(self):
        if self.state == "off": self.connect()
        else: self.disconnect()

    def connect(self):
        c = self.cfg()
        if not os.path.exists(self.cfgp):
            self.ids.sm.current = "reg"; return self.log("Register a WARP account first.")
        bind = "0.0.0.0" if c["share"] else "127.0.0.1"
        if not port_free(bind, c["port"]) or not port_free("127.0.0.1", INTERNAL):
            return self.log(f"Port {c['port']} or {INTERNAL} is busy. Change the port.")
        self.masque_ok = False
        self.set_state("wait")
        threading.Thread(target=self.run_core, args=(c, bind), daemon=True).start()

    def run_core(self, c, bind):
        l4 = c["l4"]
        args = [self.exe(), "-c", self.cfgp, "l4-socks" if l4 else "socks", "-b", "127.0.0.1", "-p", str(INTERNAL)]
        if c["h2"] and not l4: args.append("--http2")
        if c["sni"] and not l4: args += ["-s", c["sni"]]
        if c["extra"]: args += shlex.split(c["extra"])
        self.log("run: " + " ".join(args[1:]))
        try:
            p = self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                             text=True, errors="replace")
        except OSError as e:
            self.log(f"Cannot run usque: {e}"); return self.set_state("off", "usque not found - see Registry log")
        threading.Thread(target=self.reader, args=(p,), daemon=True).start()
        ok = False
        for _ in range(25):
            if p.poll() is not None: break
            try:
                ok = socks5_trace(INTERNAL, 6).get("warp") in ("on", "plus")
            except Exception as e:
                ok = False
                if self.masque_ok:  # usque says MASQUE is up: accept a plain tunnel test
                    try: ok = socks_ok(INTERNAL)
                    except Exception as e2: e = e2
                if not ok: self.log(f"test: {type(e).__name__}: {e}")
            if ok or self.state == "off": break
            time.sleep(1.5)
        if not ok:
            self.log("Could not reach WARP. Try the HTTP/2 switch or re-register.")
            return Clock.schedule_once(lambda dt: self.disconnect("FAILED - open Registry > LOG"))
        try:
            self.srv = Socks5Server(bind, c["port"], self.meter, c["user"], c["pw"])
        except OSError as e:
            self.log(f"Cannot open port: {e}"); return Clock.schedule_once(lambda dt: self.disconnect())
        self.log("Tunnel to WARP is up.")
        Clock.schedule_once(lambda dt: self.after_core(c))

    # ---- real Android VPN (key icon)
    def after_core(self, c):
        if platform != "android":
            return self.set_state("on")
        try:
            from android import activity
            from jnius import autoclass
            self.vpn_args = c
            it = autoclass("android.net.VpnService").prepare(jact())
            if it is None: return self.vpn_go()
            activity.bind(on_activity_result=self.vpn_result)
            jact().startActivityForResult(it, 7001)
        except Exception as e:
            self.log(f"VPN error: {type(e).__name__}: {e}"); self.disconnect("VPN FAILED - see LOG")

    def vpn_result(self, req, res, data):
        if req != 7001: return
        if res == -1: self.vpn_go()
        else: self.disconnect("VPN permission denied")

    def vpn_go(self):
        try:
            c = self.vpn_args; it = vpn_intent()
            it.putExtra("port", int(c["port"])); it.putExtra("user", c["user"]); it.putExtra("pw", c["pw"])
            jact().startService(it)
            self.log("VPN service started."); self.set_state("on")
        except Exception as e:
            self.log(f"VPN error: {type(e).__name__}: {e}"); self.disconnect("VPN FAILED - see LOG")

    def vpn_stop(self):
        if platform == "android":
            try: jact().stopService(vpn_intent())
            except Exception: pass

    def reader(self, p):
        for l in p.stdout:
            if "connected to masque" in l.lower(): self.masque_ok = True
            self.log("usque: " + l.rstrip())
        if p is self.proc and self.state != "off":
            Clock.schedule_once(lambda dt: self.disconnect())

    def disconnect(self, note=None):
        self.vpn_stop()
        if self.srv: self.srv.stop(); self.srv = None
        p, self.proc = self.proc, None
        if p and p.poll() is None: p.terminate()
        self.set_state("off", note)

    def stats(self, dt):
        up, down = self.meter.up, self.meter.down
        if self.state == "on" and platform == "android" and time.time() - self.t0 > 4:
            try:
                from jnius import autoclass
                if not autoclass(VPN_CLS).running: self.disconnect("VPN stopped - see LOG")
            except Exception:
                pass
        if self.state == "on":
            self.ids.dl_speed.text = fmt(down - self.last[1]) + "/s"
            self.ids.ul_speed.text = fmt(up - self.last[0]) + "/s"
            s = int(time.time() - self.t0)
            self.ids.timer.text = f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
        else:
            self.ids.dl_speed.text = self.ids.ul_speed.text = "0 B/s"
        self.last = (up, down)
        self.ids.dl_total.text, self.ids.ul_total.text = f"Total {fmt(down)}", f"Total {fmt(up)}"

    def on_stop(self):
        self.disconnect()


if __name__ == "__main__":
    AetherApp().run()
