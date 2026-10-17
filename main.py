"""Proxy Checker (Android / Kivy) - fetch port-3128 proxies from freeproxy.world, test them."""
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.utils import get_color_from_hex

BASE, PORT = "https://www.freeproxy.world/", "3128"
TEST_URL = "https://www.gstatic.com/generate_204"
UA = {"User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"}
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

KV = """
#:import hex kivy.utils.get_color_from_hex
<Pill@Button>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    color: 1, 1, 1, 1
    bold: True
    font_size: '15sp'
    bg: hex('#4F46E5')
    canvas.before:
        Color:
            rgba: self.bg if self.state == 'normal' else [c * 0.8 for c in self.bg]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<Stat@BoxLayout>:
    title: ''
    value: '0'
    tint: hex('#4F46E5')
    orientation: 'vertical'
    padding: dp(6)
    canvas.before:
        Color:
            rgba: 1, 1, 1, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
    Label:
        text: root.value
        color: root.tint
        bold: True
        font_size: '24sp'
    Label:
        text: root.title
        color: hex('#6B7280')
        font_size: '12sp'

BoxLayout:
    orientation: 'vertical'
    padding: dp(16)
    spacing: dp(10)
    Label:
        text: 'Proxy Checker'
        color: hex('#1F2937')
        bold: True
        font_size: '26sp'
        size_hint_y: None
        height: dp(44)
        halign: 'left'
        text_size: self.size
    Label:
        text: 'freeproxy.world  ·  port 3128'
        color: hex('#6B7280')
        font_size: '13sp'
        size_hint_y: None
        height: dp(18)
        halign: 'left'
        text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(76)
        spacing: dp(8)
        Stat:
            id: s_found
            title: 'Found'
        Stat:
            id: s_tested
            title: 'Tested'
            tint: hex('#D97706')
        Stat:
            id: s_ok
            title: 'Working'
            tint: hex('#16A34A')
    ProgressBar:
        id: bar
        max: 1
        size_hint_y: None
        height: dp(8)
    Label:
        id: status
        text: 'Ready.'
        color: hex('#6B7280')
        font_size: '12sp'
        size_hint_y: None
        height: dp(34)
        halign: 'left'
        valign: 'middle'
        text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(50)
        spacing: dp(8)
        Pill:
            id: go
            text: 'Fetch & Test'
            on_release: app.start()
        Pill:
            text: 'Stop'
            bg: hex('#DC2626')
            on_release: app.stop_run()
    BoxLayout:
        size_hint_y: None
        height: dp(50)
        spacing: dp(8)
        Pill:
            text: 'Copy fastest'
            bg: hex('#16A34A')
            on_release: app.copy_best()
        Pill:
            text: 'Wi-Fi settings'
            bg: hex('#374151')
            on_release: app.open_wifi()
    Label:
        text: 'Tap a working proxy to copy it'
        color: hex('#6B7280')
        font_size: '12sp'
        size_hint_y: None
        height: dp(20)
    ScrollView:
        GridLayout:
            id: lst
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(6)
"""


def fetch_page(session, page):
    params = {"type": "", "anonymity": "", "country": "", "speed": "", "port": PORT, "page": page}
    r = session.get(BASE, params=params, timeout=20)
    r.raise_for_status()
    rows = []
    for tr in BeautifulSoup(r.text, "html.parser").select("table tr"):
        td = [t.get_text(" ", strip=True) for t in tr.find_all("td")]
        if len(td) >= 6 and IP_RE.match(td[0]) and td[1] == PORT:
            rows.append((td[0], td[1], td[2]))
    return rows


def test_proxy(ip, port, timeout=8):
    p = f"http://{ip}:{port}"
    t = time.perf_counter()
    try:
        r = requests.get(TEST_URL, proxies={"http": p, "https": p}, headers=UA,
                         timeout=timeout, allow_redirects=False)
        return r.status_code in (200, 204), int((time.perf_counter() - t) * 1000)
    except Exception:
        return False, None


class ProxyApp(App):
    title = "Proxy Checker"

    def build(self):
        Window.clearcolor = get_color_from_hex("#F4F6FB")
        self.q, self.stop, self.running = queue.Queue(), threading.Event(), False
        self.c = {"found": 0, "tested": 0, "ok": 0}
        self.speeds = {}
        self.ui = Builder.load_string(KV)
        Clock.schedule_interval(self.poll, 0.2)
        return self.ui

    # ---- actions
    def start(self):
        if self.running:
            return
        self.ui.ids.lst.clear_widgets()
        self.c = dict.fromkeys(self.c, 0)
        self.speeds.clear()
        self.ui.ids.bar.value = 0
        self.stop.clear()
        self.running = True
        threading.Thread(target=self.worker, daemon=True).start()

    def stop_run(self):
        self.stop.set()
        self.say("Stopping…")

    def say(self, t):
        self.ui.ids.status.text = t

    def copy_best(self):
        if not self.speeds:
            return self.say("No working proxy yet.")
        best = min(self.speeds, key=self.speeds.get)
        Clipboard.copy(best)
        self.say(f"Copied {best}. Wi-Fi settings > your network > Proxy > Manual.")

    def open_wifi(self):
        try:
            from jnius import autoclass
            Intent = autoclass("android.content.Intent")
            Settings = autoclass("android.provider.Settings")
            act = autoclass("org.kivy.android.PythonActivity").mActivity
            act.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
        except Exception:
            self.say("Open Settings > Wi-Fi manually.")

    # ---- background
    def worker(self):
        try:
            session, seen, items = requests.Session(), set(), []
            session.headers.update(UA)
            pages = 3
            for p in range(1, pages + 1):
                if self.stop.is_set():
                    break
                self.q.put(("s", f"Fetching page {p}/{pages}…"))
                try:
                    rows = fetch_page(session, p)
                except Exception as e:
                    self.q.put(("s", f"Fetch failed: {e}"))
                    break
                if not rows:
                    break
                for ip, port, country in rows:
                    if (ip, port) not in seen:
                        seen.add((ip, port))
                        items.append((ip, port, country))
                        self.q.put(("add",))
            if items and not self.stop.is_set():
                self.q.put(("s", f"Testing {len(items)} proxies…"))
                with ThreadPoolExecutor(max_workers=40) as ex:
                    futs = {ex.submit(self.guard, ip, port): (ip, port, c) for ip, port, c in items}
                    for f in as_completed(futs):
                        r = f.result()
                        if r is not None:
                            ip, port, c = futs[f]
                            self.q.put(("res", f"{ip}:{port}", c, r[0], r[1], len(items)))
                    ex.shutdown(cancel_futures=True)
        finally:
            self.q.put(("done",))

    def guard(self, ip, port):
        return None if self.stop.is_set() else test_proxy(ip, port)

    # ---- UI updates
    def poll(self, dt):
        from kivy.factory import Factory
        for _ in range(100):
            try:
                m = self.q.get_nowait()
            except queue.Empty:
                break
            if m[0] == "s":
                self.say(m[1])
            elif m[0] == "add":
                self.c["found"] += 1
            elif m[0] == "res":
                _, key, country, ok, ms, total = m
                self.c["tested"] += 1
                self.ui.ids.bar.value = self.c["tested"] / max(total, 1)
                if ok:
                    self.c["ok"] += 1
                    self.speeds[key] = ms
                    b = Factory.Pill(text=f"{key}   ·   {ms} ms   ·   {country}",
                                     size_hint_y=None, height=48, bg=get_color_from_hex("#16A34A"))
                    b.bind(on_release=lambda w, k=key: (Clipboard.copy(k), self.say(f"Copied {k}")))
                    self.ui.ids.lst.add_widget(b, index=len(self.ui.ids.lst.children))
            elif m[0] == "done":
                self.running = False
                self.say(f"Finished · {self.c['ok']} working of {self.c['found']}")
        i = self.ui.ids
        i.s_found.value, i.s_tested.value, i.s_ok.value = (str(self.c[k]) for k in ("found", "tested", "ok"))


if __name__ == "__main__":
    ProxyApp().run()
