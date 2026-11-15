#!/usr/bin/env python3
"""
aminium_core - network / Cloudflare / scanner backend, shared by the desktop app and the
Kivy/Android app. Pure Python + requests (+ optional qrcode / blake3) - no GUI toolkit import here,
so it runs unmodified under python-for-android.

  Step 1  Token     paste the Cloudflare API token ONCE (kept on this PC; "Change token" lives here)
  Step 2  Clean IPs real scan: TCP + TLS(SNI) + HTTP /cdn-cgi/trace, several rounds, jitter / loss
  Step 3  Build     random name / password / panel path / WS path / secret / UUID are generated on every
                    launch -> deploy the Worker (or Pages) -> the found IPs are re-checked against YOUR new
                    worker with a real WebSocket upgrade -> the best ones are written into the panel,
                    so every generated config uses them
  Step 4  Configs   subscription links (v2ray / Clash / sing-box / Xray / Patt), every single config link,
                    QR codes, and "Save all files"

Install:   pip install customtkinter requests qrcode
Optional:  pip install pillow blake3 certifi      (pillow = QR as PNG, otherwise QR is saved as SVG)
Run:       python aminium_studio.py
Put aminium-pages.zip next to this file (or pick it in step 3).
"""
from __future__ import annotations

import base64
import collections
import dataclasses
import hashlib
import ipaddress
import json
import math
import mimetypes
import os
import queue
import random
import re
import secrets
import socket
import ssl
import statistics
import string
import sys
import threading
import time
import uuid as uuidlib
import webbrowser
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import requests

try:
    import qrcode  # type: ignore
except Exception:  # pragma: no cover
    qrcode = None

try:
    import blake3  # type: ignore
except Exception:  # pragma: no cover
    blake3 = None

APP_NAME = "Aminium Studio"
API = "https://api.cloudflare.com/client/v4"
from kivy.app import App


def app_dir() -> Path:
    """Writable app-private storage: Android's user_data_dir on-device, this file's folder on desktop."""
    priv = os.environ.get("ANDROID_PRIVATE")  # set by python-for-android, valid even before the App exists
    if priv:
        return Path(priv)
    try:
        app = App.get_running_app()
        if app is not None:
            return Path(app.user_data_dir)
    except Exception:
        pass
    return Path(__file__).resolve().parent


APP_DIR = app_dir()
CFG_FILE = APP_DIR / "aminium_studio_config.json"
RESULT_FILE = APP_DIR / "aminium_deploy_result.txt"

TOKEN_TEMPLATE = [
    {"key": "page", "type": "edit"},
    {"key": "workers_kv_storage", "type": "edit"},
    {"key": "d1", "type": "edit"},
    {"key": "workers_scripts", "type": "edit"},
    {"key": "account_settings", "type": "read"},
    {"key": "account_analytics", "type": "read"},
    {"key": "zone", "type": "read"},
    {"key": "dns", "type": "edit"},
]
TOKEN_URL = "https://dash.cloudflare.com/profile/api-tokens"


def token_template_url() -> str:
    keys = quote(json.dumps(TOKEN_TEMPLATE, separators=(",", ":")))
    return f"{TOKEN_URL}?permissionGroupKeys={keys}&name=Aminium%20Studio&accountId=*&zoneId=all"


# ════════════════════════════════════════════════════════════════════════════
#  PART 1 - scanner core (taken unchanged from cf_scanner.py)
# ════════════════════════════════════════════════════════════════════════════

# Official Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4)
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]       # Cloudflare HTTPS ports
PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]  # Cloudflare HTTP ports
SPEED_HOST = "speed.cloudflare.com"
UA = "Mozilla/5.0 (compatible; CF-Clean-IP-Scanner/1.1)"

# ───────────────────────────── configuration ─────────────────────────────
def _num(v, lo, hi, default, cast=int):
    try:
        x = cast(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, x))


def _host(v, default):
    v = str(v or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    return v if re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", v or "") else default


@dataclasses.dataclass
class Config:
    host: str = SPEED_HOST          # SNI + Host header (put your worker domain here for a realistic test)
    port: int = 443
    count: int = 600                # how many IPs to try (neighbours may add up to +50 %)
    threads: int = 32               # too many parallel handshakes choke slow links and everything times out
    timeout: float = 5.0
    rounds: int = 3                 # real test rounds per IP
    target: int = 40                # stop early after this many clean IPs (0 = scan everything)
    mode: str = "spread"            # spread = one IP per /24 block, random = fully random
    custom: str = ""                # extra IPs / CIDR ranges; empty = all Cloudflare ranges
    verify: bool = True             # verify the TLS certificate
    neighbors: bool = True          # probe neighbours of every good IP
    ws: bool = False                # real WebSocket upgrade test
    ws_path: str = "/"
    speed: bool = False             # real download test for the best IPs
    speed_top: int = 10
    speed_bytes: int = 2_000_000
    auto: bool = True               # check the connection first and fix SNI / certificate settings automatically
    force_tls: bool | None = None   # tests only; normally TLS is decided by the port
    fragment: bool = False          # cut the TLS ClientHello into small TCP pieces (same idea as Xray's "fragment")

    @property
    def tls(self) -> bool:
        return self.port not in PLAIN_PORTS if self.force_tls is None else self.force_tls

    @staticmethod
    def from_dict(d: dict) -> "Config":
        d = d or {}
        c = Config()
        c.host = _host(d.get("host"), SPEED_HOST)
        c.port = _num(d.get("port"), 1, 65535, 443)
        c.count = _num(d.get("count"), 1, 5000, 600)
        c.threads = _num(d.get("threads"), 1, 256, 32)
        c.timeout = _num(d.get("timeout"), 0.5, 15, 5.0, float)
        c.rounds = _num(d.get("rounds"), 1, 8, 3)
        c.target = _num(d.get("target"), 0, 2000, 40)
        c.mode = "random" if d.get("mode") == "random" else "spread"
        c.custom = str(d.get("custom") or "")[:20000]
        c.verify = bool(d.get("verify", True))
        c.neighbors = bool(d.get("neighbors", True))
        c.auto = bool(d.get("auto", True))
        c.ws = bool(d.get("ws", False))
        p = str(d.get("ws_path") or "/").strip()
        c.ws_path = p if p.startswith("/") and re.fullmatch(r"[\w\-./%?=&~:@!$+,;]*", p) else "/"
        c.fragment = bool(d.get("fragment", False))
        c.speed = bool(d.get("speed", False))
        c.speed_top = _num(d.get("speed_top"), 1, 50, 10)
        c.speed_bytes = _num(d.get("speed_bytes"), 100_000, 25_000_000, 2_000_000)
        return c


# ───────────────────────────── real probing ─────────────────────────────
class ProbeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _classify(e: BaseException) -> str:
    msg = str(e).lower()
    if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in msg:
        return "timeout"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "cert"
    if isinstance(e, ssl.SSLError):
        return "tls"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    if isinstance(e, OSError):
        return "unreachable"
    return "error"


_CTX: dict = {}


def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    c = _CTX.get(verify)
    if c is None:
        c = ssl.create_default_context()
        try:
            import certifi  # optional
            c.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001
            pass
        if not verify:
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
        try:
            c.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        _CTX[verify] = c
    return c


class _MemTLS:
    """TLS over a plain socket whose first flight (the ClientHello) is cut into small TCP pieces - the same trick as Xray's
    `fragment` (packets=tlshello, length 100-200). Lets the scanner test an IP under the SAME conditions as a client that uses fragment."""
    LEN = (100, 200)
    GAP = (1, 3)   # ms between pieces

    def __init__(self, sock, ctx, host, timeout):
        self.sock = sock
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self._in, self._out, server_hostname=host)
        sock.settimeout(timeout)
        first = True
        while True:
            try:
                self.tls.do_handshake()
                self._flush(False)
                return
            except ssl.SSLWantReadError:
                self._flush(first)
                first = False
                data = sock.recv(65536)
                if not data:
                    raise ConnectionResetError("closed during handshake")
                self._in.write(data)

    def _flush(self, cut):
        data = self._out.read()
        if not data:
            return
        if not cut:
            self.sock.sendall(data)
            return
        i = 0
        while i < len(data):
            n = random.randint(*self.LEN)
            self.sock.sendall(data[i:i + n])
            i += n
            if i < len(data):
                time.sleep(random.uniform(*self.GAP) / 1000.0)

    def sendall(self, data):
        self.tls.write(data)
        self._flush(False)

    def recv(self, n):
        while True:
            try:
                return self.tls.read(n)
            except ssl.SSLWantReadError:
                self._flush(False)
                data = self.sock.recv(65536)
                if data:
                    self._in.write(data)
                else:
                    self._in.write_eof()
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def settimeout(self, t):
        self.sock.settimeout(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@dataclasses.dataclass
class Exchange:
    status: int
    headers: dict
    body: bytes
    tcp_ms: float
    tls_ms: float
    ttfb_ms: float
    body_s: float


def http_exchange(ip, port, host, path, tls, timeout, verify, headers=None,
                  read_body=16384, headers_only=False, max_seconds=None, fragment=False) -> Exchange:
    """One real HTTP/1.1 GET to `ip` (TLS with SNI=host when tls). Raises ProbeError(code)."""
    sock = None
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=timeout)
        t_tcp = time.perf_counter()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls:
            if fragment:
                sock = _MemTLS(sock, _ssl_ctx(verify), host, timeout)
            else:
                sock = _ssl_ctx(verify).wrap_socket(sock, server_hostname=host)
        t_tls = time.perf_counter()
        sock.settimeout(timeout)
        hdrs = {"Host": host, "User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        hdrs.update(headers or {})
        req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        sock.sendall(req.encode())
        t_sent = time.perf_counter()
        buf = sock.recv(65536)
        if not buf:
            raise ProbeError("empty")
        t_first = time.perf_counter()
        while b"\r\n\r\n" not in buf and len(buf) < 32768:
            more = sock.recv(65536)
            if not more:
                break
            buf += more
        head, sep, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", lines[0])
        if not m or not sep:
            raise ProbeError("http")
        hmap = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hmap[k.strip().lower()] = v.strip()
        if not headers_only:
            try:
                want = min(int(hmap.get("content-length", read_body)), read_body)
            except ValueError:
                want = read_body
            while len(body) < want:
                if max_seconds and time.perf_counter() - t_first > max_seconds:
                    break
                try:
                    more = sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not more:
                    break
                body += more
        t_end = time.perf_counter()
        return Exchange(int(m.group(1)), hmap, body, (t_tcp - t0) * 1000, (t_tls - t_tcp) * 1000,
                        (t_first - t_sent) * 1000, t_end - t_first)
    except ProbeError:
        raise
    except Exception as e:  # noqa: BLE001 - every network failure becomes a reason code
        raise ProbeError(_classify(e)) from e
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def parse_trace(body: bytes) -> dict:
    out = {}
    for ln in body.decode("utf-8", "replace").splitlines():
        k, sep, v = ln.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def trace_round(ip: str, cfg: Config) -> dict:
    ex = http_exchange(ip, cfg.port, cfg.host, "/cdn-cgi/trace", cfg.tls, cfg.timeout, cfg.verify, fragment=cfg.fragment)
    is_cf = ex.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in ex.headers
    if not is_cf:
        raise ProbeError("notcf")
    if ex.status >= 500:
        raise ProbeError("http5xx")
    tr = parse_trace(ex.body)
    colo = tr.get("colo") or ex.headers.get("cf-ray", "").rsplit("-", 1)[-1]
    return {"tcp": ex.tcp_ms, "tls": ex.tls_ms, "ttfb": ex.ttfb_ms,
            "total": ex.tcp_ms + ex.tls_ms + ex.ttfb_ms, "colo": colo.upper()[:4], "status": ex.status}


def ws_test(ip: str, cfg: Config) -> bool:
    """Real WebSocket upgrade through this IP to your domain/path: success = HTTP 101."""
    key = base64.b64encode(os.urandom(16)).decode()
    try:
        ex = http_exchange(ip, cfg.port, cfg.host, cfg.ws_path or "/", cfg.tls, cfg.timeout, cfg.verify,
                           headers={"Connection": "Upgrade", "Upgrade": "websocket",
                                    "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"},
                           headers_only=True, fragment=cfg.fragment)
        return ex.status == 101
    except ProbeError:
        return False


def speed_test(ip: str, cfg: Config):
    """Real download through this IP (speed.cloudflare.com). Returns Mbps or None."""
    try:
        ex = http_exchange(ip, cfg.port, SPEED_HOST, f"/__down?bytes={cfg.speed_bytes}", cfg.tls,
                           max(cfg.timeout, 5.0), cfg.verify, read_body=cfg.speed_bytes + 65536, max_seconds=8, fragment=cfg.fragment)
    except ProbeError:
        return None
    if ex.status != 200 or len(ex.body) < 50_000 or ex.body_s <= 0:
        return None
    return round(len(ex.body) * 8 / ex.body_s / 1e6, 1)


def _tcp_try(ip, port, timeout):
    t = time.perf_counter()
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True, round((time.perf_counter() - t) * 1000), ""
    except Exception as e:  # noqa: BLE001
        return False, 0, _classify(e)


def _advice(d: dict, cfg: Config) -> list:
    v, port = d["verdict"], d["port"]
    op = ("پورت‌های بازِ روی شبکه‌ی تو: " + "، ".join(map(str, d["open_ports"])) + ". یکی از همین‌ها را امتحان کن.") if d.get("open_ports") else ""
    if v == "ok":
        return [f"اتصال به کلودفلر سالم است (دامنه‌ی تست: {d['best_host']})."]
    if v == "cert":
        return ["پاسخ کلودفلر می‌رسد ولی گواهی‌اش روی این سیستم تأیید نمی‌شود (ریشه‌ی گواهی در ویندوز نیست یا ساعت سیستم غلط است). اسکن بدون بررسی گواهی ادامه پیدا می‌کند؛ کلودفلر بودن پاسخ همچنان از روی هدرها و /cdn-cgi/trace کنترل می‌شود."]
    if v == "tcp":
        return [f"اتصال TCP به هیچ‌کدام از آی‌پی‌های نمونه‌ی کلودفلر روی پورت {port} برقرار نشد. یعنی اینترنت قطع است، یا VPN/پروکسی/TUN روشن است، یا فایروال/آنتی‌ویروس مانع می‌شود، یا این پورت روی شبکه‌ات بسته است. " + op]
    if v == "tls":
        return [f"TCP وصل می‌شود ولی هندشیک TLS قطع یا کند می‌شود؛ یعنی دامنه‌ی تست (SNI) یا پورت {port} روی این شبکه فیلتر است. دامنه‌ی دیگری (مثل www.cloudflare.com) یا پورت دیگری را امتحان کن. " + op]
    if v == "notcf":
        return ["TLS برقرار می‌شود ولی جواب از کلودفلر نیست؛ احتمالاً پراکسی، فیلتر یا آنتی‌ویروس وسط راه است."]
    return ["اتصال برقرار می‌شود ولی پاسخ HTTP معتبر نمی‌رسد. دامنه‌ی تست یا پورت را عوض کن."]


def diagnose(cfg: Config, samples=None, snis=None, probe_ports=None, workers: int = 12) -> dict:
    """Step-by-step check of THIS network: TCP → TLS(+certificate) → HTTP, for several SNI names.
    Tells which stage breaks and (when possible) which setting fixes it."""
    if samples is None:
        samples = ["1.1.1.1", "1.0.0.1"] + list(iter_targets(Config(count=4, mode="random")))
    if snis is None:
        snis = []
        for h in (cfg.host, SPEED_HOST, "www.cloudflare.com", "cloudflare.com"):
            if h not in snis:
                snis.append(h)
    d = {"at": time.time(), "port": cfg.port, "samples": [], "sni": [], "open_ports": [], "verdict": "", "best_host": None, "advice": []}
    with ThreadPoolExecutor(workers) as ex:
        tcp = list(ex.map(lambda ip: _tcp_try(ip, cfg.port, min(cfg.timeout, 4)), samples))
        d["samples"] = [{"ip": ip, "tcp": ok, "ms": ms, "err": err} for ip, (ok, ms, err) in zip(samples, tcp)]
        live = [x["ip"] for x in d["samples"] if x["tcp"]]

        def one(job):
            sni, ip = job
            c = dataclasses.replace(cfg, host=sni)
            try:
                trace_round(ip, c)
                return sni, "ok"
            except ProbeError as e:
                if e.code == "cert" and cfg.verify:
                    try:
                        trace_round(ip, dataclasses.replace(c, verify=False))
                        return sni, "cert_only"
                    except ProbeError as e2:
                        return sni, e2.code
                return sni, e.code

        res = list(ex.map(one, [(h, ip) for h in snis for ip in live]))
        for h in snis:
            codes = [c for n, c in res if n == h]
            d["sni"].append({"host": h, "ok": codes.count("ok"), "cert_only": codes.count("cert_only"),
                             "errors": dict(collections.Counter(c for c in codes if c not in ("ok", "cert_only")))})
        if not live:
            d["verdict"] = "tcp"
        else:
            okb = max(d["sni"], key=lambda x: (x["ok"], x["host"] == cfg.host))
            cob = max(d["sni"], key=lambda x: (x["cert_only"], x["host"] == cfg.host))
            if okb["ok"] > 0:
                d["verdict"], d["best_host"] = "ok", (cfg.host if any(x["host"] == cfg.host and x["ok"] > 0 for x in d["sni"]) else okb["host"])
            elif cob["cert_only"] > 0:
                d["verdict"], d["best_host"] = "cert", (cfg.host if any(x["host"] == cfg.host and x["cert_only"] > 0 for x in d["sni"]) else cob["host"])
            else:
                allc = collections.Counter()
                for x in d["sni"]:
                    allc.update(x["errors"])
                top = allc.most_common(1)[0][0] if allc else "http"
                d["verdict"] = "tls" if top in ("tls", "timeout", "reset", "empty", "unreachable", "refused") else ("notcf" if top == "notcf" else "http")
        if d["verdict"] in ("tcp", "tls"):
            ports = [p for p in (TLS_PORTS + PLAIN_PORTS if probe_ports is None else probe_ports)]
            ips = [x for x in samples if x not in ("1.1.1.1", "1.0.0.1")][:2] or samples[:1]
            jobs = [(ip, p) for p in ports for ip in ips]
            ans = list(ex.map(lambda j: _tcp_try(j[0], j[1], 2.0)[0], jobs))
            d["open_ports"] = sorted({j[1] for j, ok in zip(jobs, ans) if ok})
    d["advice"] = _advice(d, cfg)
    return d


def scan_ip(ip: str, cfg: Config, stop: threading.Event | None = None):
    """Returns (result_dict | None, reason). Fails fast: a dead IP costs one timeout, not all rounds."""
    rounds, reason = [], "error"
    for i in range(cfg.rounds):
        if stop is not None and stop.is_set():
            return None, "stopped"
        try:
            rounds.append(trace_round(ip, cfg))
        except ProbeError as e:
            reason = e.code
            if i == 0:
                return None, reason
    need = max(1, math.ceil(cfg.rounds * 2 / 3))
    if len(rounds) < need:
        return None, "unstable"
    totals = [r["total"] for r in rounds]
    med = statistics.median(totals)
    jitter = statistics.pstdev(totals) if len(totals) > 1 else 0.0
    loss = 1 - len(rounds) / cfg.rounds
    mid = lambda k: round(statistics.median(r[k] for r in rounds))  # noqa: E731
    res = {
        "ip": ip, "port": cfg.port, "colo": next((r["colo"] for r in rounds if r["colo"]), ""),
        "tcp": mid("tcp"), "tls": mid("tls"), "ttfb": mid("ttfb"), "total": round(med),
        "jitter": round(jitter), "loss": round(loss * 100), "ws": None, "speed": None,
        "score": round(max(0.0, 100 - med / 8 - jitter / 2 - loss * 40)),
    }
    if cfg.ws:
        res["ws"] = ws_test(ip, cfg)
    return res, "ok"


# ───────────────────────────── target generation ─────────────────────────────
def parse_targets(text: str):
    exact, nets = [], []
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        try:
            if "/" in tok:
                n = ipaddress.ip_network(tok, strict=False)
                if n.version == 4:
                    nets.append(n)
            else:
                exact.append(str(ipaddress.ip_address(tok)))
        except ValueError:
            continue
    return exact, nets


def _host_in(block, rng):
    base, size = int(block.network_address), block.num_addresses
    for _ in range(8):
        off = rng.randrange(size)
        if size < 256 or off % 256 not in (0, 255):
            break
    return str(ipaddress.IPv4Address(base + off))


def iter_targets(cfg: Config, rng: random.Random | None = None):
    rng = rng or random.Random()
    exact, nets = parse_targets(cfg.custom)
    if not exact and not nets:
        nets = [ipaddress.ip_network(c) for c in CF_RANGES]
    seen, n = set(), 0
    for ip in exact:
        if ip not in seen and n < cfg.count:
            seen.add(ip)
            n += 1
            yield ip
    if not nets or n >= cfg.count:
        return
    blocks = []
    for net in nets:
        blocks.extend(net.subnets(new_prefix=24) if net.prefixlen < 24 else [net])
    misses, limit = 0, cfg.count * 20 + 1000
    order = blocks[:]
    rng.shuffle(order)
    i = 0
    while n < cfg.count and misses < limit:
        b = order[i % len(order)] if cfg.mode == "spread" else rng.choice(blocks)
        i += 1
        ip = _host_in(b, rng)
        if ip in seen:
            misses += 1
            continue
        seen.add(ip)
        n += 1
        yield ip


def neighbours(ip: str, k: int, seen: set, rng: random.Random):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if a.version != 4:
        return []
    base, out = int(a) & ~255, []
    for _ in range(k * 3):
        c = str(ipaddress.IPv4Address(base + rng.randint(1, 254)))
        if c not in seen:
            out.append(c)
        if len(out) >= k:
            break
    return out


# ───────────────────────────── the scan job ─────────────────────────────
def net_info(timeout: float = 4.0) -> dict:
    """Who does Cloudflare think we are? (shows whether a VPN is on)"""
    try:
        ex = http_exchange("1.1.1.1", 443, "one.one.one.one", "/cdn-cgi/trace", True, timeout, True)
        tr = parse_trace(ex.body)
        is_cf = ex.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in ex.headers
        if ex.status != 200 or not is_cf or not tr.get("ip"):
            return {"ok": False, "error": "notcf"}     # a proxy / filter answered, not Cloudflare
        return {"ok": True, "ip": tr.get("ip", ""), "loc": tr.get("loc", ""), "colo": tr.get("colo", "")}
    except ProbeError as e:
        return {"ok": False, "error": e.code}



# ════════════════════════════════════════════════════════════════════════════
#  PART 2 - Cloudflare API client (taken unchanged from aminium_deployer.py)
# ════════════════════════════════════════════════════════════════════════════
LOWER = string.ascii_lowercase + string.digits


def rnd(n=16, alphabet=string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def rnd_name() -> str:
    """Random project name: starts with a letter, lowercase letters/digits only (valid for Workers/Pages)."""
    return secrets.choice(string.ascii_lowercase) + rnd(9, LOWER)


# search-depth presets used by the scan screen
DEPTH = {
    "Quick":  {"count": 200,  "threads": 24, "target": 15},
    "Normal": {"count": 600,  "threads": 32, "target": 40},
    "Deep":   {"count": 1500, "threads": 48, "target": 100},
}


class CFError(Exception):
    pass


# Extra panel settings written together with the clean IPs (the panel's own defaults already cover
# protocols / fragment / alpn, so nothing extra is needed here; tls + fingerprint are added in run_build).
PANEL_STYLE: dict = {}


# ---- proxies -------------------------------------------------------------------------------------------
#  * manual proxy  : typed by the user, used for the panel (pages.dev / workers.dev) only
#  * auto proxy    : when a connection error happens, working free proxies are fetched from
#                    freeproxy.world (fallback: public lists), tested one by one against Cloudflare and
#                    rotated automatically while the build keeps going.
#  Every request still uses normal HTTPS with certificate checking, so a proxy only sees the tunnel
#  (domain + traffic size), never the password / token inside it.
PANEL_PROXY = ""          # manual
AUTO_PROXY = False        # master switch for the automatic fallback
AUTO_CURRENT = ""         # proxy currently picked by the automatic fallback
PROXY_POOL: list = []
VPN_PROMPT = None         # set by the UI: called when the connection fails and smart connection is OFF; returns True to retry
_VPN_LOCK = threading.Lock()
_PROXY_BAD: set = set()
_PX_LOCK = threading.RLock()
_PX_LOG = print
FREEPROXY_URL = "https://www.freeproxy.world/"
FALLBACK_PROXY_LISTS = [
    ("http", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"),
    ("socks5", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"),
    ("http", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text"),
]
_PX_TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
_SCHEME = {"http": "http", "https": "http", "socks4": "socks4a", "socks5": "socks5h"}
_IPPORT = re.compile(r"(?:(https?|socks4|socks5)://)?((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})")


def normalize_proxy(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    if "://" not in p:
        p = "http://" + p
    p = re.sub(r"^socks5://", "socks5h://", p, flags=re.I)   # let the proxy resolve DNS too
    p = re.sub(r"^socks4://", "socks4a://", p, flags=re.I)
    return p


def set_panel_proxy(p: str) -> str:
    global PANEL_PROXY
    PANEL_PROXY = normalize_proxy(p)
    return PANEL_PROXY


def set_auto_proxy(on: bool) -> None:
    global AUTO_PROXY
    AUTO_PROXY = bool(on)


def set_proxy_logger(fn) -> None:
    global _PX_LOG
    _PX_LOG = fn or print


def effective_proxy(scope: str = "panel") -> str:
    if AUTO_CURRENT:
        return AUTO_CURRENT
    if scope == "panel" and PANEL_PROXY and PANEL_PROXY not in _PROXY_BAD:
        return PANEL_PROXY
    return ""


def _parse_freeproxy_world(html: str, scheme: str) -> list:
    out = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I):
        ip = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", tr)
        if not ip:
            continue
        pt = re.search(r"[?&]port=(\d{2,5})", tr) or re.search(r">\s*(\d{2,5})\s*<", tr)
        if pt:
            out.append(f"{scheme}://{ip.group(1)}:{pt.group(1)}")
    return out


def fetch_free_proxies(log, limit: int = 80) -> list:
    ua = {"User-Agent": "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36"}
    cands: list = []
    for typ in ("https", "socks5", "http"):
        try:
            r = requests.get(FREEPROXY_URL, headers=ua, timeout=15,
                             params={"type": typ, "anonymity": "", "country": "", "speed": "", "port": "", "page": 1})
            got = _parse_freeproxy_world(r.text, _SCHEME[typ]) if r.status_code == 200 else []
            log(f"freeproxy.world [{typ}]: {len(got)} proxies (HTTP {r.status_code})")
            cands += got
        except requests.RequestException as e:
            log(f"freeproxy.world unreachable: {e}")
            break
    if len(cands) < 10:
        for typ, url in FALLBACK_PROXY_LISTS:
            try:
                r = requests.get(url, headers=ua, timeout=15)
                got = []
                for m in _IPPORT.finditer(r.text):
                    got.append(f"{_SCHEME.get((m.group(1) or typ).lower(), 'http')}://{m.group(2)}:{m.group(3)}")
                log(f"backup list: {len(got)} proxies")
                cands += got
            except requests.RequestException as e:
                log(f"backup list unreachable: {e}")
    cands = [x for x in dict.fromkeys(cands) if x not in _PROXY_BAD]
    random.shuffle(cands)
    return cands[:limit]


def _proxy_ok(px: str, timeout: float = 7.0) -> bool:
    try:
        r = requests.get(_PX_TEST_URL, proxies={"http": px, "https": px}, timeout=timeout)
        return r.status_code == 200 and "colo=" in r.text
    except Exception:
        return False


PROXY_CACHE_FILE = APP_DIR / "aminium_proxy_cache.json"
_PX_FAILS: dict = {}
_PX_SEEN: set = set()


def _cache_load() -> list:
    try:
        return [x for x in json.loads(PROXY_CACHE_FILE.read_text(encoding="utf-8")) if isinstance(x, str)][:30]
    except Exception:
        return []


def _cache_save(items: list) -> None:
    try:
        PROXY_CACHE_FILE.write_text(json.dumps(items[:30]), encoding="utf-8")
    except Exception:
        pass


def _note_good(px: str) -> None:
    """A proxy just carried a real request: remember it (also across app restarts) and reset its failure count."""
    _PX_FAILS[px] = 0
    if px not in _PX_SEEN:
        _PX_SEEN.add(px)
        items = [x for x in _cache_load() if x != px]
        _cache_save([px] + items)


def _pick_working(cands: list, want: int, log) -> list:
    good: list = []
    ex = ThreadPoolExecutor(max_workers=24)
    futs = {ex.submit(_proxy_ok, c): c for c in cands}
    try:
        for fu in as_completed(futs):
            if fu.result():
                good.append(futs[fu])
                if len(good) >= want:
                    break
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return good


def refill_proxy_pool(log, want: int = 5) -> list:
    # 1) proxies that worked before (this session or an earlier one) - checked first, they are the most likely to work
    cached = [p for p in _cache_load() if p not in _PROXY_BAD]
    good: list = []
    if cached:
        log(f"Re-checking {len(cached)} proxies that worked before...")
        good = _pick_working(cached, want, log)
        log(f"{len(good)} of them still work.")
    # 2) fresh ones from freeproxy.world (+ backup lists)
    if len(good) < want:
        cands = [x for x in fetch_free_proxies(log) if x not in good]
        if cands:
            log(f"Testing {len(cands)} free proxies against Cloudflare...")
            good += _pick_working(cands, want - len(good), log)
    log(f"{len(good)} working proxies ready.")
    return good


def rotate_proxy(log=None) -> bool:
    """Drop the current proxy and switch to the next working one (fetching new ones when the pool is empty)."""
    global AUTO_CURRENT
    log = log or _PX_LOG
    with _PX_LOCK:
        cur = AUTO_CURRENT or (PANEL_PROXY if PANEL_PROXY not in _PROXY_BAD else "")
        if cur:
            _PROXY_BAD.add(cur)
            _cache_save([x for x in _cache_load() if x != cur])
            log(f"Proxy failed, dropping it: {cur}")
        AUTO_CURRENT = ""
        if not PROXY_POOL:
            log("Connection problem - looking for a working proxy...")
            PROXY_POOL[:] = refill_proxy_pool(log)
        if not PROXY_POOL:
            log("No working proxy could be found right now.")
            return False
        AUTO_CURRENT = PROXY_POOL.pop(0)
        _PX_FAILS[AUTO_CURRENT] = 0
        log(f"Now using proxy: {AUTO_CURRENT}  (it will be reused for every request until it fails)")
        return True


class _RotSession(requests.Session):
    """requests.Session that, on a connection error and with the auto-proxy switch on, rotates to a working
    proxy and retries. A proxy that works is kept and used for EVERYTHING (Cloudflare API, panel, configs)
    until it fails twice in a row - then the next one takes over."""

    def __init__(self, scope: str = "panel"):
        super().__init__()
        self.scope = scope

    def request(self, method, url, **kw):
        t = kw.pop("timeout", 30)
        tries = 0
        while True:
            px = effective_proxy(self.scope)
            if px:
                kw["proxies"] = {"http": px, "https": px}
            else:
                kw.pop("proxies", None)
            to = t
            if AUTO_PROXY and not isinstance(t, tuple):
                to = (15 if px else 10, t)          # fail fast on connect, keep the read timeout
            try:
                r = super().request(method, url, timeout=to, **kw)
                if px and px == AUTO_CURRENT:
                    _note_good(px)
                return r
            except (requests.ConnectionError, requests.Timeout):
                tries += 1
                if not AUTO_PROXY:
                    if VPN_PROMPT is not None and tries <= 3:
                        with _VPN_LOCK:
                            again = bool(VPN_PROMPT(url))
                        if again:
                            continue
                    raise
                if tries > 6:
                    raise
                if px and px == AUTO_CURRENT:
                    _PX_FAILS[px] = _PX_FAILS.get(px, 0) + 1
                    if _PX_FAILS[px] < 2:
                        continue                     # one more chance for a proxy that worked a moment ago
                if not rotate_proxy():
                    raise


def panel_session(ua: str = "Mozilla/5.0 (AminiumStudio)") -> "requests.Session":
    s = _RotSession("panel")
    s.headers["User-Agent"] = ua
    return s


def panel_get(url: str, **kw):
    return panel_session().get(url, **kw)


def check_panel_proxy(log) -> bool:
    if not PANEL_PROXY:
        return True
    try:
        r = panel_get(_PX_TEST_URL, timeout=15)
        ok = r.status_code == 200 and "colo=" in r.text
    except Exception as e:
        log(f"Proxy check failed: {e}")
        return False
    log("Proxy works - panel requests will go through it." if ok else "Proxy answered, but not like Cloudflare.")
    return ok


class CF:
    """Tiny Cloudflare API client."""

    def __init__(self, token: str, log, email: str = ""):
        self.s = _RotSession("api")
        self.global_key = bool(email)
        if email:
            self.s.headers.update({"X-Auth-Email": email, "X-Auth-Key": token})
        else:
            self.s.headers.update({"Authorization": f"Bearer {token}"})
        self.log = log

    def req(self, method, path, **kw):
        url = path if path.startswith("http") else API + path
        for attempt in range(3):
            try:
                r = self.s.request(method, url, timeout=120, **kw)
                break
            except requests.RequestException as e:
                if attempt == 2:
                    raise CFError(f"Network error: {e}")
                time.sleep(2)
        try:
            data = r.json()
        except Exception:
            raise CFError(f"HTTP {r.status_code}: {r.text[:400]}")
        if not data.get("success", False):
            errs = data.get("errors") or []
            msg = "; ".join(f"[{e.get('code')}] {e.get('message')}" for e in errs) or r.text[:400]
            err = CFError(f"{method} {path} -> HTTP {r.status_code}: {msg}")
            err.codes = [e.get("code") for e in errs]
            raise err
        return data

    # ---- account / token
    def verify(self):
        if self.global_key:
            r = self.req("GET", "/user")["result"]
            return {"status": f"active (global key, {r.get('email')})"}
        return self.req("GET", "/user/tokens/verify")["result"]

    def accounts(self):
        return self.req("GET", "/accounts?per_page=50")["result"]

    def usable_accounts(self, accs: list) -> list:
        """Keep only accounts this token can really work in (a probe call per account)."""
        if self.global_key:
            return accs
        ok = []
        for a in accs:
            try:
                self.req("GET", f"/accounts/{a['id']}/storage/kv/namespaces?per_page=1")
                ok.append(a)
            except CFError as e:
                self.log(f"Account {a.get('name')} ({a['id'][:6]}) is not usable with this token: {str(e)[:120]}")
        return ok or accs

    # ---- create a full-permission token (needs Global Key or a token with "API Tokens: Edit")
    def create_full_token(self, acc_id, name):
        groups = self.req("GET", "/user/tokens/permission_groups")["result"]
        wanted = {
            "kv": lambda n: "kv" in n and "write" in n,
            "d1": lambda n: n.startswith("d1") and "write" in n,
            "pages": lambda n: "pages" in n and "write" in n,
            "scripts": lambda n: n == "workers scripts write",
            "settings": lambda n: n == "account settings read",
            "analytics": lambda n: n == "account analytics read",
        }
        picked = {}
        for g in groups:
            n = g.get("name", "").lower()
            scopes = " ".join(g.get("scopes") or [])
            if "com.cloudflare.api.account" not in scopes:
                continue
            for k, fn in wanted.items():
                if k not in picked and fn(n):
                    picked[k] = g
        missing = [k for k in ("kv", "d1", "pages") if k not in picked]
        if missing:
            raise CFError(f"Permission groups not found: {', '.join(missing)}")
        for k, g in picked.items():
            self.log(f"  + {g['name']}")
        body = {
            "name": name,
            "policies": [
                {
                    "effect": "allow",
                    "resources": {f"com.cloudflare.api.account.{acc_id}": "*"},
                    "permission_groups": [{"id": g["id"]} for g in picked.values()],
                }
            ],
        }
        return self.req("POST", "/user/tokens", json=body)["result"]["value"]

    # ---- KV
    def kv_get_or_create(self, acc, title):
        res = self.req("GET", f"/accounts/{acc}/storage/kv/namespaces?per_page=100")["result"]
        for ns in res:
            if ns["title"] == title:
                self.log(f"KV namespace exists: {title}")
                return ns["id"]
        ns = self.req("POST", f"/accounts/{acc}/storage/kv/namespaces", json={"title": title})["result"]
        self.log(f"KV namespace created: {title}")
        return ns["id"]

    # ---- D1
    def d1_get_or_create(self, acc, name):
        res = self.req("GET", f"/accounts/{acc}/d1/database?per_page=100")["result"]
        for db in res:
            if db["name"] == name:
                self.log(f"D1 database exists: {name}")
                return db["uuid"]
        try:
            db = self.req("POST", f"/accounts/{acc}/d1/database", json={"name": name})["result"]
        except CFError as e:
            if re.search(r"limit|maximum|exceed|too many|quota|max", str(e), re.I):
                raise CFError("Cloudflare says this account reached its D1 database limit. Open Saved > Databases, "
                              "delete the ones you do not need, then press Build again.  (" + str(e)[:160] + ")")
            raise
        self.log(f"D1 database created: {name}")
        return db["uuid"]

    def d1_list(self, acc):
        out, page = [], 1
        while page < 20:
            res = self.req("GET", f"/accounts/{acc}/d1/database?per_page=100&page={page}")["result"]
            out += res
            if len(res) < 100:
                break
            page += 1
        return out

    def d1_delete(self, acc, uuid):
        self.req("DELETE", f"/accounts/{acc}/d1/database/{uuid}")
        self.log(f"D1 database deleted: {uuid}")

    def kv_delete(self, acc, ns_id):
        self.req("DELETE", f"/accounts/{acc}/storage/kv/namespaces/{ns_id}")
        self.log(f"KV namespace deleted: {ns_id}")

    # ---- Pages
    def pages_project(self, acc, name):
        try:
            return self.req("GET", f"/accounts/{acc}/pages/projects/{name}")["result"]
        except CFError:
            return None

    def pages_create(self, acc, name):
        return self.req(
            "POST",
            f"/accounts/{acc}/pages/projects",
            json={"name": name, "production_branch": "main"},
        )["result"]

    def pages_configure(self, acc, name, kv_id, d1_id, env_vars):
        cfg = {
            "compatibility_date": "2024-09-23",
            "kv_namespaces": {"KV": {"namespace_id": kv_id}},
            "env_vars": env_vars,
        }
        if d1_id:
            cfg["d1_databases"] = {"DB": {"id": d1_id}}
        body = {"deployment_configs": {"production": cfg, "preview": cfg}}
        return self.req("PATCH", f"/accounts/{acc}/pages/projects/{name}", json=body)["result"]

    def pages_deploy(self, acc, name, files: dict):
        """files: {"_worker.js": bytes, "index.html": bytes, ...}"""
        manifest = {}
        parts = []
        for fname, content in files.items():
            if fname == "_worker.js":
                parts.append(("_worker.js", ("_worker.js", content, "application/javascript")))
                continue
            h = file_hash(fname, content)
            manifest["/" + fname] = h
            ctype = mimetypes.guess_type(fname)[0] or "application/octet-stream"
            parts.append((h, (fname, content, ctype)))
        parts.insert(0, ("manifest", (None, json.dumps(manifest))))
        parts.insert(1, ("branch", (None, "main")))
        return self.req("POST", f"/accounts/{acc}/pages/projects/{name}/deployments", files=parts)["result"]

    def pages_deployment_status(self, acc, name, dep_id):
        return self.req("GET", f"/accounts/{acc}/pages/projects/{name}/deployments/{dep_id}")["result"]

    # ---- Workers (workers.dev)
    def workers_account_subdomain(self, acc, suggest):
        """Return the account's workers.dev subdomain, registering one if the account has none yet."""
        try:
            r = self.req("GET", f"/accounts/{acc}/workers/subdomain").get("result") or {}
            if r.get("subdomain"):
                return r["subdomain"]
        except CFError:
            pass
        base = re.sub(r"[^a-z0-9-]", "", suggest.lower()).strip("-")[:30] or "aminium"
        last = None
        for cand in (base, f"{base}-{rnd(4, string.ascii_lowercase + string.digits)}"):
            try:
                r = self.req("PUT", f"/accounts/{acc}/workers/subdomain", json={"subdomain": cand})["result"]
                self.log(f"workers.dev subdomain registered: {r['subdomain']}")
                return r["subdomain"]
            except CFError as e:
                last = e
        raise last

    def workers_deploy(self, acc, name, js: bytes, kv_id, d1_id, env_vars):
        """Upload an ES-module Worker with KV / D1 bindings and variables / secrets in one multipart request."""
        bindings = [{"type": "kv_namespace", "name": "KV", "namespace_id": kv_id}]
        if d1_id:
            bindings.append({"type": "d1", "name": "DB", "id": d1_id})
        for k, v in env_vars.items():
            bindings.append({"type": v["type"], "name": k, "text": v["value"]})
        meta = {
            "main_module": "worker.js",
            "compatibility_date": "2024-09-23",
            "bindings": bindings,
        }
        parts = [
            ("metadata", (None, json.dumps(meta), "application/json")),
            ("worker.js", ("worker.js", js, "application/javascript+module")),
        ]
        return self.req("PUT", f"/accounts/{acc}/workers/scripts/{name}", files=parts)["result"]

    # ---- custom domain (the domain's zone must be in the same Cloudflare account)
    def zone_for(self, hostname):
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            res = self.req("GET", f"/zones?name={cand}&per_page=1")["result"]
            if res:
                return res[0]["id"]
        return None

    def workers_attach_domain(self, acc, name, hostname, zone_id):
        return self.req(
            "PUT", f"/accounts/{acc}/workers/domains",
            json={"hostname": hostname, "service": name, "zone_id": zone_id, "environment": "production"},
        )

    def pages_attach_domain(self, acc, name, hostname, zone_id, target):
        self.req("POST", f"/accounts/{acc}/pages/projects/{name}/domains", json={"name": hostname})
        try:
            self.req("POST", f"/zones/{zone_id}/dns_records",
                     json={"type": "CNAME", "name": hostname, "content": target, "proxied": True})
        except CFError as e:
            self.log(f"DNS record not created (it may already exist): {e}")

    def workers_delete(self, acc, name):
        return self.req("DELETE", f"/accounts/{acc}/workers/scripts/{name}", params={"force": "true"})

    def pages_delete(self, acc, name):
        return self.req("DELETE", f"/accounts/{acc}/pages/projects/{name}")

    def workers_enable_subdomain(self, acc, name):
        return self.req(
            "POST", f"/accounts/{acc}/workers/scripts/{name}/subdomain",
            json={"enabled": True, "previews_enabled": False},
        )

    def workers_set_cron(self, acc, name, cron="*/15 * * * *"):
        return self.req("PUT", f"/accounts/{acc}/workers/scripts/{name}/schedules", json=[{"cron": cron}])


def file_hash(fname: str, content: bytes) -> str:
    import base64

    ext = Path(fname).suffix.lstrip(".")
    payload = base64.b64encode(content).decode() + ext
    if blake3:
        return blake3.blake3(payload.encode()).hexdigest()[:32]
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def fetch_sub_link(base: str, panel: str, password: str, log, wait: int = 90, ws_path: str = ""):
    """Log in to the freshly deployed panel, make sure a user exists, return (sub_url, user_name)."""
    s = panel_session("Mozilla/5.0 (AminiumDeployer)")
    api = f"{base}{panel}/api"
    deadline = time.time() + wait
    last = ""
    while True:
        try:
            r = s.post(api + "/login", json={"password": password}, timeout=20)
            if r.status_code == 200 and r.json().get("ok"):
                break
            last = f"HTTP {r.status_code}"
            if r.status_code == 401:
                raise CFError("Panel rejected the admin password")
        except requests.RequestException as e:
            last = str(e)
        except ValueError:
            snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))[:160]
            last = f"HTTP {r.status_code}: {snippet}"
            if "1101" in r.text or "Worker threw" in r.text:
                log("Cloudflare error 1101 = the Worker crashed. Open the Worker > Observability > Logs "
                    "(or 'Real-time logs') and send me the red error line.")
        if time.time() > deadline:
            raise CFError(f"Panel not reachable ({last})")
        log(f"Waiting for the panel... ({last})")
        time.sleep(5)
    state = s.get(api + "/state", timeout=20).json()
    if ws_path and (state.get("settings") or {}).get("wsPath") != ws_path:
        r = s.post(api + "/settings", json={"wsPath": ws_path}, timeout=20)
        if r.status_code == 200:
            log(f"WebSocket path set to {ws_path}")
        else:
            log(f"Could not set WebSocket path ({r.status_code}): {r.text[:200]}")
    users = state.get("users") or []
    user = next((u for u in users if u.get("enabled") is not False), None)
    if user is None:
        r = s.post(api + "/users", json={"name": "user1", "days": 0, "limitGB": 0}, timeout=20)
        r.raise_for_status()
        user = r.json()["user"]
        log("No users yet: created 'user1' (unlimited).")
    return f"{base}/sub/{user['token']}", user.get("name", "")


BUILTIN = "@builtin"   # marker meaning "use the panel zip that is baked into the app (panel_data.py)"


def builtin_panel_bytes() -> bytes | None:
    """The panel zip embedded in the APK by embed_panel.py (panel_data.py), or None if not embedded."""
    try:
        import panel_data  # generated by embed_panel.py
        return base64.b64decode("".join(panel_data.PANEL_ZIP_B64.split()))
    except Exception:
        return None


def builtin_available() -> bool:
    return builtin_panel_bytes() is not None


def _files_from_zip(fobj) -> dict:
    files = {}
    with zipfile.ZipFile(fobj) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            files[info.filename.replace("\\", "/")] = z.read(info)
    if "_worker.js" not in files:  # strip a single top-level folder if present
        tops = {n.split("/")[0] for n in files}
        if len(tops) == 1:
            top = tops.pop() + "/"
            files = {n[len(top):]: c for n, c in files.items() if n.startswith(top)}
    return files


def load_source(path: str) -> dict:
    """Load files from the built-in panel, a zip or a folder. Must contain _worker.js."""
    import io
    files = {}
    if not path or path == BUILTIN:
        blob = builtin_panel_bytes()
        if blob is None:
            raise CFError("No panel inside the app and no zip chosen - pick aminium-pages.zip first")
        files = _files_from_zip(io.BytesIO(blob))
    else:
        p = Path(path)
        if p.is_file() and p.suffix.lower() == ".zip":
            files = _files_from_zip(str(p))
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    files[f.relative_to(p).as_posix()] = f.read_bytes()
        else:
            raise CFError("Source must be a .zip file or a folder")
    if "_worker.js" not in files:
        raise CFError("_worker.js not found in the selected source")
    return files



# ════════════════════════════════════════════════════════════════════════════
#  PART 3 - glue: English diagnosis text, scan job, panel client
# ════════════════════════════════════════════════════════════════════════════
def _advice(d: dict, cfg: Config) -> list:  # noqa: F811  (replaces the Persian text of cf_scanner)
    v, port = d["verdict"], d["port"]
    op = ("Ports open on your network: " + ", ".join(map(str, d["open_ports"])) + ". Try one of them.") if d.get("open_ports") else ""
    if v == "ok":
        return [f"Connection to Cloudflare is healthy (test domain: {d['best_host']})."]
    if v == "cert":
        return ["Cloudflare answers but its certificate cannot be verified on this PC (missing root cert or wrong clock). "
                "Scanning continues without certificate check; Cloudflare is still confirmed by headers and /cdn-cgi/trace."]
    if v == "tcp":
        return [f"TCP to Cloudflare sample IPs on port {port} failed: internet down, a VPN/proxy/TUN is on, a firewall/antivirus blocks it, "
                f"or this port is closed on your network. " + op]
    if v == "tls":
        return [f"TCP connects but the TLS handshake dies: the test domain (SNI) or port {port} is filtered here. "
                f"Try another domain (e.g. www.cloudflare.com) or another port. " + op]
    if v == "notcf":
        return ["TLS works but the answer is not from Cloudflare: a proxy, filter or antivirus sits in the middle."]
    return ["Connected, but no valid HTTP answer came back. Change the test domain or the port."]


class ScanJob:
    """Same algorithm as cf_scanner.Scan, with English log lines and a plain log callback."""

    def __init__(self, cfg: Config, log):
        self.cfg = cfg
        self._log = log
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.soft = threading.Event()
        self.results: list = []
        self.reasons = collections.Counter()
        self.tested = 0
        self.total = 0
        self.phase = "idle"
        self.started = 0.0
        self.finished = 0.0
        self.rng = random.Random()
        self.seen: set = set()
        self.cert_fails = 0
        self.diag: dict | None = None
        self.diag_on_empty = True
        self.recent = collections.deque(maxlen=80)   # (ip, ok) of the latest probes - drives the radar

    def log(self, msg):
        self._log(msg)

    def snapshot(self):
        with self.lock:
            end = self.finished or time.time()
            return {"phase": self.phase, "tested": self.tested, "total": self.total,
                    "found": len(self.results), "elapsed": round(end - self.started, 1) if self.started else 0,
                    "results": list(self.results), "reasons": dict(self.reasons),
                    "recent": list(self.recent)}

    def _worker(self, q: queue.PriorityQueue):
        cfg = self.cfg
        while True:
            try:
                _, _, ip = q.get(timeout=0.25)
            except queue.Empty:
                if self.phase != "scanning":
                    return
                continue
            try:
                if self.stop.is_set() or self.soft.is_set():
                    continue
                res, reason = scan_ip(ip, cfg, self.stop)
                with self.lock:
                    self.tested += 1
                    self.recent.append((ip, bool(res)))
                    if res:
                        self.results.append(res)
                        if cfg.target and len(self.results) >= cfg.target:
                            self.soft.set()
                    elif reason != "stopped":
                        self.reasons[reason] += 1
                        if reason == "cert" and cfg.verify and not self.results:
                            self.cert_fails += 1
                            if self.cert_fails == 8:
                                cfg.verify = False
                                self.log("Certificate cannot be verified on this system: check turned off, scan continues.")
                if res and cfg.neighbors and not self.soft.is_set():
                    with self.lock:
                        extra = neighbours(ip, 4, self.seen, self.rng)
                        cap = int(cfg.count * 1.5)
                        extra = extra[: max(0, cap - len(self.seen))]
                        self.seen.update(extra)
                        self.total += len(extra)
                    for e in extra:
                        q.put((0, self.rng.random(), e))
            finally:
                q.task_done()

    def run(self):
        cfg = self.cfg
        self.started = time.time()
        try:
            if cfg.auto:
                self.phase = "diagnosing"
                self.log("Checking the connection to Cloudflare...")
                d = self.diag = diagnose(cfg)
                for a in d["advice"]:
                    self.log(a)
                if d["verdict"] in ("ok", "cert"):
                    best = d["best_host"]
                    if best and best != cfg.host:
                        self.log(f"'{cfg.host}' does not answer on this network; scanning with '{best}' instead.")
                        cfg.host = best
                        if cfg.ws:
                            cfg.ws = False
                            self.log("WebSocket test disabled for this run (your domain could not be tested).")
                    if d["verdict"] == "cert" and cfg.verify:
                        cfg.verify = False
                elif d["verdict"] == "tcp":
                    self.phase = "done"
                    return
            self.phase = "scanning"
            self.log(f"Scan started: {cfg.host}:{cfg.port} ({'TLS' if cfg.tls else 'no TLS'}), {cfg.rounds} rounds per IP")
            q: queue.PriorityQueue = queue.PriorityQueue()
            for ip in iter_targets(cfg, self.rng):
                self.seen.add(ip)
                q.put((1, self.rng.random(), ip))
            self.total = len(self.seen)
            if not self.total:
                self.log("No valid IPs to test (check the custom ranges).")
            threads = [threading.Thread(target=self._worker, args=(q,), daemon=True)
                       for _ in range(min(cfg.threads, max(1, self.total)))]
            for t in threads:
                t.start()
            q.join()
            self.phase = "finishing"
            for t in threads:
                t.join(timeout=2)
            if self.soft.is_set():
                self.log(f"Target reached: {len(self.results)} clean IPs.")
            if cfg.speed and self.results and not self.stop.is_set():
                self.phase = "speed"
                best = sorted(self.results, key=lambda r: -r["score"])[: cfg.speed_top]
                self.log(f"Download speed test for the {len(best)} best IPs...")
                for r in best:
                    if self.stop.is_set():
                        break
                    r["speed"] = speed_test(r["ip"], cfg)
            if not self.results and not self.stop.is_set() and self.diag_on_empty:
                self.phase = "diagnosing"
                self.log("No clean IP found; checking why...")
                d = self.diag = diagnose(cfg)
                if d["verdict"] == "ok":
                    top = ", ".join(f"{k}: {v}" for k, v in self.reasons.most_common(3)) or "-"
                    d["advice"] = [f"Connection is fine but none of this random sample passed (top reasons: {top}). "
                                   "Raise the IP count, lower threads to 16 and raise the timeout to 6-8 s."]
                for a in d["advice"]:
                    self.log(a)
            self.phase = "stopped" if self.stop.is_set() else "done"
            self.log(f"Finished: {len(self.results)} clean IPs out of {self.tested} tested.")
        except Exception as e:  # noqa: BLE001
            self.log(f"Scan error: {e}")
            self.phase = "done"
        finally:
            self.finished = time.time()


def best_ips(results: list, n: int) -> list:
    """Best N IPs by score. If the WebSocket test was on, only IPs that passed it are eligible."""
    ws_tested = any(r.get("ws") is not None for r in results)
    pool = [r for r in results if r.get("ws")] if ws_tested else list(results)
    pool.sort(key=lambda r: -r["score"])
    return [r["ip"] for r in pool[: max(1, n)]]


def panel_login(base: str, panel: str, password: str, log, wait: int = 90):
    s = panel_session("Mozilla/5.0 (AminiumStudio)")
    api = f"{base}{panel}/api"
    deadline, last = time.time() + wait, ""
    while True:
        try:
            r = s.post(api + "/login", json={"password": password}, timeout=20)
            if r.status_code == 200 and r.json().get("ok"):
                return s, api
            last = f"HTTP {r.status_code}"
            if r.status_code == 401:
                raise CFError("Panel rejected the admin password")
        except requests.RequestException as e:
            last = str(e)
        except ValueError:
            last = "non-JSON answer"
        if time.time() > deadline:
            raise CFError(f"Panel not reachable ({last})")
        log(f"Waiting for the panel... ({last})")
        time.sleep(5)


def panel_apply_clean(base: str, panel: str, password: str, ips: list, log, keep_domains: bool = True, extra: dict | None = None):
    """Write clean IPs (+ optional extra settings such as tls / ports / protocols) into the panel.
    Existing CDN domains in the list are kept, old IPs are replaced."""
    s, api = panel_login(base, panel, password, log)
    state = s.get(api + "/state", timeout=20).json()
    cur = (state.get("settings") or {}).get("cleanAddrs") or []
    ipv4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
    keep = [x for x in cur if not ipv4.fullmatch(x)] if keep_domains else []
    new = keep + [ip for ip in ips if ip not in keep]
    body = {"cleanAddrs": new}
    body.update(extra or {})
    r = s.post(api + "/settings", json=body, timeout=30)
    if r.status_code != 200:
        raise CFError(f"Panel refused the settings (HTTP {r.status_code}): {r.text[:200]}")
    log(f"Panel updated: {len(ips)} clean IPs written (kept {len(keep)} existing domain entries).")


def panel_set(base: str, panel: str, password: str, settings: dict, log):
    s, api = panel_login(base, panel, password, log, wait=30)
    r = s.post(api + "/settings", json=settings, timeout=30)
    if r.status_code != 200:
        raise CFError(f"Panel refused the settings (HTTP {r.status_code}): {r.text[:200]}")


# ---- per-network profiles: the panel picks a profile by the ASN of whoever fetches the subscription, so ONE
# subscription can carry different clean IPs / fragment values for MCI, Irancell, Rightel and home internet.
NET_PRESETS = {
    "mci": {"label": "MCI (Hamrah-e-Avval)", "name": "MCI", "asns": [197207], "plmn": "43211",
            "fragment": {"length": "10-30", "interval": "1-2"}},
    "irancell": {"label": "Irancell", "name": "Irancell", "asns": [44244], "plmn": "43235",
                 "fragment": {"length": "10-30", "interval": "1-2"}},
    "rightel": {"label": "Rightel", "name": "Rightel", "asns": [57218], "plmn": "43220",
                "fragment": {"length": "10-30", "interval": "1-2"}},
    "home": {"label": "Home internet (ADSL / Fiber)", "name": "Home",
             "asns": [58224, 12880, 31549, 16322, 43754, 44889, 50810, 48159, 42337, 25184],
             "fragment": {"length": "100-200", "interval": "1-1"}},
}
_DEFAULT_PROFILES = [
    {"name": "MCI", "asns": [197207], "cleanAddrs": [], "ports": [], "fragment": None},
    {"name": "Irancell", "asns": [44244], "cleanAddrs": [], "ports": [], "fragment": None},
    {"name": "Rightel", "asns": [57218], "cleanAddrs": [], "ports": [], "fragment": None},
    {"name": "Shatel", "asns": [31549], "cleanAddrs": [], "ports": [], "fragment": None},
    {"name": "TCI", "asns": [58224, 12880], "cleanAddrs": [], "ports": [], "fragment": None},
]


def valid_frag(length: str, interval: str):
    rng = re.compile(r"^\d{1,4}-\d{1,4}$")
    if rng.match(length or "") and rng.match(interval or ""):
        return {"length": length, "interval": interval}
    return None


def panel_apply_profile(base: str, panel: str, password: str, key: str, ips: list, log, frag: dict | None = None):
    """Write the verified IPs of the network you are on now into that network's profile on the panel."""
    p = NET_PRESETS.get(key)
    if not p or not ips:
        return
    s, api = panel_login(base, panel, password, log)
    state = s.get(api + "/state", timeout=20).json()
    cur = (state.get("settings") or {}).get("ispProfiles")
    if not isinstance(cur, list):
        cur = [dict(x) for x in _DEFAULT_PROFILES]
    out = []
    for pr in cur:
        nm = str(pr.get("name", ""))
        if nm.lower() == p["name"].lower():
            continue
        if key == "home" and nm in ("TCI", "Shatel") and not pr.get("cleanAddrs"):
            continue                                   # replaced by the broader "Home" profile
        pr = dict(pr)
        pr["asns"] = [a for a in (pr.get("asns") or []) if a not in p["asns"]]
        if pr["asns"]:
            out.append(pr)
    out.append({"name": p["name"], "asns": list(p["asns"]), "cleanAddrs": list(ips), "ports": [],
                "fragment": frag or p["fragment"]})
    r = s.post(api + "/settings", json={"ispProfiles": out}, timeout=30)
    if r.status_code != 200:
        raise CFError(f"Panel refused the network profile (HTTP {r.status_code}): {r.text[:200]}")
    fr = frag or p["fragment"]
    log(f"Network profile '{p['name']}' saved: {len(ips)} IPs, fragment {fr['length']} / {fr['interval']}.")


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


# ════════════════════════════════════════════════════════════════════════════
#  PART 4 - delivery helpers (sub formats, raw links, QR)
# ════════════════════════════════════════════════════════════════════════════
FORMATS = [  # key, button label, query, file name (None = no file, link only)
    ("auto", "Auto (recommended)", "", None),
    ("xray", "Xray", "?format=xray", "xray.json"),
    ("clash", "Clash", "?format=clash", "clash.yaml"),
    ("singbox", "sing-box", "?format=singbox", "singbox.json"),
    ("patt", "Patt", "?format=patt", "patt.txt"),
    ("v2ray", "Plain links", "?format=base64", "sub_v2ray.txt"),
]
RAW = "Raw links"
AUTO_NOTE = ("This is the plain subscription link of your panel. Paste it into v2rayN, v2rayNG, Hiddify, Clash, sing-box ... "
             "and the panel sends each app the format that suits it ")
FORMAT_HELP = {
    "auto": "Best choice. Same kind of link the plain deployer gives you: every app receives the right format by itself.",
    "xray": "For Xray-core apps (v2rayN, v2rayNG...).",
    "clash": "For Clash / Mihomo / Stash.",
    "singbox": "For sing-box / Hiddify / Karing.",
    "patt": "For PattNG-style clients (extra TLS disguise).",
    "v2ray": "Plain share links.",
    RAW: "Single share links.",
}


def links_from_base64(raw: str) -> list:
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    except Exception:
        dec = raw
    return [ln.strip() for ln in dec.splitlines() if re.match(r"^[a-z0-9]+://", ln.strip())]


def fetch_configs(sub: str, log) -> dict:
    """Download every subscription format from the panel and decode the raw vless/trojan links."""
    out = {"sub": sub, "text": {}, "links": []}
    out["text"]["auto"] = AUTO_NOTE
    for key, _, q, _ in FORMATS:
        if key == "auto":
            continue
        try:
            r = panel_get(sub + q, timeout=30, headers={"User-Agent": "AminiumStudio"})
            if r.status_code == 200:
                out["text"][key] = r.text
            else:
                log(f"{key}: HTTP {r.status_code}")
        except requests.RequestException as e:
            log(f"{key}: {e}")
    out["links"] = links_from_base64(out["text"].get("v2ray", ""))
    return out


def qr_matrix(text: str):
    if qrcode is None:
        return None
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(text)
    qr.make(fit=True)
    return qr.get_matrix()


def save_qr(text: str, path_no_ext: Path) -> str:
    """PNG when Pillow is present, otherwise SVG. Returns the written file name ('' = no qrcode module)."""
    if qrcode is None:
        return ""
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(text)
    qr.make(fit=True)
    try:
        img = qr.make_image(fill_color="black", back_color="white")
        p = str(path_no_ext) + ".png"
        img.save(p)
        return p
    except Exception:
        import qrcode.image.svg as qsvg  # type: ignore
        img = qr.make_image(image_factory=qsvg.SvgPathImage)
        p = str(path_no_ext) + ".svg"
        img.save(p)
        return p


def save_all(rec: dict, out: dict, log) -> Path:
    folder = APP_DIR / "aminium_output" / rec["project"]
    folder.mkdir(parents=True, exist_ok=True)
    urls = []
    for key, label, q, fname in FORMATS:
        txt = out["text"].get(key)
        if txt is None:
            continue
        if fname:
            (folder / fname).write_text(txt, encoding="utf-8")
        url = out["sub"] + q
        urls.append(f"{label}: {url}")
        save_qr(url, folder / f"qr_{key}")
    (folder / "sub_links.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (folder / "links.txt").write_text("\n".join(out["links"]) + "\n", encoding="utf-8")
    (folder / "panel.txt").write_text(
        f"Panel:    {rec['base']}{rec['panel_path']}\nPassword: {rec['password']}\nSub:      {out['sub']}\n", encoding="utf-8")
    log(f"Saved {len(out['links'])} config links, {len(urls)} subscription formats and QR codes to {folder}")
    return folder


# ════════════════════════════════════════════════════════════════════════════
#  PART 6 - full deploy pipeline (ported from the desktop Wizard.build_worker,
#  logic unchanged - only pulled out of the tkinter class so the Kivy UI can call it)
# ════════════════════════════════════════════════════════════════════════════
def selected_account_id(accounts: list, picked_id: str | None):
    if picked_id:
        for a in accounts:
            if a["id"] == picked_id:
                return a["id"]
    return accounts[0]["id"] if accounts else None


def run_build(token: str, email: str, accounts: list, account_id: str,
              project: str, source: str, panel: str, mode: str, f: dict,
              log, stage) -> dict:
    """Runs the whole deploy pipeline (same steps/order as the desktop app) and returns
    {"rec": rec, "out": out}. Raises CFError / Exception on failure; `log(str)` and
    `stage(text, fraction)` are called for progress, exactly like the desktop version."""
    set_proxy_logger(log)
    if f.get("auto_proxy") is not None:
        set_auto_proxy(f.get("auto_proxy"))
    if f.get("proxy") is not None:
        set_panel_proxy(f.get("proxy"))
    if PANEL_PROXY:
        log("Panel requests (login / users / configs) will use the temporary proxy.")
        check_panel_proxy(log)
    if AUTO_PROXY:
        log("Auto proxy is ON: on a connection error, free proxies are fetched and rotated automatically.")
    cf = CF(token, log, email)
    stage("Checking your token...", 0.04)
    cf.verify()
    if not accounts:
        accounts = cf.accounts()
    acc = selected_account_id(accounts, account_id)
    if not acc:
        raise CFError("No Cloudflare account found for this token")
    log("Using account: " + next((f"{a.get('name')} ({a['id'][:6]})" for a in accounts if a["id"] == acc), acc))
    files = load_source(source)
    log(f"Files: {', '.join(files)}  ({sum(len(v) for v in files.values()) // 1024} KB)")
    if not cf.global_key:
        try:
            cf.req("GET", f"/accounts/{acc}/" + ("workers/scripts" if mode == "workers" else "pages/projects?per_page=1"))
        except CFError as e:
            if "10000" in str(e) or "403" in str(e):
                need = "Workers Scripts: Edit" if mode == "workers" else "Cloudflare Pages: Edit"
                raise CFError(f"Token has no '{need}' permission. Change the token in step 1.")
            raise
        try:
            cf.req("GET", f"/accounts/{acc}/storage/kv/namespaces?per_page=1")
        except CFError:
            raise CFError("Token has no 'Workers KV Storage: Edit' permission.")
        if f["d1"]:
            try:
                cf.req("GET", f"/accounts/{acc}/d1/database?per_page=1")
            except CFError:
                raise CFError("Token has no 'D1: Edit' permission (or untick the D1 option in Advanced).")
    stage("Creating storage (KV / D1)...", 0.14)
    kv_id = cf.kv_get_or_create(acc, f"{project}-kv")
    d1_id = cf.d1_get_or_create(acc, f"{project}-db") if f["d1"] else None
    proj = None
    if mode != "workers":
        proj = cf.pages_project(acc, project)
        if not proj:
            proj = cf.pages_create(acc, project)

    env_vars = {"ADMIN_PASSWORD": {"type": "secret_text", "value": f["pass"]}}

    def add(key, val, secret=False):
        val = (val or "").strip()
        if val:
            env_vars[key] = {"type": "secret_text" if secret else "plain_text", "value": val}
    add("PANEL_PATH", panel)
    if mode != "workers":
        add("CRON_SECRET", f["cron"], True)
    add("UUID", f["uuid"])
    add("DECOY_URL", f["decoy"])
    add("TG_TOKEN", f["tg_token"], True)
    add("TG_SECRET", f["tg_secret"], True)
    add("TG_ADMINS", f["tg_admins"])

    cron_url = ""
    stage("Uploading the panel...", 0.3)
    if mode == "workers":
        cf.workers_deploy(acc, project, files["_worker.js"], kv_id, d1_id, env_vars)
        wsub = cf.workers_account_subdomain(acc, project)
        try:
            cf.workers_enable_subdomain(acc, project)
        except CFError as e:
            log(f"workers.dev route toggle: {e}")
        try:
            cf.workers_set_cron(acc, project)
        except CFError as e:
            log(f"Cron trigger not set (add it in Settings > Triggers): {e}")
        status = "worker:success"
        base = f"https://{project}.{wsub}.workers.dev"
    else:
        cf.pages_configure(acc, project, kv_id, d1_id, env_vars)
        dep = cf.pages_deploy(acc, project, files)
        dep_id = dep.get("id")
        status = "unknown"
        for _ in range(40):
            time.sleep(3)
            try:
                dd = cf.pages_deployment_status(acc, project, dep_id)
            except CFError as e:
                log(f"status check: {e}")
                continue
            st = dd.get("latest_stage", {})
            status = f"{st.get('name')}:{st.get('status')}"
            stage(f"Pages deployment: {status}", 0.4)
            if (st.get("name") == "deploy" and st.get("status") in ("success", "failure")) or st.get("status") == "failure":
                break
        base = f"https://{(proj or {}).get('subdomain') or f'{project}.pages.dev'}"
        if f["cron"]:
            cron_url = f"{base}/cron/{f['cron']}"

    if f["domain"]:
        try:
            zid = cf.zone_for(f["domain"])
            if not zid:
                raise CFError("the domain's zone was not found in this account (token needs Zone: Read)")
            if mode == "workers":
                cf.workers_attach_domain(acc, project, f["domain"], zid)
            else:
                cf.pages_attach_domain(acc, project, f["domain"], zid, base.replace("https://", ""))
            base = f"https://{f['domain']}"
            log(f"Custom domain attached: {f['domain']}")
        except CFError as e:
            log(f"Custom domain failed: {e}  -> keeping {base}")

    panel_path = panel or "/panel"
    stage("Waiting for the panel to come online...", 0.5)
    sub_link, sub_user = fetch_sub_link(base, panel_path, f["pass"], log, ws_path=f["ws_path"])

    host = host_of(base)
    pool, keep_n, ws_path = f["ips"], f["keep"], (f["ws_path"] or "/")
    good: list = []
    warned = False
    if f["verify_ws"] and pool:
        stage("Reading a real signed WebSocket path from the panel...", 0.54)
        try:
            r0 = panel_get(sub_link + "?format=base64", timeout=30, headers={"User-Agent": "AminiumStudio"})
            for ln in links_from_base64(r0.text):
                mt = re.search(r"[?&]path=([^&#]+)", ln)
                if mt:
                    ws_path = unquote(mt.group(1))
                    break
        except Exception as e:
            log(f"Could not read a signed path ({e}); using the plain WS path.")
        modes = [(False, "")]
        scores: dict = {}
        for n, (frag, label) in enumerate(modes):
            stage(f"Testing {len(pool)} IPs on your worker {label}...".replace("  ", " "), 0.58 + 0.12 * n)
            d = dict(f["scan"])
            d.update(host=host, ws=True, ws_path=ws_path, custom="\n".join(pool), count=len(pool), target=0, neighbors=False,
                     auto=False, speed=False, rounds=2, port=443 if f["tls"] else 80, fragment=frag)
            job = ScanJob(Config.from_dict(d), log)
            job.diag_on_empty = False
            job.run()
            rows = [r for r in job.snapshot()["results"] if r["ws"]]
            log(f"{len(rows)} of {len(pool)} IPs reach your worker {label}.".replace("  ", " "))
            for r in rows:
                scores[r["ip"]] = max(scores.get(r["ip"], 0), r["score"] + (1 if frag else 0))
        good = [ip for ip, _ in sorted(scores.items(), key=lambda kv: -kv[1])][:keep_n]
    elif pool:
        good = pool[:keep_n]
    warned = bool(f["verify_ws"] and pool and not good)
    if warned:
        log(f"WARNING: no clean IP could reach your worker from this network . The configs will use "
            f"your worker's own address ({host}), exactly like the plain deployer. If those do not connect either, this "
            "network blocks that domain: deploy to Workers instead of Pages, or attach your own domain (Advanced > Custom domain).")
        stage("No clean IP works with this worker here - configs use its own address.", 0.75)
    addrs = good if good else [host]   # only the found IPs; the Pages/Workers address is used only if no IP works
    stage("Writing the address list and settings into the panel...", 0.84)
    extra = dict(PANEL_STYLE)
    extra.update(tls=f["tls"], fingerprint="chrome")
    panel_apply_clean(base, panel_path, f["pass"], addrs, log, keep_domains=False, extra=extra)
    ips = good
    net = f.get("net")
    if net in NET_PRESETS and ips:
        try:
            panel_apply_profile(base, panel_path, f["pass"], net, ips, log,
                                frag=valid_frag(f.get("frag_len", ""), f.get("frag_int", "")))
        except Exception as e:
            log(f"Network profile not saved ({e}); the default list still works for every network.")

    stage("Generating configs...", 0.92)
    out = fetch_configs(sub_link, log)
    rec = {"project": project, "mode": mode, "account": acc, "base": base, "panel_path": panel_path, "password": f["pass"],
           "sub": sub_link, "ws_path": f["ws_path"], "kv_id": kv_id, "d1_id": d1_id, "ips": ips, "tls": f["tls"],
           "fp": "chrome", "net": f.get("net") or "", "created": time.strftime("%Y-%m-%d %H:%M")}
    text = (f"Aminium deployed ({status})\nSite:        {base}\nPanel:       {base}{panel_path}\nPassword:    {f['pass']}\n"
            f"Sub link:    {sub_link}\nCron URL:    {cron_url or ('(native cron, every 15 min)' if mode == 'workers' else '-')}\n"
            f"Clean IPs:   {len(ips)}\nConfig links: {len(out['links'])}\nKV id:       {kv_id}\nD1 id:       {d1_id or '-'}\n")
    try:
        RESULT_FILE.write_text(text, encoding="utf-8")
    except Exception:
        pass
    for line in text.strip().splitlines():
        log(line)
    if cron_url:
        log("Pages has no Cron Triggers: call the Cron URL every 15 min from cron-job.org (or similar).")
    if not warned:
        stage(f"Done: {len(out['links'])} configs ready.", 1.0)
    return {"rec": rec, "out": out, "warned": warned}


# ════════════════════════════════════════════════════════════════════════════
#  PART 7 - saved-deployments store (the new "manage my configs" feature)
# ════════════════════════════════════════════════════════════════════════════
DEPLOYMENTS_FILE = APP_DIR / "aminium_deployments.json"


def load_deployments() -> list:
    """All configs ever built on this device, newest last - used by the Configs-management screen."""
    try:
        return json.loads(DEPLOYMENTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_deployments(items: list) -> None:
    try:
        DEPLOYMENTS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def add_deployment(rec: dict) -> list:
    items = load_deployments()
    items.append(rec)
    save_deployments(items)
    return items


def rename_deployment(items: list, index: int, new_label: str) -> list:
    if 0 <= index < len(items):
        items[index]["label"] = new_label
        save_deployments(items)
    return items


def delete_deployment(items: list, index: int, token: str = "", email: str = "", log=print,
                       also_remove_remote: bool = False) -> list:
    """Removes a saved config from the local list. If also_remove_remote is True and we still
    have a usable token, also deletes the Worker/Pages project from Cloudflare."""
    if not (0 <= index < len(items)):
        return items
    rec = items[index]
    if also_remove_remote and token:
        try:
            cf = CF(token, log, email)
            if rec.get("mode") == "workers":
                cf.workers_delete(rec["account"], rec["project"])
            else:
                cf.pages_delete(rec["account"], rec["project"])
            log(f"Removed {rec['project']} from Cloudflare too.")
            if rec.get("d1_id"):
                try:
                    cf.d1_delete(rec["account"], rec["d1_id"])
                except Exception as e:
                    log(f"Could not delete its D1 database ({e}).")
            if rec.get("kv_id"):
                try:
                    cf.kv_delete(rec["account"], rec["kv_id"])
                except Exception as e:
                    log(f"Could not delete its KV namespace ({e}).")
        except Exception as e:
            log(f"Could not remove the remote project ({e}); removed from this list only.")
    items.pop(index)
    save_deployments(items)
    return items


def update_deployment_ips(rec: dict, pool: list, scan_form: dict, log, stage=lambda *_: None, keep: int = 100,
                          net: str = "", frag: dict | None = None) -> dict:
    """Re-test `pool` against the saved worker and write the working IPs into its panel.
    Leaves the panel untouched if none of them works from this network."""
    pool = list(dict.fromkeys(pool))
    if not pool:
        raise CFError("No IPs to test - run the Radar first, or the saved list is empty.")
    base, panel_path, password = rec["base"], rec.get("panel_path") or "/panel", rec["password"]
    host, tls = host_of(base), rec.get("tls", True)
    ws_path = rec.get("ws_path") or "/"
    if rec.get("sub"):
        try:
            r0 = panel_get(rec["sub"] + "?format=base64", timeout=30, headers={"User-Agent": "AminiumStudio"})
            for ln in links_from_base64(r0.text):
                mt = re.search(r"[?&]path=([^&#]+)", ln)
                if mt:
                    ws_path = unquote(mt.group(1))
                    break
        except Exception as e:
            log(f"Could not read the signed path ({e}); using the plain WS path.")
    modes = [(False, "")]
    scores: dict = {}
    for n, (frag, label) in enumerate(modes):
        stage(f"Testing {len(pool)} IPs {label}...".replace("  ", " "), 0.2 + 0.3 * n)
        d = dict(scan_form)
        d.update(host=host, ws=True, ws_path=ws_path, custom="\n".join(pool), count=len(pool), target=0, neighbors=False,
                 auto=False, speed=False, rounds=2, port=443 if tls else 80, fragment=frag)
        job = ScanJob(Config.from_dict(d), log)
        job.diag_on_empty = False
        job.run()
        rows = [r for r in job.snapshot()["results"] if r["ws"]]
        log(f"{len(rows)} of {len(pool)} IPs reach the worker {label}.".replace("  ", " "))
        for r in rows:
            scores[r["ip"]] = max(scores.get(r["ip"], 0), r["score"] + (1 if frag else 0))
    good = [ip for ip, _ in sorted(scores.items(), key=lambda kv: -kv[1])][:keep]
    if not good:
        raise CFError("None of these IPs reaches your worker from this network - the panel was left unchanged.")
    stage("Writing the new IPs into the panel...", 0.8)
    extra = dict(PANEL_STYLE)
    extra.update(tls=tls, fingerprint=rec.get("fp", "chrome"))
    panel_apply_clean(base, panel_path, password, good, log, keep_domains=False, extra=extra)
    if net in NET_PRESETS:
        panel_apply_profile(base, panel_path, password, net, good, log, frag=frag)
        rec["net"] = net
    rec["ips"] = good
    rec["updated"] = time.strftime("%Y-%m-%d %H:%M")
    return rec


def replace_deployment(index: int, rec: dict) -> list:
    items = load_deployments()
    if 0 <= index < len(items):
        items[index] = rec
        save_deployments(items)
    return items


def forget_d1(uuid: str) -> None:
    items = load_deployments()
    for r in items:
        if r.get("d1_id") == uuid:
            r["d1_id"] = None
    save_deployments(items)
