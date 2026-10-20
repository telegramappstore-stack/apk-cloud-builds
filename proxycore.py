"""proxycore - find and test free proxies, and export them as links.

Pure standard library (no Kivy), so it can be tested on a PC and keeps the APK small.
"""
import base64
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# A proxy is "working" only if it can fetch this URL and return HTTP 204 (no body to fake).
TEST_TARGET = ("www.gstatic.com", 80, "/generate_204")

# SOCKS5 / HTTP proxies come ONLY from freeproxy.world (see fetch_freeproxy_world below).
#
# V2Ray configs come ONLY from this single subscription link (a BPB panel, "raw" list for Xray).
V2_SUB_URL = "https://qv2zt7gqgnlgdfg-7vtb1.pages.dev/trqN0NacQe7dAav/sub/raw?app=xray"
V2_NAME_PREFIX = "Amin"          # every config is shown as Amin01, Amin02, ...
CACHE_FILE = None                # set by the app: last good list, used when the link is unreachable


class Proxy:
    """kind: 'socks5' | 'http' | 'v2ray'. v2ray entries also carry the original share link."""
    __slots__ = ("kind", "host", "port", "ms", "link", "proto", "sec", "sni", "name", "tcp", "ok_real", "cc", "country")

    def __init__(self, kind, host, port, ms=None, link=None, proto=None, sec=None, sni=None, name=None):
        self.kind, self.host, self.port, self.ms = kind, host, int(port), ms
        self.link, self.proto, self.sec, self.sni, self.name = link, proto, sec, sni, name
        self.tcp = None
        self.cc = self.country = None   # ISO code + English name (see geolocate)
        self.ok_real = None          # True once a real request went through the Xray core

    @property
    def addr(self):
        return "%s:%d" % (self.host, self.port)

    def to_dict(self):
        return {"kind": self.kind, "host": self.host, "port": self.port, "ms": self.ms, "link": self.link,
                "proto": self.proto, "sec": self.sec, "sni": self.sni, "name": self.name, "tcp": self.tcp, "ok_real": self.ok_real,
                "cc": self.cc, "country": self.country}


# ------------------------------------------------------------------ parsing / fetching
_V2_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")
_ADDR = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")


def parse_proxies(text, kinds=("socks5", "http")):
    """Extract ip:port pairs. A 'socks'/'http' word on the line decides the type, else `kinds` are all tried.
    Private / loopback / link-local addresses are skipped on purpose (a list must not make the phone scan your LAN)."""
    out, seen = [], set()
    for line in text.splitlines():
        if line.lstrip().lower().startswith(_V2_SCHEMES):
            continue
        m = _ADDR.search(line)
        if not m:
            continue
        host, port = m.group(1), int(m.group(2))
        try:
            if not ipaddress.ip_address(host).is_global:
                continue
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        low = line.lower()
        ks = ["socks5"] if "socks" in low else ["http"] if "http" in low else list(kinds)
        for k in ks:
            if (k, host, port) not in seen:
                seen.add((k, host, port))
                out.append(Proxy(k, host, port))
    return out


def _ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def fetch_text(url, timeout=15):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36",
        "Accept": "text/html,text/plain,*/*", "Accept-Language": "en-US,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
        return r.read(8_000_000).decode("utf-8", "ignore")


def _key(p):
    return p.link or (p.kind, p.host, p.port)



# ------------------------------------------------------------------ freeproxy.world
FPW_URL = "https://www.freeproxy.world/?type=%s&anonymity=&country=&speed=&port=%s&page=%d"
_FPW_PAGES = 6                      # 50 rows per page
# Cloudflare edge ranges: the site lists many of them as "http proxies" but they are not open proxies.
_CF_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]
_ROW_SPLIT = re.compile(r"<tr\b|\n(?=\|)", re.I)
_IP = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


def _is_cloudflare(host):
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in _CF_NETS)
    except ValueError:
        return False


def parse_freeproxy_world(html):
    """Rows of the freeproxy.world table (works on the raw HTML and on a text/markdown rendering).
    Every row has links like ?port=80 and ?type=socks5, which is what we read."""
    out, seen = [], set()
    for chunk in _ROW_SPLIT.split(html):
        m = _IP.search(chunk)
        if not m:
            continue
        host = m.group(1)
        pm = re.search(r"[?&]port=(\d{1,5})", chunk)
        if pm:
            port = int(pm.group(1))
        else:
            pm = re.search(re.escape(host) + r"[^\d]{0,80}?(\d{1,5})", chunk)
            port = int(pm.group(1)) if pm else 0
        types = {t.lower() for t in re.findall(r"[?&]type=(http|https|socks4|socks5)\b", chunk, re.I)}
        try:
            ok = ipaddress.ip_address(host).is_global and 1 <= port <= 65535 and not _is_cloudflare(host)
        except ValueError:
            ok = False
        if not ok or not types:
            continue
        kinds = (["socks5"] if "socks5" in types else []) + (["http"] if types & {"http", "https"} else [])
        for k in kinds:                       # socks4-only rows are skipped: Xray/hev need SOCKS5 or HTTP
            if (k, host, port) not in seen:
                seen.add((k, host, port))
                out.append(Proxy(k, host, port))
    return out


def fetch_freeproxy_world(kind, log=lambda m: None, stop=None, pages=_FPW_PAGES, port=None):
    """Download several pages of one proxy type from freeproxy.world. `port` (optional) = only that port."""
    from concurrent.futures import ThreadPoolExecutor
    pages_order = list(range(1, pages + 1))

    def one(n):
        if stop is not None and stop.is_set():
            return []
        try:
            time.sleep(0.25 * (n - 1) % 1.0)            # tiny stagger, be polite to the site
            return parse_freeproxy_world(fetch_text(FPW_URL % (kind, port or "", n), timeout=20))
        except Exception as e:
            log("freeproxy.world page %d (%s): %s" % (n, kind, type(e).__name__))
            return []

    out, seen = [], set()
    with ThreadPoolExecutor(max_workers=3) as ex:
        for items in ex.map(one, pages_order):
            for p in items:
                if p.kind == kind and (not port or p.port == port) and (p.host, p.port) not in seen:
                    seen.add((p.host, p.port))
                    out.append(p)
    log("freeproxy.world: %d %s proxies%s" % (len(out), kind, (" (port %d)" % port) if port else ""))
    return out


def _load_cache():
    if not CACHE_FILE:
        return []
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return parse_v2ray(f.read())
    except OSError:
        return []


def _save_cache(items):
    if not CACHE_FILE or not items:
        return
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(p.link for p in items[:3000]))
    except OSError:
        pass


def _name_all(items):
    for i, p in enumerate(items, 1):
        p.name = "%s%02d" % (V2_NAME_PREFIX, i)
    return items


def fetch_v2ray(log=lambda m: None, stop=None):
    """Download the one subscription link (3 tries) and number the configs Amin01, Amin02, ..."""
    items, err = [], ""
    for n in range(3):
        if stop is not None and stop.is_set():
            return []
        try:
            items = parse_v2ray(fetch_text(V2_SUB_URL, timeout=25))
            if items:
                break
            err = "the link returned no configs"
        except Exception as e:
            err = type(e).__name__
        time.sleep(1.0)
    if items:
        _name_all(items)
        _save_cache(items)
        log("V2Ray subscription: %d configs" % len(items))
        return items
    items = _load_cache()
    if items:
        log("V2Ray subscription unreachable (%s) - using the last saved list (%d configs)." % (err, len(items)))
        return _name_all(items)
    log("V2Ray subscription unreachable (%s)." % err)
    return []


def fetch_candidates(kinds, log=lambda m: None, stop=None, port=None):
    out, seen = [], set()
    for kind in kinds:
        if stop is not None and stop.is_set():
            return out
        if kind in ("socks5", "http"):
            items = fetch_freeproxy_world(kind, log, stop, port=port)
        elif kind == "v2ray":
            items = fetch_v2ray(log, stop)
        else:
            items = []
        for p in items:
            if _key(p) not in seen:
                seen.add(_key(p))
                out.append(p)
    return out


def pick_sample(cands, limit):
    """Random sample that keeps the proxy types balanced."""
    by = {}
    for p in cands:
        by.setdefault(p.kind, []).append(p)
    per = max(1, limit // max(1, len(by)))
    out = []
    for kind, lst in by.items():
        if kind == "v2ray":                       # one small subscription: keep its order (Amin01, Amin02, ...)
            out += lst[:per]
        else:
            random.shuffle(lst)
            out += lst[:per]
    random.shuffle(out)
    return out


# ------------------------------------------------------------------ V2Ray share links
def _b64d(s, lenient=False):
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    if lenient:
        s = s[: len(s) // 4 * 4]                    # a truncated download still decodes up to the cut
    else:
        s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def parse_v2ray_link(line):
    line = line.strip()
    low = line.lower()
    try:
        if low.startswith("vmess://"):
            d = json.loads(_b64d(line[8:]))
            host, port = str(d.get("add", "")).strip(), int(d.get("port"))
            sec = "tls" if str(d.get("tls", "")).lower() in ("tls", "reality", "1", "true") else "none"
            sni = d.get("sni") or d.get("host") or None
            proto, name = "vmess", str(d.get("ps") or "")
        elif low.startswith("ss://"):
            body = line[5:].split("#", 1)[0].split("?", 1)[0]
            if "@" not in body:
                body = _b64d(body)
            host, port = body.rsplit("@", 1)[1].rsplit(":", 1)
            host, port = host.strip("[]"), int(port)
            proto, sec, sni = "ss", "none", None
            name = urllib.parse.unquote(line.split("#", 1)[1]) if "#" in line else ""
        elif low.startswith(("vless://", "trojan://")):
            u = urllib.parse.urlsplit(line)
            q = dict(urllib.parse.parse_qsl(u.query))
            host, port = u.hostname, u.port
            proto = low.split("://", 1)[0]
            sec = (q.get("security") or ("tls" if proto == "trojan" else "none")).lower()
            sni = q.get("sni") or q.get("host") or None
            name = urllib.parse.unquote(u.fragment)
        else:
            return None
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        return None
    if not host or not port or not 1 <= port <= 65535:
        return None
    try:
        if not ipaddress.ip_address(host).is_global:
            return None
    except ValueError:
        pass                                          # a domain name
    return Proxy("v2ray", host, port, link=line, proto=proto, sec=sec, sni=sni, name=name.strip()[:60])


def parse_v2ray(text):
    """Share links from plain text or from a base64 subscription."""
    if not any(sch in text.lower() for sch in _V2_SCHEMES):
        try:
            text = _b64d(text, lenient=True)
        except ValueError:
            return []
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line.lower().startswith(_V2_SCHEMES):
            continue
        p = parse_v2ray_link(line)
        if p and p.link not in seen:
            seen.add(p.link)
            out.append(p)
    return out


# ------------------------------------------------------------------ testing
def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _status_line(s):
    buf = b""
    while b"\n" not in buf and len(buf) < 512:
        chunk = s.recv(256)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0]


def _request(host, path, port):
    hh = host if port == 80 else "%s:%d" % (host, port)
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            % (path, hh)).encode()


def check_socks5(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                                   # no-auth only
        if _recvn(s, 2) != b"\x05\x00":
            return None
        hb = th.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", tp))
        head = _recvn(s, 4)
        if len(head) < 4 or head[0] != 5 or head[1] != 0:
            return None
        atyp = head[3]
        if atyp == 1:
            _recvn(s, 6)
        elif atyp == 4:
            _recvn(s, 18)
        elif atyp == 3:
            _recvn(s, _recvn(s, 1)[0] + 2)
        else:
            return None
        s.sendall(_request(th, path, tp))
        if b" 204" not in _status_line(s):
            return None
        return int((time.monotonic() - t0) * 1000)
    except (OSError, IndexError, ValueError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def check_http(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        url = "http://%s%s%s" % (th, "" if tp == 80 else ":%d" % tp, path)
        s.sendall(_request(th, url, tp))                             # absolute-URI form for proxies
        line = _status_line(s)
        if not line.startswith(b"HTTP/") or b" 204" not in line:
            return None
        return int((time.monotonic() - t0) * 1000)
    except (OSError, ValueError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def _global_addr(host, port):
    """Resolve and accept only public addresses (a config must not aim the phone at your LAN)."""
    for fam, _t, _p, _c, sa in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        try:
            if ipaddress.ip_address(sa[0]).is_global:
                return fam, sa
        except ValueError:
            continue
    return None


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_v2ray(p, timeout=6.0):
    """Reachability only: TCP connect (+ TLS handshake for tls/reality). It cannot prove the config
    authenticates and carries traffic - that needs the Xray core."""
    t0 = time.monotonic()
    conn = None
    try:
        ga = _global_addr(p.host, p.port)
        if not ga:
            return None
        s = socket.socket(ga[0], socket.SOCK_STREAM)
        conn = s
        s.settimeout(timeout)
        s.connect(ga[1])
        if p.sec in ("tls", "reality", "xtls"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(s, server_hostname=p.sni or (None if _is_ip(p.host) else p.host))
        return int((time.monotonic() - t0) * 1000)
    except (OSError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def test_many(proxies, on_result, stop, workers=48, timeout=6.0, target=TEST_TARGET):
    """Test proxies in parallel; calls on_result(proxy, ok) from worker context as results arrive."""
    def job(p):
        if stop.is_set():
            return p, None
        if p.kind == "v2ray":
            return p, check_v2ray(p, timeout)
        fn = check_socks5 if p.kind == "socks5" else check_http
        return p, fn(p.host, p.port, timeout, target)

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futs = [ex.submit(job, p) for p in proxies]
        for f in as_completed(futs):
            if stop.is_set():
                break
            p, ms = f.result()
            if ms is not None:
                p.ms = ms
            on_result(p, ms is not None)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


# ------------------------------------------------------------------ real latency from this phone
def tcp_ping(host, port, timeout=4.0):
    """Time (ms) to open a TCP connection from this device to host:port - the 'raw' distance to the server."""
    t0 = time.monotonic()
    try:
        ga = _global_addr(host, port)
        if not ga:
            return None
        s = socket.socket(ga[0], socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(ga[1])
        finally:
            s.close()
        return int((time.monotonic() - t0) * 1000)
    except (OSError, ValueError):
        return None


def measure(p, samples=3, timeout=6.0, target=TEST_TARGET):
    """Ping measured by THIS phone on ITS internet connection (not a number copied from a website).
    tcp  = connect time to the server;  ms = median time for a full request through it (None if it failed)."""
    vals = []
    for _ in range(samples):
        if p.kind == "v2ray":
            v = check_v2ray(p, timeout)
        elif p.kind == "socks5":
            v = check_socks5(p.host, p.port, timeout, target)
        else:
            v = check_http(p.host, p.port, timeout, target)
        if v is not None:
            vals.append(v)
    vals.sort()
    return {"tcp": tcp_ping(p.host, p.port, min(timeout, 4.0)), "ms": vals[len(vals) // 2] if vals else None,
            "ok": len(vals), "n": samples}


def ping_many(proxies, on_result, stop, samples=3, workers=24, timeout=6.0):
    def job(p):
        return p, (None if stop.is_set() else measure(p, samples, timeout))

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        for f in as_completed([ex.submit(job, p) for p in proxies]):
            if stop.is_set():
                break
            p, r = f.result()
            if r is not None:
                on_result(p, r)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


# ------------------------------------------------------------------ export
def tg_link(p):
    """Telegram only accepts SOCKS5 (and MTProto) proxies through links."""
    return "tg://socks?server=%s&port=%d" % (p.host, p.port) if p.kind == "socks5" else None


def tg_web_link(p):
    return "https://t.me/socks?server=%s&port=%d" % (p.host, p.port) if p.kind == "socks5" else None


def plain_link(p):
    if p.kind == "v2ray":
        return p.link
    return "%s://%s:%d" % ("socks5" if p.kind == "socks5" else "http", p.host, p.port)


def v2ray_link(p):
    if p.kind == "v2ray":
        return p.link
    return "%s://%s:%d#%s" % ("socks" if p.kind == "socks5" else "http", p.host, p.port,
                              "%s-%dms" % (p.kind, p.ms or 0))


def export_text(proxies, fmt):
    fn = {"tg": tg_web_link, "v2ray": v2ray_link, "plain": plain_link}[fmt]
    return "\n".join(x for x in (fn(p) for p in proxies) if x)


def save_results(path, proxies):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([p.to_dict() for p in proxies], f)
    except OSError:
        pass


def load_results(path):
    try:
        with open(path, encoding="utf-8") as f:
            out = []
            for d in json.load(f):
                p = Proxy(d["kind"], d["host"], d["port"], d.get("ms"), d.get("link"), d.get("proto"),
                          d.get("sec"), d.get("sni"), d.get("name"))
                p.tcp = d.get("tcp")
                p.ok_real = d.get("ok_real")
                p.cc, p.country = d.get("cc"), d.get("country")
                out.append(p)
            return out
    except (OSError, ValueError, KeyError, TypeError):
        return []


# ------------------------------------------------------------------ country + flag
GEO_URL = "http://ip-api.com/batch?fields=status,country,countryCode"
FLAG_URL = "https://flagcdn.com/w40/%s.png"
FLAG_DIR = None                 # set by the app (a cache folder)


def geolocate(proxies, stop=None):
    """Fill p.cc / p.country for proxies that have none. One batch request per 100 hosts (the answers keep the
    order of the request, so domain names work too). Silent on failure: no country is shown then."""
    todo = [p for p in proxies if not p.cc]
    hosts = list(dict.fromkeys(p.host for p in todo))
    found = {}
    for i in range(0, len(hosts), 100):
        if stop is not None and stop.is_set():
            break
        chunk = hosts[i:i + 100]
        try:
            req = urllib.request.Request(GEO_URL, data=json.dumps(chunk).encode(),
                                         headers={"Content-Type": "application/json", "User-Agent": "Amizoo"})
            with urllib.request.urlopen(req, timeout=15) as r:
                rows = json.loads(r.read().decode("utf-8", "ignore"))
            for h, row in zip(chunk, rows):
                if row.get("status") == "success" and row.get("countryCode"):
                    found[h] = (row["countryCode"].lower(), row.get("country") or row["countryCode"])
        except Exception:
            continue
    for p in todo:
        if p.host in found:
            p.cc, p.country = found[p.host]


def flag_path(cc):
    """Local PNG of a country flag (downloaded once from flagcdn.com, then cached) or ''."""
    import os
    if not cc or not FLAG_DIR or not cc.isalpha():
        return ""
    path = os.path.join(FLAG_DIR, cc.lower() + ".png")
    if os.path.exists(path):
        return path
    try:
        os.makedirs(FLAG_DIR, exist_ok=True)
        req = urllib.request.Request(FLAG_URL % cc.lower(), headers={"User-Agent": "Amizoo"})
        with urllib.request.urlopen(req, timeout=10, context=_ssl_context()) as r:
            data = r.read(100000)
        if data[:4] != b"\x89PNG":
            return ""
        with open(path, "wb") as f:
            f.write(data)
        return path
    except Exception:
        return ""


def flag_path_cached(cc):
    """Flag PNG only if it is already on disk (never touches the network - safe to call from the UI thread)."""
    import os
    if not cc or not FLAG_DIR or not cc.isalpha():
        return ""
    path = os.path.join(FLAG_DIR, cc.lower() + ".png")
    return path if os.path.exists(path) else ""
