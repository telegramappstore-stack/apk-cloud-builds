"""proxycore - find and test free proxies, measure real latency, and export them as links.

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

# Each entry is a group of mirrors for the same list; the first mirror that answers is used.
# jsDelivr mirrors the same GitHub files and is often reachable when raw.githubusercontent.com is not.
SOURCES = {
    "socks5": [
        ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
         "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt"),
        ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
         "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt"),
        ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
         "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt"),
    ],
    # V2Ray / Xray share links (vmess, vless, trojan, ss). Many lists are base64 subscriptions - handled below.
    "v2ray": [
        ("https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
         "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/All_Configs_Sub.txt"),
        ("https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
         "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/All_Configs_Sub.txt"),
        ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
         "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt"),
    ],
    "http": [
        ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
         "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt"),
        ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
         "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/http.txt"),
    ],
}


class Proxy:
    """kind: 'socks5' | 'http' | 'v2ray'. v2ray entries also carry the original share link."""
    __slots__ = ("kind", "host", "port", "ms", "link", "proto", "sec", "sni", "name")

    def __init__(self, kind, host, port, ms=None, link=None, proto=None, sec=None, sni=None, name=None):
        self.kind, self.host, self.port, self.ms = kind, host, int(port), ms
        self.link, self.proto, self.sec, self.sni, self.name = link, proto, sec, sni, name

    @property
    def addr(self):
        return "%s:%d" % (self.host, self.port)

    def to_dict(self):
        return {"kind": self.kind, "host": self.host, "port": self.port, "ms": self.ms, "link": self.link,
                "proto": self.proto, "sec": self.sec, "sni": self.sni, "name": self.name}


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
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
        return r.read(8_000_000).decode("utf-8", "ignore")


def _key(p):
    return p.link or (p.kind, p.host, p.port)


def fetch_candidates(kinds, log=lambda m: None, stop=None):
    out, seen = [], set()
    for kind in kinds:
        for mirrors in SOURCES.get(kind, []):
            for url in mirrors:
                if stop is not None and stop.is_set():
                    return out
                host = url.split("/")[2]
                try:
                    text = fetch_text(url)
                    items = parse_v2ray(text) if kind == "v2ray" else parse_proxies(text, (kind,))
                except Exception as e:
                    log("%s unavailable (%s)" % (host, type(e).__name__))
                    continue
                new = [p for p in items if _key(p) not in seen]
                seen.update(_key(p) for p in new)
                out.extend(new)
                log("%s: %d %s proxies" % (host, len(new), kind))
                break
    return out


def pick_sample(cands, limit):
    """Random sample that keeps the proxy types balanced."""
    by = {}
    for p in cands:
        by.setdefault(p.kind, []).append(p)
    per = max(1, limit // max(1, len(by)))
    out = []
    for lst in by.values():
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
# "ms" is a real round-trip time, not "time to download a page":
#   socks5 / http : latency of a SECOND request sent over the same open connection (client -> proxy -> target -> back).
#                   The first request also pays for TCP connect + SOCKS handshake + the proxy dialing the target, so it is
#                   only used when the proxy closes the connection after one answer.
#   v2ray         : TCP connect time to the server (= the ping to that server).
# direct_ping() measures your own internet the same way, so the numbers are comparable.
DIRECT_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443))


def direct_ping(timeout=2.5, rounds=3):
    """Your own internet latency without any proxy: best TCP connect time (ms) to a public anycast IP, or None."""
    best = None
    for _ in range(rounds):
        for host, port in DIRECT_TARGETS:
            t0 = time.monotonic()
            try:
                s = socket.create_connection((host, port), timeout=timeout)
            except OSError:
                continue
            ms = (time.monotonic() - t0) * 1000.0
            try:
                s.close()
            except OSError:
                pass
            best = ms if best is None else min(best, ms)
            break
    return None if best is None else max(1, int(round(best)))


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _request(host, path, port):
    hh = host if port == 80 else "%s:%d" % (host, port)
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
            % (path, hh)).encode()


def _timed_204(s, req):
    """One request/response over an open socket -> (got_204, milliseconds)."""
    t0 = time.monotonic()
    s.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 4096:
        chunk = s.recv(1024)
        if not chunk:
            break
        buf += chunk
    ms = (time.monotonic() - t0) * 1000.0
    first = buf.split(b"\r\n", 1)[0]
    return first.startswith(b"HTTP/") and b" 204" in first, ms


def _measure(s, req):
    ok, cold = _timed_204(s, req)
    if not ok:
        return None
    try:
        ok2, warm = _timed_204(s, req)                # the real round trip: connection already open
    except OSError:
        return max(1, int(cold))
    return max(1, int(warm if ok2 else cold))


def check_socks5(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
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
        return _measure(s, _request(th, path, tp))
    except (OSError, IndexError, ValueError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def check_http(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        url = "http://%s%s%s" % (th, "" if tp == 80 else ":%d" % tp, path)
        return _measure(s, _request(th, url, tp))                    # absolute-URI form for proxies
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
    """ms = TCP connect time (the ping to the server; DNS and the TLS handshake are not counted).
    Reachability only: whether the config really authenticates is proven by the Xray core when you connect."""
    conn = None
    try:
        ga = _global_addr(p.host, p.port)
        if not ga:
            return None
        s = socket.socket(ga[0], socket.SOCK_STREAM)
        conn = s
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.connect(ga[1])
        ms = max(1, int((time.monotonic() - t0) * 1000))
        if p.sec in ("tls", "reality", "xtls"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(s, server_hostname=p.sni or (None if _is_ip(p.host) else p.host))
        return ms
    except (OSError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def test_many(proxies, on_result, stop, workers=48, timeout=6.0, target=TEST_TARGET):
    """Test proxies in parallel; calls on_result(proxy, ok) as results arrive."""
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
            return [Proxy(d["kind"], d["host"], d["port"], d.get("ms"), d.get("link"), d.get("proto"),
                          d.get("sec"), d.get("sni"), d.get("name")) for d in json.load(f)]
    except (OSError, ValueError, KeyError, TypeError):
        return []
