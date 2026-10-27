#!/usr/bin/env python3
"""NetFree v2 - Kivy / Android port.
Cloudflare IP scanner + online proxy finder + resilient SOCKS5/HTTP server + Cloudflare-IP forwarder.
Engine is unchanged from netfree_v2.py; only the UI is new (Kivy) and the scan ranges are much larger.
Removed (not possible on Android): Windows system proxy, SNI-spoof (needs WinDivert).
"""
import asyncio, ipaddress, json, os, queue, random, re, socket, ssl, statistics, struct, sys, threading, time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# Android's python has no system CA store -> use certifi for every verified TLS connection
try:
    import certifi
    CAFILE = certifi.where(); os.environ.setdefault("SSL_CERT_FILE", CAFILE)
except Exception:
    CAFILE = None


def _vctx():
    return ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl.create_default_context()


# Scan ranges. Every IP is verified (server: cloudflare / cf-ray) so stale or wrong blocks are simply skipped.
# 1) official published Cloudflare ranges (104.16.0.0/12 = whole CLOUDFLARENET block, wider than the published /13 + /14)
# 2) extra Cloudflare-owned blocks (DNS 1.x, legacy 199.27, 185.146, 45.131 ...) 3) the scattered 8.x edge blocks
CF = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
      "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
      "172.64.0.0/13", "131.0.72.0/22",
      "1.0.0.0/24", "1.1.1.0/24", "199.27.128.0/21", "185.146.172.0/22", "66.235.200.0/24", "45.131.4.0/22", "45.131.208.0/22",
      "8.6.144.0/24", "8.9.231.0/24", "8.10.148.0/24", "8.14.199.0/24", "8.14.202.0/24", "8.17.205.0/24", "8.17.206.0/24",
      "8.18.50.0/24", "8.18.113.0/24", "8.18.194.0/24", "8.19.8.0/24", "8.20.100.0/24", "8.20.101.0/24", "8.20.103.0/24",
      "8.20.122.0/23", "8.20.124.0/23", "8.20.126.0/24", "8.20.253.0/24", "8.21.8.0/22", "8.21.13.0/24", "8.21.110.0/23",
      "8.21.239.0/24", "8.23.139.0/24", "8.24.87.0/24", "8.26.182.0/24", "8.27.64.0/22", "8.28.20.0/24", "8.28.82.0/24",
      "8.28.126.0/24", "8.28.213.0/24", "8.29.105.0/24", "8.29.230.0/23", "8.30.234.0/24", "8.31.2.0/24", "8.31.160.0/24",
      "8.34.69.0/24", "8.34.70.0/24", "8.34.200.0/22", "8.35.57.0/24", "8.35.58.0/23", "8.35.149.0/24", "8.36.216.0/22",
      "8.37.41.0/24", "8.38.147.0/24", "8.38.148.0/23", "8.38.172.0/24", "8.39.6.0/24", "8.39.18.0/24", "8.39.124.0/23",
      "8.39.201.0/24", "8.39.202.0/23", "8.39.204.0/22", "8.39.212.0/22", "8.40.26.0/23", "8.40.29.0/24", "8.40.30.0/23",
      "8.40.107.0/24", "8.40.111.0/24", "8.40.140.0/24", "8.41.5.0/24", "8.41.6.0/23", "8.41.36.0/23", "8.42.51.0/24",
      "8.42.52.0/23", "8.42.54.0/23", "8.42.161.0/24", "8.42.164.0/24", "8.42.172.0/24", "8.42.245.0/24", "8.43.121.0/24",
      "8.43.122.0/23", "8.43.224.0/23", "8.43.226.0/24", "8.44.0.0/22", "8.44.6.0/24", "8.44.58.0/23", "8.44.60.0/22",
      "8.45.41.0/24", "8.45.42.0/23", "8.45.44.0/22", "8.45.97.0/24", "8.45.101.0/24", "8.45.102.0/23", "8.45.108.0/24",
      "8.45.111.0/24", "8.45.144.0/22", "8.46.113.0/24", "8.46.114.0/23", "8.46.117.0/24", "8.46.118.0/23", "8.47.9.0/24",
      "8.47.12.0/22", "8.47.69.0/24", "8.47.71.0/24", "8.48.130.0/23", "8.48.132.0/24", "8.48.134.0/24"]


def merge_nets(nets):
    """Drop overlaps (e.g. 104.16.0.0/13 inside 104.16.0.0/12) so nothing is counted twice."""
    out = []
    for v in (4, 6):
        out += list(ipaddress.collapse_addresses([x for x in nets if x.version == v]))
    return out


def sample_ips(nets, n):
    """Random IPs spread over ALL ranges. weighting by size**0.75 keeps the many small blocks from being drowned out by the huge /12 and /13."""
    n = min(n, sum(x.num_addresses for x in nets)); wts = [x.num_addresses ** 0.75 for x in nets]; out, tries = set(), 0
    while len(out) < n and tries < n * 30:
        x = random.choices(nets, wts)[0]; out.add(str(x[random.randrange(x.num_addresses)])); tries += 1
    return list(out)


RAW = "https://raw.githubusercontent.com/"
SRC = {"SOCKS5": [RAW + "TheSpeedX/PROXY-List/master/socks5.txt", RAW + "monosans/proxy-list/main/proxies/socks5.txt",
                  RAW + "hookzof/socks5_list/master/proxy.txt"],
       "HTTP": [RAW + "TheSpeedX/PROXY-List/master/http.txt", RAW + "monosans/proxy-list/main/proxies/http.txt"]}
SNIS = ["security.vercel.com", "hcaptcha.com", "www.snapp.ir", "snapp.ir", "auth.vercel.com",
        "www.digikala.com", "www.aparat.com", "www.speedtest.net", "cdnjs.cloudflare.com"]
APP_DIR = os.path.join(os.environ.get("ANDROID_PRIVATE") or os.path.expanduser("~"), ".netfree")  # same dir in the UI and the background service
CFG = os.path.join(APP_DIR, "config.json")
IDLE = 300  # seconds of silence before a relayed connection is dropped


def load_cfg():
    try:
        with open(CFG, encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(d):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(CFG, "w", encoding="utf8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


# ---------- probes ----------
def tcp_ping(ip, port=443, t=3):
    s = time.perf_counter()
    try:
        with socket.create_connection((ip, port), t):
            return (time.perf_counter() - s) * 1000
    except OSError:
        return None


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def tls_ping(ip, sni, t=3):
    s = time.perf_counter()
    try:
        with socket.create_connection((ip, 443), t) as c, _ctx().wrap_socket(c, server_hostname=sni):
            return (time.perf_counter() - s) * 1000
    except (OSError, ssl.SSLError):
        return None


def cf_check(ip, sni, t=4):
    """True if the IP really answers like a Cloudflare edge (server: cloudflare / cf-ray)."""
    try:
        with socket.create_connection((ip, 443), t) as c, _ctx().wrap_socket(c, server_hostname=sni) as s:
            s.settimeout(t)
            s.sendall(f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            h = s.recv(2048).lower()
            return b"cloudflare" in h or b"cf-ray" in h
    except (OSError, ssl.SSLError):
        return False


def probe_ip(ip, sni, samples=3, verify=True):
    """Several TLS samples -> median latency, jitter, loss, optional Cloudflare verification."""
    lat = [m for m in (tls_ping(ip, sni, 3) for _ in range(samples)) if m is not None]
    if not lat or 1 - len(lat) / samples > 0.5:
        return None
    if verify and not cf_check(ip, sni):
        return None
    med = statistics.median(lat); jit = max(lat) - min(lat); loss = 1 - len(lat) / samples
    return {"ip": ip, "tls": med, "tcp": tcp_ping(ip) or med, "jit": jit, "ok": f"{len(lat)}/{samples}",
            "score": med + 1.5 * jit + 400 * loss}


def _rn(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x: raise OSError("eof")
        b += x
    return b


def proxy_tunnel(kind, host, port, dh, dp, t=6):
    """Open a tunnel through a SOCKS5/HTTP proxy to dh:dp. Returns a connected socket or None."""
    c = None
    try:
        c = socket.create_connection((host, port), t); c.settimeout(t)
        if kind == "SOCKS5":
            c.sendall(b"\x05\x01\x00")
            if _rn(c, 2) != b"\x05\x00": raise OSError("auth")
            d = dh.encode()
            c.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + struct.pack(">H", dp))
            h = _rn(c, 4)
            if h[1]: raise OSError("refused")
            _rn(c, {1: 6, 4: 18}.get(h[3]) or (_rn(c, 1)[0] + 2))
        else:
            c.sendall(f"CONNECT {dh}:{dp} HTTP/1.1\r\nHost: {dh}:{dp}\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 4096:
                x = c.recv(1024)
                if not x: raise OSError("eof")
                buf += x
            if b" 200" not in buf.split(b"\r\n")[0]: raise OSError("refused")
        return c
    except (OSError, IndexError):
        if c: c.close()
        return None


def proxy_ping(kind, host, port, t=6):
    s0 = time.perf_counter(); c = proxy_tunnel(kind, host, port, "cp.cloudflare.com", 80, t)
    if not c: return None
    try:
        c.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n")
        return (time.perf_counter() - s0) * 1000 if b" 204" in c.recv(256)[:20] else None
    except OSError:
        return None
    finally:
        c.close()


def proxy_probe(kind, host, port, samples=2, t=6):
    """Real latency (several samples) + TLS-integrity check (verified cert through the tunnel => not MITM)."""
    lat = [m for m in (proxy_ping(kind, host, port, t) for _ in range(samples)) if m is not None]
    if not lat: return None
    secure = False
    c = proxy_tunnel(kind, host, port, "cloudflare.com", 443, t)
    if c:
        try:
            with _vctx().wrap_socket(c, server_hostname="cloudflare.com"): secure = True
        except (OSError, ssl.SSLError):
            pass
        finally:
            c.close()
    med = statistics.median(lat); jit = max(lat) - min(lat)
    return {"kind": kind, "addr": f"{host}:{port}", "host": host, "port": port, "lat": med, "jit": jit, "secure": secure,
            "score": med + jit + (0 if secure else 600) + 300 * (1 - len(lat) / samples)}


def fetch_proxies(kind, n, log=None):
    found = set()

    def get(u):
        try:
            return set(re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", urllib.request.urlopen(u, timeout=12, context=_vctx()).read().decode("utf8", "ignore")))
        except Exception as e:
            if log: log(f"دریافت لیست ناموفق: {u.split('/')[4]} ({e.__class__.__name__})")
            return set()
    with ThreadPoolExecutor(4) as ex:
        for r in ex.map(get, SRC[kind]): found |= r
    found = list(found); random.shuffle(found)
    return [(h, int(p)) for h, p in found[:n]]


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as x:
            x.connect(("10.255.255.255", 1)); return x.getsockname()[0]
    except OSError:
        return "127.0.0.1"


_dns = {}


def doh(host):
    """Resolve through Cloudflare DNS-over-HTTPS (1.1.1.1) to dodge poisoned local DNS. Cached 5 min."""
    hit = _dns.get(host)
    if hit and hit[1] > time.time(): return hit[0]
    try:
        req = urllib.request.Request(f"https://1.1.1.1/dns-query?name={host}&type=A", headers={"accept": "application/dns-json"})
        data = json.load(urllib.request.urlopen(req, timeout=4, context=_vctx()))
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        if ips:
            _dns[host] = (ips, time.time() + 300); return ips
    except Exception:
        pass
    return None


def hello(sni):
    """Minimal TLS ClientHello carrying the fake SNI."""
    n = sni.encode()
    ext = b"\x00\x00" + struct.pack(">HHBH", len(n) + 5, len(n) + 3, 0, len(n)) + n
    ext += b"\x00\x0a\x00\x04\x00\x02\x00\x1d" + b"\x00\x0d\x00\x04\x00\x02\x04\x03"
    body = b"\x03\x03" + os.urandom(32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def sni_offset(d):
    """(offset, length) of the SNI hostname inside a TLS ClientHello, or None."""
    try:
        i = 5 + 4 + 2 + 32
        i += 1 + d[i]
        i += 2 + int.from_bytes(d[i:i + 2], "big")
        i += 1 + d[i]
        end = i + 2 + int.from_bytes(d[i:i + 2], "big"); i += 2
        while i + 4 <= min(end, len(d)):
            t = int.from_bytes(d[i:i + 2], "big"); l = int.from_bytes(d[i + 2:i + 4], "big")
            if t == 0: return i + 9, int.from_bytes(d[i + 7:i + 9], "big")
            i += 4 + l
    except Exception:
        pass
    return None


def frag_plan(d):
    """Split the first TLS record so the hostname is cut in the middle (breaks naive DPI matching)."""
    cuts = {1, 5}
    so = sni_offset(d)
    if so: cuts.add(so[0] + max(1, so[1] // 2))
    else: cuts |= {40, 90}
    cuts = sorted(c for c in cuts if 0 < c < len(d))
    parts, prev = [], 0
    for c in cuts: parts.append(d[prev:c]); prev = c
    parts.append(d[prev:]); return parts


async def send_frag(w, d, frag):
    if frag and d[:1] == b"\x16" and len(d) > 60:
        try: w.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception: pass
        for part in frag_plan(d):
            w.write(part); await w.drain(); await asyncio.sleep(random.uniform(0.005, 0.03))
    else:
        w.write(d); await w.drain()


# ---------- pools ----------
class Pool:
    """Thread-safe list of upstream endpoints with health tracking (fail count + exponential cool-down)."""
    def __init__(s): s.items, s.lock = [], threading.Lock()

    def __len__(s): return len(s.items)

    def add(s, kind, host, port, lat=0.0):
        with s.lock:
            for e in s.items:
                if (e["kind"], e["host"], e["port"]) == (kind, host, port):
                    e["lat"] = lat or e["lat"]; return e
            e = {"kind": kind, "host": host, "port": port, "lat": lat, "fails": 0, "until": 0.0}
            s.items.append(e); return e

    def remove(s, e):
        with s.lock:
            if e in s.items: s.items.remove(e)

    def clear(s):
        with s.lock: s.items.clear()

    def snapshot(s):
        with s.lock: return list(s.items)

    def ordered(s):
        now, items = time.time(), s.snapshot()
        live = [e for e in items if e["until"] <= now] or sorted(items, key=lambda e: e["until"])[:1]
        return sorted(live, key=lambda e: (min(e["fails"], 3), e["lat"] or 9e9))

    def good(s, e): e["fails"] = 0; e["until"] = 0.0

    def bad(s, e): e["fails"] += 1; e["until"] = time.time() + min(300, 10 * 2 ** min(e["fails"], 5))

    def mark(s, e, ms):
        if ms: e["lat"] = ms; s.good(e)
        else: s.bad(e)


class Stats:
    def __init__(s): s.up = s.down = s.conns = s.active = s.fail = 0; s.t0 = time.time()


# ---------- relay + servers ----------
async def pipe(r, w, st=None, key="down"):
    try:
        while True:
            d = await asyncio.wait_for(r.read(65536), IDLE)
            if not d: break
            w.write(d); await w.drain()
            if st: setattr(st, key, getattr(st, key) + len(d))
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass


async def open_tcp(host, port, t=8):
    return await asyncio.wait_for(asyncio.open_connection(host, port), t)


async def via_proxy(kind, uh, up, h, p, t=10):
    rr, rw = await open_tcp(uh, up, t)
    try:
        hb = h.encode()
        if kind == "SOCKS5":
            rw.write(b"\x05\x01\x00")
            if await asyncio.wait_for(rr.readexactly(2), t) != b"\x05\x00": raise OSError("auth")
            rw.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", p))
            rep = await asyncio.wait_for(rr.readexactly(4), t)
            if rep[1]: raise OSError("refused")
            n = {1: 4, 4: 16}.get(rep[3])
            if n is None: n = (await rr.readexactly(1))[0]
            await asyncio.wait_for(rr.readexactly(n + 2), t)
        else:
            rw.write(f"CONNECT {h}:{p} HTTP/1.1\r\nHost: {h}:{p}\r\n\r\n".encode())
            head = await asyncio.wait_for(rr.readuntil(b"\r\n\r\n"), t)
            if b" 200" not in head.split(b"\r\n")[0]: raise OSError("refused")
        return rr, rw
    except BaseException:
        rw.close(); raise


class Srv:
    def __init__(s, host, port, log, frag=True):
        s.host, s.port, s.log, s.frag = host, port, log, frag
        s.stats, s.state, s.loop, s.stopping = Stats(), "starting", None, False

    def run(s):
        try: asyncio.run(s.main())
        except Exception as e: s.log(f"خطا: {e}")
        finally: s.state = "stopped"

    async def main(s):
        s.ev = asyncio.Event(); s.sem = asyncio.Semaphore(350); s.loop = asyncio.get_running_loop()
        try:
            srv = await asyncio.start_server(s.handle, s.host, s.port, backlog=256)
        except OSError as e:
            s.log(f"پورت {s.port} قابل استفاده نیست: {e}"); return
        s.state = "running"; s.log(f"{s.__class__.__name__} روی {s.host}:{s.port} فعال شد")
        task = asyncio.create_task(s.extra())
        await s.ev.wait()
        task.cancel(); srv.close()

    async def extra(s): pass

    def stop(s):
        s.stopping = True
        if s.loop: s.loop.call_soon_threadsafe(s.ev.set)

    async def up(s, r, w):
        """client -> remote; fragments the very first TLS hello when enabled."""
        try:
            d = await asyncio.wait_for(r.read(65536), IDLE)
            if d: await send_frag(w, d, s.frag); s.stats.up += len(d)
        except Exception:
            w.close(); return
        await pipe(r, w, s.stats, "up")

    async def relay(s, r, w, rr, rw):
        await asyncio.gather(s.up(r, rw), pipe(rr, w, s.stats, "down"))


class Socks(Srv):
    """One port, three protocols (SOCKS5 / SOCKS4(a) / HTTP proxy): upstream pool with automatic failover, DoH, TLS fragmentation, timeouts, connection cap."""
    def __init__(s, host, port, log, pool, frag=True, use_doh=True):
        super().__init__(host, port, log, frag); s.pool, s.doh = pool, use_doh

    async def resolve(s, h):
        if not s.doh or ":" in h or re.fullmatch(r"[\d.]+", h): return [h]
        ips = await asyncio.get_running_loop().run_in_executor(None, doh, h)
        return (ips or []) + [h]

    async def connect(s, h, p):
        if len(s.pool):
            for e in s.pool.ordered()[:3]:
                try:
                    res = await via_proxy(e["kind"], e["host"], e["port"], h, p)
                    s.pool.good(e); return res
                except Exception:
                    s.pool.bad(e)
            s.log(f"همه آپ‌استریم‌ها برای {h} ناموفق بودند؛ مورد بعدی نوبت می‌گیرد")
            return None
        for ip in (await s.resolve(h))[:3]:
            try: return await open_tcp(ip, p)
            except Exception: pass
        return None

    async def _socks5(s, r, w):
        n = (await asyncio.wait_for(r.readexactly(1), 10))[0]
        await asyncio.wait_for(r.readexactly(n), 10); w.write(b"\x05\x00")
        _, cmd, _, at = await asyncio.wait_for(r.readexactly(4), 10)
        if at == 1: h = socket.inet_ntoa(await r.readexactly(4))
        elif at == 3: h = (await r.readexactly((await r.readexactly(1))[0])).decode("utf8", "ignore")
        else: h = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        p = struct.unpack(">H", await r.readexactly(2))[0]
        if cmd != 1:
            w.write(b"\x05\x07\x00\x01" + b"\0" * 6); return None
        return h, p, b"\x05\x00\x00\x01" + b"\0" * 6, b"\x05\x04\x00\x01" + b"\0" * 6, b""

    async def _socks4(s, r, w):  # SOCKS4 and SOCKS4a (Chrome/Edge use this for "socks=" system proxies)
        hd = await asyncio.wait_for(r.readexactly(7), 10)
        if hd[0] != 1:
            w.write(b"\x00\x5b" + b"\0" * 6); return None
        p = struct.unpack(">H", hd[1:3])[0]; h = socket.inet_ntoa(hd[3:7])
        await asyncio.wait_for(r.readuntil(b"\x00"), 10)  # user id
        if hd[3:6] == b"\0\0\0" and hd[6] != 0:
            h = (await asyncio.wait_for(r.readuntil(b"\x00"), 10))[:-1].decode("utf8", "ignore")
        return h, p, b"\x00\x5a" + b"\0" * 6, b"\x00\x5b" + b"\0" * 6, b""

    async def _http(s, first, r, w):  # HTTP proxy: CONNECT tunnels (https) and absolute-URI requests (http)
        head = first + await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 15)
        line, _, rest = head.partition(b"\r\n")
        parts = line.decode("latin1").split()
        bad = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        if len(parts) < 3:
            return None
        m, tgt, ver = parts[0], parts[1], parts[2]
        if m.upper() == "CONNECT":
            h, _, p = tgt.rpartition(":")
            if not h: h, p = tgt, "443"
            return h.strip("[]"), int(p), b"HTTP/1.1 200 Connection Established\r\n\r\n", bad, b""
        mm = re.match(r"(?i)https?://(\[[^\]]+\]|[^/:]+)(?::(\d+))?(/.*)?$", tgt)
        if not mm:
            w.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"); return None
        hdrs = [l for l in rest.split(b"\r\n") if l and not l.lower().startswith((b"proxy-connection", b"connection", b"proxy-authorization"))]
        req = f"{m} {mm.group(3) or '/'} {ver}\r\n".encode("latin1") + b"\r\n".join(hdrs) + b"\r\nConnection: close\r\n\r\n"
        return mm.group(1).strip("[]"), int(mm.group(2) or 80), b"", bad, req

    async def handle(s, r, w):
        rw, counted = None, False
        async with s.sem:
            try:
                first = await asyncio.wait_for(r.readexactly(1), 10)
                info = await (s._socks5(r, w) if first == b"\x05" else s._socks4(r, w) if first == b"\x04" else s._http(first, r, w))
                if not info: return
                h, p, ok, fail, early = info
                s.stats.conns += 1; s.stats.active += 1; counted = True
                res = await s.connect(h, p)
                if not res:
                    s.stats.fail += 1; w.write(fail); return
                rr, rw = res
                if ok: w.write(ok); await w.drain()
                if early: rw.write(early); await rw.drain()
                await s.relay(r, w, rr, rw)
            except Exception:
                pass
            finally:
                if counted: s.stats.active -= 1
                w.close()
                if rw: rw.close()

class Forwarder(Srv):
    """Local port -> best Cloudflare IP:443 from the pool. Failover at connect time + background health checks."""
    def __init__(s, host, port, log, pool, frag=True, sni="security.vercel.com"):
        super().__init__(host, port, log, frag); s.pool, s.sni = pool, sni

    async def extra(s):
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(40)
            for e in s.pool.snapshot():
                s.pool.mark(e, await loop.run_in_executor(None, tls_ping, e["host"], s.sni, 4))

    async def handle(s, r, w):
        rw, counted = None, False
        async with s.sem:
            try:
                s.stats.conns += 1; s.stats.active += 1; counted = True
                rr = None
                for e in s.pool.ordered()[:4]:
                    try:
                        rr, rw = await open_tcp(e["host"], e["port"], 6); s.pool.good(e); break
                    except Exception:
                        s.pool.bad(e); rr = rw = None
                if not rw:
                    s.stats.fail += 1; s.log("هیچ IP سالمی در استخر پاسخ نداد"); return
                await s.relay(r, w, rr, rw)
            except Exception:
                pass
            finally:
                if counted: s.stats.active -= 1
                w.close()
                if rw: rw.close()




# ---------- one-click real connection ----------
def tunnel_https(kind, host, port, dest, t=6, path="/generate_204", n=300):
    """Verified-TLS GET to dest through a proxy tunnel; returns the first n response bytes, or None."""
    c = proxy_tunnel(kind, host, port, dest, 443, t)
    if not c: return None
    try:
        with _vctx().wrap_socket(c, server_hostname=dest) as s:
            s.settimeout(t)
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {dest}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            data = b""
            try:
                while len(data) < n:
                    x = s.recv(n - len(data))
                    if not x: break
                    data += x
            except OSError:
                pass
            return data or None
    except (OSError, ssl.SSLError):
        return None
    finally:
        c.close()


def speed_test(kind, host, port, t=8, nbytes=300000):
    """KB/s while downloading nbytes from Cloudflare through the proxy (0 if it fails or stalls)."""
    c = proxy_tunnel(kind, host, port, "speed.cloudflare.com", 443, t)
    if not c: return 0
    try:
        with _vctx().wrap_socket(c, server_hostname="speed.cloudflare.com") as s:
            s.settimeout(t); s0 = time.perf_counter()
            s.sendall(f"GET /__down?bytes={nbytes} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n".encode())
            got = 0
            try:
                while time.perf_counter() - s0 < t:
                    x = s.recv(65536)
                    if not x: break
                    got += len(x)
            except OSError:
                pass
            return got / 1024 / max(0.05, time.perf_counter() - s0) if got >= nbytes * 0.8 else 0
    except (OSError, ssl.SSLError):
        return 0
    finally:
        c.close()


def strict_probe(kind, host, port, strict=True):
    """A route only counts if it really reaches YouTube (and Google) over verified TLS and moves data at a usable speed."""
    t0 = time.perf_counter(); r = tunnel_https(kind, host, port, "www.youtube.com", 6)
    if not r or b" 204" not in r[:20]: return None
    lat, kb = (time.perf_counter() - t0) * 1000, 0
    if strict:
        g = tunnel_https(kind, host, port, "www.google.com", 6)
        if not g or b" 204" not in g[:20]: return None
        kb = speed_test(kind, host, port)
        if kb < 40: return None
    return {"kind": kind, "addr": f"{host}:{port}", "host": host, "port": port, "lat": lat, "jit": 0, "secure": True,
            "kbps": kb, "score": lat + 20000 / max(kb, 40)}


def real_check(port, t=8):
    """End-to-end test THROUGH the local server: YouTube must answer over verified TLS.
    Returns (ms, exit_ip, country) or None. Green in the UI means YouTube is actually reachable."""
    s0 = time.perf_counter(); r = tunnel_https("SOCKS5", "127.0.0.1", port, "www.youtube.com", t)
    if not r or b" 204" not in r[:20]: return None
    ms, ip, loc = (time.perf_counter() - s0) * 1000, "?", "?"
    tr = tunnel_https("SOCKS5", "127.0.0.1", port, "1.1.1.1", t, "/cdn-cgi/trace", 1500)
    if tr:
        m = dict(l.split("=", 1) for l in tr.decode("utf8", "ignore").splitlines() if "=" in l)
        ip, loc = m.get("ip", "?"), m.get("loc", "?")
    return ms, ip, loc


def find_best(n, workers, ev, status, only_secure=True, want=8):
    """Fetch public SOCKS5+HTTP proxy lists, test them in parallel, return the best `want` (lowest score)."""
    status("دریافت لیست پروکسی‌ها ...")
    cands = [(k, h, p) for k in ("SOCKS5", "HTTP") for h, p in fetch_proxies(k, n)]
    random.shuffle(cands)
    if not cands or ev.is_set(): return []
    status(f"تست {len(cands)} پروکسی ...")
    res, done = [], 0

    def one(c): return None if ev.is_set() else strict_probe(c[0], c[1], c[2], only_secure)
    with ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(one, c) for c in cands]
        for f in as_completed(futs):
            done += 1
            try: r = f.result()
            except Exception: r = None
            if r: res.append(r)
            if done % 10 == 0: status(f"تست {done}/{len(cands)} — {len(res)} مسیر سالم")
            if len(res) >= want * 2 or ev.is_set():
                for g in futs: g.cancel()
                break
    return sorted(res, key=lambda r: r["score"])[:want]


class QuickLink:
    """One click: local SOCKS up -> find best proxies -> verify real end-to-end connectivity -> watchdog
    that re-verifies every few seconds and automatically picks fresh routes when the link dies."""
    ok_wait, bad_wait = 15, 4

    def __init__(s, pool, status, state, on_server):
        s.pool, s.status, s.state, s.on_server = pool, status, state, on_server
        s.stop = threading.Event()

    def start(s, lan, secure):
        s.stop.set(); s.stop = ev = threading.Event()
        threading.Thread(target=s._run, args=(ev, lan, secure), daemon=True).start()

    def cancel(s): s.stop.set()

    def _dead(s):
        items = s.pool.snapshot(); return bool(items) and all(e["fails"] >= 3 for e in items)

    def _refresh(s, ev, port, secure, attempts, sa):
        for i in range(attempts):
            sa(f"جستجوی بهترین مسیر (تلاش {i + 1}/{attempts}) ...")
            best = find_best(300, 150, ev, sa, secure and i < attempts - 1, 8)  # last attempt relaxes the TLS filter
            if ev.is_set(): return False
            if not best: continue
            s.pool.clear()
            for r in best: s.pool.add(r["kind"], r["host"], r["port"], r["lat"])
            sa("بررسی اتصال واقعی ...")
            if any(real_check(port) for _ in range(3)): return True
        return False

    def _run(s, ev, lan, secure):
        st = lambda *a: None if ev.is_set() else s.state(*a)
        sa = lambda m: None if ev.is_set() else s.status(m)
        try:
            srv = s.on_server(lan)
            if not srv: return st("failed", "راه‌اندازی سرور محلی ناموفق بود (پورت اشغال است؟)")
            port, first, fails = srv.port, True, 0
            while not ev.is_set():
                if srv.state == "stopped": return st("idle", None)
                if first or fails >= 2 or s._dead():
                    if not first: st("connecting", None)
                    if not s._refresh(ev, port, secure, 3 if first else 2, sa):
                        if ev.is_set(): break
                        if first: return st("failed", "مسیر سالمی پیدا نشد؛ دوباره تلاش کنید")
                        ev.wait(s.bad_wait); continue
                    first, fails = False, 0
                res = real_check(port)
                if res: fails = 0; st("connected", {"ms": res[0], "ip": res[1], "loc": res[2]})
                else: fails += 1; sa("اتصال ضعیف است؛ در حال بررسی ...")
                ev.wait(s.ok_wait if res else s.bad_wait)
        except Exception as e:
            st("failed", f"خطا: {e}")




# ---------- shared by the UI process and the background service (control channel on localhost) ----------
CTL_PORT = 18999


def get_token():
    """Random secret in the app-private dir: only our own processes can talk to the service."""
    p = os.path.join(APP_DIR, "token")
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        if not os.path.exists(p):
            with open(p, "w") as f: f.write(os.urandom(16).hex())
        with open(p) as f: return f.read().strip()
    except Exception:
        return "x"


def rpc(cmd, timeout=2.0, **kw):
    """One request/response (JSON line) to the background service. Returns dict or None."""
    try:
        with socket.create_connection(("127.0.0.1", CTL_PORT), timeout) as c:
            c.settimeout(timeout); c.sendall((json.dumps(dict(kw, cmd=cmd, token=get_token())) + "\n").encode()); buf = b""
            while not buf.endswith(b"\n"):
                x = c.recv(65536)
                if not x: break
                buf += x
        return json.loads(buf) if buf else None
    except Exception:
        return None
