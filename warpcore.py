"""
warpcore.py - platform-independent network/logic core for the Aether WARP tool.

This is the Android/Kivy port of the network logic from the original
tkinter desktop tool (aether_tool2.py). All Windows-only code (winreg,
ctypes system proxy, tkinter widgets) has been removed. This module has
no GUI dependency at all -- it can be imported from main.py (Kivy) or
tested from a plain Python shell.

pip install requests cryptography
"""
import base64
import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

TOOL_VERSION = "7-android"
API = "https://api.cloudflareclient.com/v0a2158"
HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.3-1922",
    "Content-Type": "application/json",
}
SCAN_RANGES = ["162.159.192", "162.159.193", "162.159.195", "188.114.96",
               "188.114.97", "188.114.98", "188.114.99"]
SNI = "zt-masque.cloudflareclient.com"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


# ======================================================================
# App data directory (works on desktop AND Android)
# ======================================================================
def app_dir() -> str:
    """Private, writable app-data directory. On Android this is the app's
    internal storage (no special permission needed); on desktop it's next
    to this file."""
    try:
        from android.storage import app_storage_path  # noqa: F401  (p4a only)
        p = app_storage_path()
        os.makedirs(p, exist_ok=True)
        return p
    except Exception:
        p = os.path.dirname(os.path.abspath(__file__))
        return p


def native_lib_dir() -> str:
    """Directory where Android unpacks lib*.so files from the APK - this is
    the ONLY place on modern Android where a bundled binary can actually be
    executed (W^X / scoped storage block execution from any other writable
    path). On desktop, falls back to app_dir()."""
    try:
        from jnius import autoclass  # noqa: F401 (p4a only, pyjnius)
        from android.storage import app_storage_path  # noqa: F401
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        ctx = PythonActivity.mActivity
        return ctx.getApplicationInfo().nativeLibraryDir
    except Exception:
        return app_dir()


# ======================================================================
# WARP API (account registration)
# ======================================================================
def register_warp(masque: bool, proxy: str = "") -> dict:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    sk = x25519.X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    priv = sk.private_bytes(raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    body = {"key": b64(pub), "install_id": "", "fcm_token": "",
            "tos": datetime.datetime.utcnow().isoformat() + "Z",
            "model": "PC", "serial_number": str(uuid.uuid4()), "locale": "en_US"}
    r = requests.post(f"{API}/reg", json=body, headers=HEADERS,
                       proxies=proxies, timeout=20)
    r.raise_for_status()
    acc = r.json()
    result = {"id": acc["id"], "token": acc["token"],
              "license": acc.get("account", {}).get("license", ""),
              "wg_private_key": b64(priv), "wg_public_key": b64(pub),
              "config": acc.get("config", {})}
    if masque:
        ek = ec.generate_private_key(ec.SECP256R1())
        ek_pub = ek.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ek_priv = ek.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        h = dict(HEADERS, Authorization=f"Bearer {acc['token']}")
        r2 = requests.patch(f"{API}/reg/{acc['id']}",
                             json={"key": b64(ek_pub), "key_type": "secp256r1",
                                   "tunnel_type": "masque"},
                             headers=h, proxies=proxies, timeout=20)
        r2.raise_for_status()
        result["masque_private_key_pem"] = ek_priv
        result["config"] = r2.json().get("config", result["config"])
    return result


# ======================================================================
# aether:// links
# ======================================================================
def build_link(protocol, scan, ip, transport, name) -> str:
    q = urlencode([("protocol", protocol), ("scan", scan),
                   ("ip", ip), ("transport", transport)])
    return f"aether://?{q}" + (f"#{quote(name)}" if name else "")


def parse_link(link: str) -> dict:
    u = urlparse(link.strip())
    if u.scheme != "aether":
        raise ValueError("not an aether:// link")
    d = dict(parse_qsl(u.query))
    d["name"] = unquote(u.fragment)
    return d


# ======================================================================
# Network helpers
# ======================================================================
def probe(ip, port=443, timeout=2.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return ip, (time.perf_counter() - t) * 1000
    except OSError:
        return ip, None


def port_free(bind: str, port) -> bool:
    s = socket.socket()
    try:
        s.bind((bind, int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace",
                            timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as e:
        return None, f"cannot run: {e}"


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed by proxy")
        buf += chunk
    return buf


def socks5_connect(bind, port, host, dport, timeout=15):
    """Open a TCP connection to host:dport through a SOCKS5 proxy (stdlib only)."""
    s = socket.create_connection((bind, int(port)), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake refused")
        try:
            req = b"\x05\x01\x00\x01" + socket.inet_pton(socket.AF_INET, host)
        except OSError:
            try:
                req = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, host)
            except OSError:
                hb = host.encode("idna")
                req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
        s.sendall(req + int(dport).to_bytes(2, "big"))
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise OSError(f"SOCKS5 CONNECT failed (reply code {head[1]})")
        if head[3] == 1:
            _recv_exact(s, 6)
        elif head[3] == 4:
            _recv_exact(s, 18)
        elif head[3] == 3:
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        return s
    except Exception:
        s.close()
        raise


def socks5_trace(bind, port, timeout=8) -> dict:
    """Fetch https://one.one.one.one/cdn-cgi/trace through a SOCKS5 proxy."""
    s = socks5_connect(bind, port, "one.one.one.one", 443, timeout)
    try:
        tls = ssl.create_default_context().wrap_socket(s, server_hostname="one.one.one.one")
        tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\n"
                    b"Connection: close\r\n\r\n")
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        body = data.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
        return dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
    finally:
        s.close()


def pin_from_config(cfg_path: str) -> bytes:
    """DER SubjectPublicKeyInfo of the endpoint key that usque pins (endpoint_pub_key)."""
    with open(cfg_path, encoding="utf-8") as fh:
        pem = json.load(fh)["endpoint_pub_key"]
    return serialization.load_pem_public_key(pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def check_endpoint(ip, port, pin_der, sni, timeout=4.0):
    """TLS handshake to ip:port. Returns (latency_ms or None, pin_matches)."""
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
        ms = (time.perf_counter() - t0) * 1000
        spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return ms, spki == pin_der
    except Exception:  # noqa: BLE001
        return None, False


def mask_ip(ip: str) -> str:
    return re.sub(r"^(\d+\.\d+\.\d+)\.\d+$", r"\1.xxx", ip)


def scan_prefixes(prefixes, pin_der, sni, workers=48):
    """Blocking helper: scans a list of /24 prefixes, returns sorted
    [(ip, ms, pinned_ok), ...] -- verified+fast first."""
    ips = [f"{p}.{i}" for p in prefixes for i in range(1, 255)]

    def one(ip):
        return (ip,) + check_endpoint(ip, 443, pin_der, sni)

    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(one, ips))
    res = [r for r in res if r[1] is not None]
    res.sort(key=lambda r: (not r[2], r[1]))
    return res


def load_settings(path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_settings(data: dict, path) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return True
    except OSError:
        return False
