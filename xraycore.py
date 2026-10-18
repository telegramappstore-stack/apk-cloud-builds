"""xraycore - turns a proxy (SOCKS5 / HTTP / vmess / vless / trojan / ss) into an Xray config and runs the Xray binary.

Every kind of proxy goes through the same engine, so connecting, the local SOCKS5/HTTP gateway and the
"does it really carry traffic" check behave identically. Pure standard library.
"""
import json
import os
import socket
import subprocess
import threading
import time
import urllib.parse
from collections import deque

import proxycore as pc

SOCKS_PORT = 10808
HTTP_PORT = 10809


class XrayError(Exception):
    pass


def _truthy(v):
    return str(v).lower() in ("1", "true", "yes")


# ------------------------------------------------------------------ share link -> outbound
def _stream(net, sec, q):
    net = (net or "tcp").lower()
    net = {"h2": "http", "splithttp": "xhttp"}.get(net, net)
    if net not in ("tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "kcp"):
        raise XrayError("unsupported transport: %s" % net)
    host = q.get("host") or ""
    path = q.get("path") or "/"
    st = {"network": net}
    if net == "ws":
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": q.get("serviceName") or q.get("path") or "",
                              "multiMode": q.get("mode") == "multi"}
    elif net == "http":
        h = {"path": path}
        if host:
            h["host"] = host.split(",")
        st["httpSettings"] = h
    elif net == "httpupgrade":
        h = {"path": path}
        if host:
            h["host"] = host
        st["httpupgradeSettings"] = h
    elif net == "xhttp":
        h = {"path": path, "mode": q.get("mode") or "auto"}
        if host:
            h["host"] = host
        st["xhttpSettings"] = h
    elif net == "kcp":
        k = {"header": {"type": q.get("headerType") or "none"}}
        if q.get("seed"):
            k["seed"] = q["seed"]
        st["kcpSettings"] = k
    elif net == "tcp" and q.get("headerType") == "http":
        st["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [host] if host else []}}}}

    sec = (sec or "none").lower()
    sni = q.get("sni") or q.get("peer") or host
    if sec == "tls":
        t = {"allowInsecure": _truthy(q.get("allowInsecure") or q.get("insecure") or "0")}
        if sni:
            t["serverName"] = sni
        if q.get("fp"):
            t["fingerprint"] = q["fp"]
        if q.get("alpn"):
            t["alpn"] = q["alpn"].split(",")
        st["security"] = "tls"
        st["tlsSettings"] = t
    elif sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {"serverName": sni or "", "fingerprint": q.get("fp") or "chrome",
                                 "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
                                 "spiderX": q.get("spx", "")}
    elif sec not in ("none", ""):
        raise XrayError("unsupported security: %s" % sec)
    return st


def outbound_from_link(link):
    link = link.strip()
    low = link.lower()
    try:
        if low.startswith("vmess://"):
            d = json.loads(pc._b64d(link[8:]))
            q = {"host": d.get("host") or "", "path": d.get("path") or "/", "sni": d.get("sni") or "",
                 "fp": d.get("fp") or "", "alpn": d.get("alpn") or "", "headerType": d.get("type") or "none",
                 "serviceName": d.get("path") or ""}
            sec = "tls" if str(d.get("tls", "")).lower() in ("tls", "1", "true") else "none"
            user = {"id": d["id"], "alterId": int(d.get("aid") or 0), "security": d.get("scy") or "auto"}
            return {"protocol": "vmess",
                    "settings": {"vnext": [{"address": str(d["add"]).strip(), "port": int(d["port"]), "users": [user]}]},
                    "streamSettings": _stream(d.get("net") or "tcp", sec, q)}

        if low.startswith(("vless://", "trojan://")):
            u = urllib.parse.urlsplit(link)
            q = dict(urllib.parse.parse_qsl(u.query))
            proto = low.split("://", 1)[0]
            secret = urllib.parse.unquote(u.username or "")
            if not secret or not u.hostname or not u.port:
                raise XrayError("incomplete %s link" % proto)
            sec = q.get("security") or ("tls" if proto == "trojan" else "none")
            stream = _stream(q.get("type") or "tcp", sec, q)
            if proto == "vless":
                user = {"id": secret, "encryption": q.get("encryption") or "none"}
                if q.get("flow"):
                    user["flow"] = q["flow"]
                settings = {"vnext": [{"address": u.hostname, "port": u.port, "users": [user]}]}
            else:
                settings = {"servers": [{"address": u.hostname, "port": u.port, "password": secret}]}
            return {"protocol": proto, "settings": settings, "streamSettings": stream}

        if low.startswith("ss://"):
            body = link[5:].split("#", 1)[0]
            query = ""
            if "?" in body:
                body, query = body.split("?", 1)
            if "plugin" in query:
                raise XrayError("Shadowsocks plugins are not supported")
            if "@" in body:
                userinfo, hostport = body.rsplit("@", 1)
                userinfo = urllib.parse.unquote(userinfo)
                if ":" not in userinfo:
                    userinfo = pc._b64d(userinfo)
            else:
                userinfo, hostport = pc._b64d(body).rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            return {"protocol": "shadowsocks", "settings": {"servers": [{
                "address": host.strip("[]"), "port": int(port), "method": method, "password": password}]}}
    except XrayError:
        raise
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as e:
        raise XrayError("cannot read this config (%s)" % type(e).__name__)
    raise XrayError("unknown link type")


def outbound_for(p):
    if p.kind == "socks5":
        return {"protocol": "socks", "settings": {"servers": [{"address": p.host, "port": p.port}]}}
    if p.kind == "http":
        return {"protocol": "http", "settings": {"servers": [{"address": p.host, "port": p.port}]}}
    return outbound_from_link(p.link)


def build_config(p, socks_port=SOCKS_PORT, http_port=HTTP_PORT):
    out = outbound_for(p)
    out["tag"] = "proxy"
    return {
        "log": {"loglevel": "warning"},
        # Xray on Android has no resolv.conf, so give it explicit resolvers (used to resolve the server's own name)
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": http_port, "protocol": "http", "settings": {}},
        ],
        "outbounds": [out,
                      {"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
    }


# ------------------------------------------------------------------ process
def _port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        return True
    except OSError:
        return False


class Xray:
    def __init__(self, binary, workdir):
        self.binary, self.workdir = binary, workdir
        self.proc = None
        self.log = deque(maxlen=40)

    @property
    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def tail(self):
        lines = [l for l in self.log if l.strip()]
        return " | ".join(lines[-3:])[:300]

    def _pump(self, proc):
        try:
            for raw in iter(proc.stdout.readline, b""):
                self.log.append(raw.decode("utf-8", "ignore").strip())
        except (OSError, ValueError):
            pass

    def start(self, p, socks_port=SOCKS_PORT, http_port=HTTP_PORT, wait=6.0):
        self.stop()
        if not self.binary or not os.path.exists(self.binary):
            raise XrayError("Xray core not found")
        cfg = build_config(p, socks_port, http_port)
        path = os.path.join(self.workdir, "xray_config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = self.workdir
        try:
            self.proc = subprocess.Popen([self.binary, "run", "-c", path], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, cwd=self.workdir, env=env)
        except OSError as e:
            raise XrayError("cannot start the core: %s" % e)
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                time.sleep(0.15)
                raise XrayError("core exited: %s" % (self.tail() or "no output"))
            if _port_open(socks_port):
                return
            time.sleep(0.15)
        self.stop()
        raise XrayError("core did not start in time")

    def stop(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
        except OSError:
            pass
