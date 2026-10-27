"""NetFree background service (runs as a python-for-android foreground service, separate process).
Owns the SOCKS5/HTTP server, Cloudflare forwarder, pools and the QuickLink watchdog, so the connection
stays alive after the UI is closed. The UI talks to it through a token-protected JSON-lines socket on localhost."""
import json, os, socketserver, threading, time

from engine import (APP_DIR, CTL_PORT, Forwarder, Pool, QuickLink, Socks, get_token, proxy_ping)

STATE = os.path.join(APP_DIR, "service_state.json")


class Svc:
    def __init__(s):
        s.logs, s.base, s.lock = [], 0, threading.Lock()
        s.up, s.ip = Pool(), Pool()
        s.srv = s.fwd = None
        s.qs = {"st": "idle", "info": None, "msg": ""}
        s.qparams = {"lan": False, "secure": True, "port": 1080}
        s.quick = QuickLink(s.up, s.on_msg, s.on_state, s.quick_server)
        s.token = get_token()
        s.load()

    # ----- persistence (so a restarted service resumes the user's last connection) -----
    def load(s):
        try:
            with open(STATE, encoding="utf8") as f: d = json.load(f)
        except Exception:
            return
        for h, lat in d.get("ip_pool", []): s.ip.add("IP", h, 443, lat)
        s.resume = d.get("resume")

    resume = None

    def save(s):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(STATE, "w", encoding="utf8") as f:
                json.dump({"ip_pool": [[e["host"], e["lat"]] for e in s.ip.snapshot()], "resume": s.resume}, f)
        except Exception:
            pass

    def log(s, m):
        with s.lock:
            s.logs.append(time.strftime("%H:%M:%S  ") + str(m))
            if len(s.logs) > 400: del s.logs[:100]; s.base += 100

    def on_msg(s, m): s.qs["msg"] = m
    def on_state(s, st, info=None): s.qs["st"], s.qs["info"] = st, info

    # ----- servers -----
    def _spawn(s, srv):
        threading.Thread(target=srv.run, daemon=True).start()
        for _ in range(30):
            if srv.state != "starting": break
            time.sleep(0.1)
        return srv

    def quick_server(s, lan):
        for _ in range(40):
            if not (s.srv and s.srv.stopping): break
            time.sleep(0.1)
        if s.srv and s.srv.state == "running" and not s.srv.stopping: return s.srv
        if s.srv: return None
        s.srv = srv = Socks("0.0.0.0" if lan else "127.0.0.1", s.qparams["port"], s.log, s.up, True, True)
        return srv if s._spawn(srv).state == "running" else None

    def start_socks(s, lan=False, port=1080, frag=True, doh=True, **_):
        if s.srv: return
        s.srv = Socks("0.0.0.0" if lan else "127.0.0.1", int(port), s.log, s.up, frag, doh); s._spawn(s.srv)

    def start_fwd(s, lan=False, port=10443, frag=True, sni="", **_):
        if s.fwd: return
        if not len(s.ip): return s.log("استخر IP خالی است")
        s.fwd = Forwarder("0.0.0.0" if lan else "127.0.0.1", int(port), s.log, s.ip, frag, sni); s._spawn(s.fwd)

    def quick_start(s, lan=False, secure=True, port=1080, **_):
        s.qparams = {"lan": lan, "secure": secure, "port": int(port)}
        s.resume = dict(s.qparams); s.save()
        s.qs.update(st="connecting", info=None, msg="")
        s.quick.start(lan, secure)

    def quick_stop(s, **_):
        s.resume = None; s.save(); s.quick.cancel()
        if s.srv: s.srv.stop()
        s.qs.update(st="idle", info=None, msg="")

    # ----- status / commands -----
    def status(s, since=0, opts=None, **_):
        if s.srv and s.srv.state == "stopped": s.srv = None
        if s.fwd and s.fwd.state == "stopped": s.fwd = None
        o = opts or {}
        if s.srv: s.srv.frag, s.srv.doh = o.get("frag", s.srv.frag), o.get("doh", s.srv.doh)
        if s.fwd: s.fwd.frag, s.fwd.sni = o.get("ffrag", s.fwd.frag), o.get("fsni", s.fwd.sni)

        def sv(x):
            return None if not x else {"state": x.state, "host": x.host, "port": x.port, "up": x.stats.up, "down": x.stats.down,
                                       "conns": x.stats.conns, "active": x.stats.active, "fail": x.stats.fail}
        with s.lock:
            n = s.base + len(s.logs); new = s.logs[max(0, since - s.base):]
        return {"socks": sv(s.srv), "fwd": sv(s.fwd), "quick": dict(s.qs), "up_pool": s.up.snapshot(), "ip_pool": s.ip.snapshot(), "logs": new, "nlog": n}

    def handle(s, req):
        c = req.get("cmd")
        if c == "ping": return {"ok": 1}
        if c == "status": return s.status(**{k: v for k, v in req.items() if k in ("since", "opts")})
        if c == "start_socks": s.start_socks(**req)
        elif c == "stop_socks":
            if s.srv: s.srv.stop()
        elif c == "start_fwd": s.start_fwd(**req)
        elif c == "stop_fwd":
            if s.fwd: s.fwd.stop()
        elif c == "quick_start": s.quick_start(**req)
        elif c == "quick_stop": s.quick_stop()
        elif c == "set_up":
            s.up.clear()
            for i in req.get("items", []): s.up.add(i["kind"], i["host"], int(i["port"]), i.get("lat", 0))
        elif c == "add_up": i = req["item"]; s.up.add(i["kind"], i["host"], int(i["port"]), i.get("lat", 0))
        elif c == "rm_up": s._rm(s.up, req)
        elif c == "clear_up": s.up.clear()
        elif c == "set_ip":
            s.ip.clear()
            for i in req.get("items", []): s.ip.add("IP", i["host"], 443, i.get("lat", 0))
            s.save()
        elif c == "add_ip": i = req["item"]; s.ip.add("IP", i["host"], 443, i.get("lat", 0)); s.save()
        elif c == "rm_ip": s._rm(s.ip, req); s.save()
        elif c == "clear_ip": s.ip.clear(); s.save()
        elif c == "test_socks":
            port = s.srv.port if s.srv and s.srv.state == "running" else None
            if not port: s.log("ابتدا سرور را روشن کنید")
            else: threading.Thread(target=lambda: s.log((lambda m: f"تست موفق: {m:.0f} ms" if m else "تست ناموفق")(proxy_ping("SOCKS5", "127.0.0.1", port, 15))), daemon=True).start()
        elif c == "shutdown":
            s.quick_stop()
            if s.fwd: s.fwd.stop()
            threading.Timer(0.5, lambda: os._exit(0)).start()
        else: return {"error": "unknown"}
        return {"ok": 1}

    def _rm(s, pool, req):
        for e in pool.snapshot():
            if (e["host"], e["port"]) == (req.get("host"), req.get("port")): pool.remove(e)


class H(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            req = json.loads(self.rfile.readline(1 << 20))
            if req.get("token") != SVC.token: out = {"error": "auth"}
            else: out = SVC.handle(req)
        except Exception as e:
            out = {"error": str(e)}
        self.wfile.write((json.dumps(out) + "\n").encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address, daemon_threads = True, True


SVC = None


def wake_lock():
    """Keep the CPU awake so the proxy keeps working with the screen off (Android only)."""
    try:
        from jnius import autoclass
        act = autoclass("org.kivy.android.PythonService").mService
        pm = act.getSystemService(autoclass("android.content.Context").POWER_SERVICE)
        wl = pm.newWakeLock(1, "netfree:svc"); wl.acquire(); return wl
    except Exception:
        return None


def main():
    global SVC
    wake_lock()
    SVC = Svc()
    SVC.log("سرویس پس‌زمینه شروع شد")
    if SVC.resume:  # service was restarted by Android: bring the last connection back
        SVC.log("بازیابی اتصال قبلی ..."); SVC.quick_start(**SVC.resume)
    with Server(("127.0.0.1", CTL_PORT), H) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
