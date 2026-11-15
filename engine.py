"""engine - connects the phone to a chosen proxy.

Android : Java VpnService (org.proxyscout.vpn.ProxyVpnService) = tun -> hev-socks5-tunnel -> Xray -> proxy.
Desktop : a simulation, so the connection screen can be tried on a PC.
The UI only talks to the small API of BaseEngine.
"""
import json
import os
import random
import socket
import threading
import time

import proxycore as pc
import xrayconf as xc

ACTION_START = "org.proxyscout.vpn.START"
ACTION_STOP = "org.proxyscout.vpn.STOP"
SERVICE_CLASS = "org.proxyscout.vpn.ProxyVpnService"
REQ_VPN = 7421
STATE_FILE, LOG_FILE, SESSION_FILE = "vpn_state.txt", "vpn_xray.log", "vpn_session.json"
CRASH_FILE = "vpn_crash.txt"


SHARE = {"on": False, "port": 10809}      # filled from the saved settings by main.py


def lan_ips():
    """[(interface, ipv4)] of this phone on hotspot / Wi-Fi (private addresses only)."""
    out = []
    try:
        if on_android():
            from jnius import autoclass
            ifs = autoclass("java.net.NetworkInterface").getNetworkInterfaces()
            while ifs is not None and ifs.hasMoreElements():
                ni = ifs.nextElement()
                name = str(ni.getName())
                if ni.isLoopback() or not ni.isUp() or name.startswith("tun"):
                    continue
                addrs = ni.getInetAddresses()
                while addrs.hasMoreElements():
                    a = addrs.nextElement()
                    ip = str(a.getHostAddress())
                    if "." in ip and a.isSiteLocalAddress():
                        out.append((name, ip))
        else:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            out.append(("pc", s.getsockname()[0]))
            s.close()
    except Exception:
        pass
    return out


def share_cfg():
    if not SHARE["on"]:
        return None
    ips = lan_ips()
    return {"port": SHARE["port"], "ip": ips[0][1] if ips else "127.0.0.1"}


def share_listening(ip=None):
    """True when the shared SOCKS5 port answers on the phone's hotspot / Wi-Fi address (checked from the phone itself)."""
    import socket
    ip = ip or (lan_ips() or [("", "127.0.0.1")])[0][1]
    s = socket.socket()
    s.settimeout(0.6)
    try:
        s.connect((ip, SHARE["port"]))
        return True
    except OSError:
        return False
    finally:
        s.close()


def on_android():
    return "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ


class BaseEngine:
    simulated = False

    def __init__(self):
        self.state = "stopped"          # stopped | starting | running | error
        self.error = ""
        self.proxy = None
        self.t0 = None

    def adopt(self):
        """A VPN that kept running while the app was closed -> its Proxy, else None."""
        return None

    def connect(self, proxy):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError

    def poll(self):
        """-> dict(state, error, tx, rx, uptime); tx/rx = real bytes sent/received since the connection came up."""
        raise NotImplementedError

    def tunnel_ping(self):
        """ms for a full request THROUGH the running tunnel (Xray's local SOCKS), or None."""
        for _ in range(2):                                           # one request like NPV, retried once on failure
            a = pc.check_socks5("127.0.0.1", xc.LOCAL_PORT, 6.0, pc.V2RAY_TARGET)
            if a is not None:
                return a
        return None

    def direct_ping(self):
        """ms to open a TCP connection to the proxy server from this phone's own internet."""
        return pc.tcp_ping(self.proxy.host, self.proxy.port) if self.proxy else None


def looks_like_xray_config_error(err):
    e = (err or "").lower()
    return "xray" in e and any(k in e for k in ("config", "json", "unmarshal", "unknown", "invalid", "parse", "failed to start"))


class AndroidEngine(BaseEngine):
    """The VPN lives in its own Android process (:vpn). This class only sends intents and reads the state files
    the service writes, so closing the app does not stop the VPN and re-opening it picks the session up again."""

    def __init__(self):
        super().__init__()
        from jnius import autoclass
        self._ac = autoclass
        self.act = autoclass("org.kivy.android.PythonActivity").mActivity
        self.Intent = autoclass("android.content.Intent")
        self.VpnService = autoclass("android.net.VpnService")
        self.Svc = autoclass(SERVICE_CLASS)                          # only its static getWanBytes() is used from here
        self.sdk = autoclass("android.os.Build$VERSION").SDK_INT
        self.files = str(self.act.getFilesDir().getAbsolutePath())
        self._base = (0, 0)
        self._cancel = False
        self._gen = 0

    # -------------------------------------------------------------- state files
    def _f(self, name):
        return os.path.join(self.files, name)

    def _read_state(self):
        """-> (state, since_ms, error) exactly as the service wrote it ('stopped' when the file is missing)."""
        try:
            with open(self._f(STATE_FILE), encoding="utf-8") as f:
                st, hb, since, err = (f.read().split("\n", 3) + ["", "", ""])[:4]
            st, hb, since = st.strip(), int(hb), int(since)
        except (OSError, ValueError):
            return "stopped", 0, ""
        if st == "running" and time.time() * 1000 - hb > 10000:
            st = "stopped"
        return st, since, err

    def _tun_up(self):
        """True while the VPN interface (198.18.0.1) exists - visible to every app, no service state needed."""
        try:
            ifs = self._ac("java.net.NetworkInterface").getNetworkInterfaces()
            while ifs is not None and ifs.hasMoreElements():
                ni = ifs.nextElement()
                if not ni.isUp():
                    continue
                addrs = ni.getInetAddresses()
                while addrs.hasMoreElements():
                    if str(addrs.nextElement().getHostAddress()) == "198.18.0.1":
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _xray_port_open():
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", xc.LOCAL_PORT))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def _live(self):
        """The tunnel really exists: VPN interface up AND Xray answering on its local port."""
        return self._tun_up() and self._xray_port_open()

    def _svc(self):
        """-> (state, since_ms, error). The state file is preferred, but if it says nothing useful while the tunnel is
        demonstrably up (old service build, file not written, ...) the live tunnel wins - a working VPN is never
        reported as failed just because a status file is missing."""
        st, since, err = self._read_state()
        if st not in ("running", "error") and self._live():
            return "running", since, ""
        return st, since, err

    def _write_state(self, st, since_ms):
        try:
            tmp = self._f(STATE_FILE + ".py")
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("%s\n%d\n%d\n" % (st, int(time.time() * 1000), since_ms))
            os.replace(tmp, self._f(STATE_FILE))
        except OSError:
            pass

    def _xray_log(self):
        try:
            with open(self._f(LOG_FILE), encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError:
            return ""

    def _save_session(self):
        try:
            with open(self._f(SESSION_FILE), "w", encoding="utf-8") as f:
                json.dump({"tx": self._base[0], "rx": self._base[1], "proxy": self.proxy.to_dict()}, f)
        except (OSError, AttributeError):
            pass

    def adopt(self):
        st, since, _ = self._svc()
        if st != "running":
            return None
        try:
            with open(self._f(SESSION_FILE), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        pd = d.get("proxy")
        if pd:
            p = pc.Proxy(pd["kind"], pd["host"], pd["port"], pd.get("ms"), pd.get("link"), pd.get("proto"),
                         pd.get("sec"), pd.get("sni"), pd.get("name"))
            p.cc, p.country, p.ok_real = pd.get("cc"), pd.get("country"), pd.get("ok_real")
        else:
            p = pc.Proxy("socks5", "127.0.0.1", xc.LOCAL_PORT, name="Active VPN")
        w = self.Svc.getWanBytes()
        self._base = (int(d.get("tx", w[0])), int(d.get("rx", w[1])))
        self.proxy, self.state, self.error, self.t0 = p, "running", "", since / 1000.0
        return p

    # -------------------------------------------------------------- service plumbing
    def _intent(self, action):
        i = self.Intent()
        i.setClassName(self.act.getPackageName(), SERVICE_CLASS)
        i.setAction(action)
        return i

    def _start_service(self, t_req):
        """The service reads <filesDir>/xray.json (written just before); nothing is passed through extras."""
        self._write_state("starting", t_req)                        # a stale 'running' / 'error' is never read
        i = self._intent(ACTION_START)
        if self.sdk >= 26:
            self.act.startForegroundService(i)
        else:
            self.act.startService(i)

    def _stop_service(self):
        try:
            self.act.startService(self._intent(ACTION_STOP))
        except Exception:
            pass

    def _wait(self, wanted, timeout, t_req):
        end = time.time() + timeout
        up_since = None
        while time.time() < end and not self._cancel:
            st, since, _ = self._read_state()
            if st in wanted and since >= t_req:
                return st
            if "running" in wanted and self._live():             # file missing / old service: trust the live tunnel
                up_since = up_since or time.time()
                if time.time() - up_since >= 2.0:                # must stay up 2 s (not the previous session dying)
                    return "running"
            else:
                up_since = None
            time.sleep(0.25)
        return None

    def _diag(self):
        st, since, err = self._read_state()
        return "state-file=%s tun=%s xray-port=%s" % (st, self._tun_up(), self._xray_port_open())

    # -------------------------------------------------------------- API
    def connect(self, proxy):
        self.proxy, self.error, self.state, self.t0 = proxy, "", "starting", None
        self._cancel = False
        self._gen += 1
        try:
            need = self.VpnService.prepare(self.act)             # Intent when Android still has to ask the user
        except Exception as e:
            return self._fail("VPN check failed: %s" % e)
        if need is None:
            self._begin(self._gen)
            return
        from android import activity
        try:
            activity.unbind(on_activity_result=self._on_result)
        except Exception:
            pass
        activity.bind(on_activity_result=self._on_result)
        self.act.startActivityForResult(need, REQ_VPN)

    def _on_result(self, request, result, data):
        if request != REQ_VPN:
            return
        from android import activity
        try:
            activity.unbind(on_activity_result=self._on_result)
        except Exception:
            pass
        if result == -1:                                           # RESULT_OK
            self._begin(self._gen)
        else:
            self._fail("VPN permission was denied")

    def _begin(self, gen):
        threading.Thread(target=self._run, args=(gen,), daemon=True).start()

    def _fail(self, msg):
        self.error, self.state = msg, "error"

    def _run(self, gen):
        cfg_path = self._f("xray.json")
        last = ""
        for legacy in (False, True):                                # Xray >= 25.10 layout first, then the older one
            if self._cancel or gen != self._gen:
                return
            try:
                text = xc.dumps(self.proxy, legacy=legacy, share=share_cfg())
            except xc.ConfigError as e:
                return self._fail(str(e))
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(text)
            try:
                os.remove(self._f(CRASH_FILE))
            except OSError:
                pass
            t_req = int(time.time() * 1000)
            self._start_service(t_req)
            st = self._wait(("running", "error"), 30, t_req)
            if self._cancel or gen != self._gen:
                return
            if st == "running":
                w = self.Svc.getWanBytes()
                self._base = (max(0, int(w[0])), max(0, int(w[1])))
                self._save_session()
                self.t0, self.state, self.error = time.time(), "running", ""
                return
            last = self._read_state()[2]
            if not last:
                try:
                    with open(self._f(CRASH_FILE), encoding="utf-8", errors="ignore") as f:
                        last = "VPN service crashed: " + f.read()[:700]
                except OSError:
                    last = "The VPN service never answered (not started or killed by Android)."
                last += "  [" + self._diag() + "]"
            if not (not legacy and looks_like_xray_config_error(last)):
                break
            self._stop_service()
            time.sleep(1.0)
        self._stop_service()
        self._fail(last)

    def disconnect(self):
        self._cancel = True
        self._gen += 1
        self._stop_service()
        try:
            os.remove(self._f(SESSION_FILE))
        except OSError:
            pass
        self.state, self.error, self.t0 = "stopped", "", None

    def poll(self):
        st, err, tx, rx = self.state, self.error, 0, 0
        if st == "running":
            try:
                java, _, jerr = self._svc()
                if java != "running":                              # revoked from system UI, Xray died, ...
                    st, err = ("error", jerr or "VPN stopped") if java == "error" else ("stopped", "")
                    self.state, self.error, self.t0 = st, err, None
                else:
                    w = self.Svc.getWanBytes()
                    tx, rx = max(0, int(w[0]) - self._base[0]), max(0, int(w[1]) - self._base[1])
            except Exception as ex:
                err = str(ex)
        return {"state": st, "error": err, "tx": tx, "rx": rx, "uptime": (time.time() - self.t0) if self.t0 else 0,
                "log": self._xray_log() if st == "error" else ""}


class BrokenEngine(BaseEngine):
    """Android build whose native VPN pieces are missing: connecting reports why, it never fakes a connection."""

    def __init__(self, reason):
        super().__init__()
        self.reason = reason

    def connect(self, proxy):
        self.proxy, self.state, self.error = proxy, "error", self.reason

    def disconnect(self):
        self.state, self.error = "stopped", ""

    def poll(self):
        return {"state": self.state, "error": self.error, "tx": 0, "rx": 0, "uptime": 0, "log": ""}

    def tunnel_ping(self):
        return None


class DummyEngine(BaseEngine):
    """Desktop preview: pretends to connect and produces random traffic."""
    simulated = True

    def __init__(self):
        super().__init__()
        self._tx = self._rx = 0.0
        self._last = time.time()

    def connect(self, proxy):
        self.proxy, self.error, self.state = proxy, "", "starting"
        self._tx = self._rx = 0.0
        threading.Timer(1.2, self._up).start()

    def _up(self):
        if self.state == "starting":
            self.state, self.t0, self._last = "running", time.time(), time.time()

    def disconnect(self):
        self.state, self.t0 = "stopped", None

    def poll(self):
        now = time.time()
        if self.state == "running":
            dt, self._last = now - self._last, now
            self._rx += random.uniform(0.2e6, 3e6) * dt
            self._tx += random.uniform(0.02e6, 0.4e6) * dt
        return {"state": self.state, "error": "", "tx": int(self._tx), "rx": int(self._rx),
                "uptime": (now - self.t0) if self.t0 else 0, "log": ""}

    def tunnel_ping(self):
        return random.randint(90, 400)

    def direct_ping(self):
        return random.randint(30, 200)


def get_engine():
    if on_android():
        try:
            return AndroidEngine()
        except Exception as e:                                      # e.g. the Java classes are missing from this build
            return BrokenEngine("The VPN service is not in this APK (%s: %s). Check the CI log of prebuild.py / the Java sources."
                                % (type(e).__name__, e))
    return DummyEngine()
