"""androidbridge - everything that talks to Android (pyjnius). Safe to import on a PC: nothing runs at import time."""
import os
import shutil

from kivy.utils import platform

SERVICE = "org.aminium.vpn.AminiumVpnService"
_REQ_VPN = 7001

V2_APPS = (("com.v2ray.ang", "v2rayNG"), ("moe.nb4a", "NekoBox"), ("app.hiddify.com", "Hiddify"),
           ("io.nekohasekai.sfa", "sing-box"))
PSIPHON_APPS = (("com.psiphon3.subscription", "Psiphon Pro"), ("com.psiphon3", "Psiphon"))


def is_android():
    return platform == "android"


def _activity():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


# ------------------------------------------------------------------ Xray binary
def xray_binary():
    """Android: the core ships as libxray.so (so Android extracts it with the exec bit). PC: $AMINIUM_XRAY or `xray` on PATH."""
    env = os.environ.get("AMINIUM_XRAY")
    if env and os.path.exists(env):
        return env
    if is_android():
        try:
            path = os.path.join(str(_activity().getApplicationInfo().nativeLibraryDir), "libxray.so")
            return path if os.path.exists(path) else None
        except Exception:
            return None
    return shutil.which("xray")


def native_lib_listing():
    """What Android actually put in the app's native library folder (for error messages)."""
    try:
        d = str(_activity().getApplicationInfo().nativeLibraryDir)
        return "%s: %s" % (d, ", ".join(sorted(os.listdir(d))) or "(empty)")
    except Exception as e:
        return "cannot list native libs (%s)" % type(e).__name__


# ------------------------------------------------------------------ VPN layer (Java VpnService + tun2socks)
def hev_config(socks_port, mtu=1500):
    """Config for hev-socks5-tunnel: TUN packets -> Xray's local SOCKS5. mapdns makes DNS resolve at the far end."""
    return (
        "tunnel:\n  mtu: %d\n  ipv4: 198.18.0.1\n"
        "socks5:\n  port: %d\n  address: 127.0.0.1\n  udp: 'udp'\n"
        "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n"
        "misc:\n  log-level: warn\n" % (mtu, socks_port))


def vpn_prepare(callback):
    """Ask Android for the VPN permission. callback(bool) - may arrive on a non-Kivy thread."""
    from jnius import autoclass
    from android import activity
    act = _activity()
    intent = autoclass("android.net.VpnService").prepare(act)
    if intent is None:
        callback(True)
        return

    def on_result(request, result, data):
        if request != _REQ_VPN:
            return
        activity.unbind(on_activity_result=on_result)
        callback(result == -1)                    # Activity.RESULT_OK

    activity.bind(on_activity_result=on_result)
    act.startActivityForResult(intent, _REQ_VPN)


def _service_intent(mode, config_path):
    from jnius import autoclass
    Intent = autoclass("android.content.Intent")
    String = autoclass("java.lang.String")
    act = _activity()
    it = Intent()
    it.setClassName(act.getPackageName(), SERVICE)
    it.putExtra("mode", String(mode))
    it.putExtra("config", String(config_path or ""))
    return act, it


def start_service(mode, config_path=""):
    """mode 'vpn' = TUN + tun2socks (whole phone); 'proxy' = only a foreground notification that keeps the core alive."""
    from jnius import autoclass
    act, it = _service_intent(mode, config_path)
    if autoclass("android.os.Build$VERSION").SDK_INT >= 26:
        act.startForegroundService(it)
    else:
        act.startService(it)


def stop_service():
    act, it = _service_intent("stop", "")
    act.stopService(it)


def tunnel_state():
    """(service_running, tunnel_up, last_error)"""
    from jnius import autoclass
    cls = autoclass(SERVICE)
    return bool(cls.isRunning()), bool(cls.isTunnelUp()), str(cls.getLastError() or "")


def request_notifications():
    """Android 13+: lets the 'connected' notification show. Best effort - the connection works without it."""
    try:
        from android.permissions import request_permissions
        request_permissions(["android.permission.POST_NOTIFICATIONS"])
    except Exception:
        pass


# ------------------------------------------------------------------ data usage
def traffic_bytes():
    """(rx, tx) bytes this app has moved over the real network (loopback excluded) - i.e. what the tunnel really used."""
    try:
        from jnius import autoclass
        ts = autoclass("android.net.TrafficStats")
        uid = autoclass("android.os.Process").myUid()
        rx, tx = int(ts.getUidRxBytes(uid)), int(ts.getUidTxBytes(uid))
        return (rx, tx) if rx >= 0 and tx >= 0 else None
    except Exception:
        return None


# ------------------------------------------------------------------ misc intents
def view(url):
    from jnius import autoclass
    Intent = autoclass("android.content.Intent")
    Uri = autoclass("android.net.Uri")
    _activity().startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))


def launch_first(apps):
    """Open the first installed app from [(package, name)]; returns its name or None."""
    act = _activity()
    pm = act.getPackageManager()
    for pkg, name in apps:
        try:
            it = pm.getLaunchIntentForPackage(pkg)
        except Exception:
            it = None
        if it is not None:
            act.startActivity(it)
            return name
    return None


def share(text):
    from jnius import autoclass, cast
    Intent = autoclass("android.content.Intent")
    String = autoclass("java.lang.String")
    it = Intent()
    it.setAction(Intent.ACTION_SEND)
    it.putExtra(Intent.EXTRA_TEXT, String(text))
    it.setType("text/plain")
    chooser = Intent.createChooser(it, cast("java.lang.CharSequence", String("Share proxies")))
    _activity().startActivity(chooser)
