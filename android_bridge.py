"""
android_bridge.py - talks to VpnTunnelService (the Java VpnService) from
Python/Kivy, using pyjnius. Does nothing (safely) when not running on
Android, so the rest of the app / desktop testing is unaffected.

Flow for a "real" system-wide tunnel (the thing that makes the Android
status-bar key icon appear):
    1. usque is already running locally as a SOCKS5 proxy (see main.py).
    2. request_vpn_permission(on_result) -> shows Android's one-time
       "<app> wants to set up a VPN connection" system dialog (VpnService
       .prepare()). Must be called from the main/UI thread.
    3. once granted, start_vpn(socks_port) sends ACTION_CONNECT to
       VpnTunnelService, which establishes the TUN device and hands it to
       tun2socks -> this is what actually shows the key icon.
    4. stop_vpn() sends ACTION_DISCONNECT.
"""
import logging

log = logging.getLogger("android_bridge")

IS_ANDROID = False
try:
    from jnius import autoclass, cast  # noqa: F401
    from android import activity as _android_activity  # noqa: F401
    IS_ANDROID = True
except Exception:
    IS_ANDROID = False

VPN_PREPARE_REQUEST_CODE = 7171

_pending_callback = {"cb": None}


def _on_activity_result(request_code, result_code, intent):
    if request_code != VPN_PREPARE_REQUEST_CODE:
        return
    RESULT_OK = -1  # android.app.Activity.RESULT_OK
    granted = result_code == RESULT_OK
    cb = _pending_callback.get("cb")
    _pending_callback["cb"] = None
    if cb:
        cb(granted)


if IS_ANDROID:
    try:
        _android_activity.bind(on_activity_result=_on_activity_result)
    except Exception:  # noqa: BLE001
        log.exception("could not bind on_activity_result")


def _get_activity():
    PythonActivity = autoclass("org.kivy.android.PythonActivity")
    return PythonActivity.mActivity


def request_vpn_permission(on_result):
    """on_result(granted: bool) is called once the user answers the
    system VPN consent dialog (or immediately with True if Android has
    already granted it for this app before)."""
    if not IS_ANDROID:
        on_result(False)
        return
    VpnService = autoclass("android.net.VpnService")
    activity = _get_activity()
    intent = VpnService.prepare(activity)
    if intent is None:
        on_result(True)  # already granted
        return
    _pending_callback["cb"] = on_result
    activity.startActivityForResult(intent, VPN_PREPARE_REQUEST_CODE)


def start_vpn(socks_port: int, dns: str = "1.1.1.1"):
    if not IS_ANDROID:
        log.info("start_vpn: not on Android, skipping (desktop test mode)")
        return
    Intent = autoclass("android.content.Intent")
    Service = autoclass("org.aether.warptool.VpnTunnelService")
    activity = _get_activity()
    intent = Intent(activity, Service)
    intent.setAction("org.aether.warptool.CONNECT")
    intent.putExtra("socks_port", int(socks_port))
    intent.putExtra("dns", dns)
    activity.startService(intent)


def stop_vpn():
    if not IS_ANDROID:
        log.info("stop_vpn: not on Android, skipping (desktop test mode)")
        return
    Intent = autoclass("android.content.Intent")
    Service = autoclass("org.aether.warptool.VpnTunnelService")
    activity = _get_activity()
    intent = Intent(activity, Service)
    intent.setAction("org.aether.warptool.DISCONNECT")
    activity.startService(intent)


def keep_screen_on_and_wakelock():
    """Optional: acquire a partial wakelock so Android doesn't kill the
    background usque/tun2socks processes as aggressively. Call once after
    connecting."""
    if not IS_ANDROID:
        return None
    try:
        PowerManager = autoclass("android.os.PowerManager")
        activity = _get_activity()
        pm = activity.getSystemService(activity.POWER_SERVICE)
        wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "AetherWarp::Tunnel")
        wl.acquire()
        return wl
    except Exception:  # noqa: BLE001
        log.exception("wakelock failed")
        return None
