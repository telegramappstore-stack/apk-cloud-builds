"""python-for-android hook: registers NetFreeVpnService in the generated AndroidManifest.xml (idempotent).
Used through `p4a.hook = p4a_hook.py` in buildozer.spec. If you change package.domain/package.name, change SERVICE_CLASS too."""
import glob
import os

SERVICE_CLASS = "org.netfree.netfree.NetFreeVpnService"
SERVICE_XML = """
        <service android:name="%s"
                 android:permission="android.permission.BIND_VPN_SERVICE"
                 android:exported="false">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
        </service>
""" % SERVICE_CLASS


def _manifests(toolchain):
    seen = []
    roots = [os.getcwd()]
    for attr in ("_dist", "dist"):
        d = getattr(toolchain, attr, None)
        if d is not None and getattr(d, "dist_dir", None): roots.append(d.dist_dir)
    ctx = getattr(toolchain, "ctx", None)
    if ctx is not None and getattr(ctx, "dist_dir", None): roots.append(ctx.dist_dir)
    for r in roots:
        for p in (os.path.join(r, "src", "main", "AndroidManifest.xml"), os.path.join(r, "AndroidManifest.xml")):
            if os.path.exists(p) and p not in seen: seen.append(p)
        if not seen:
            seen += glob.glob(os.path.join(r, "**", "src", "main", "AndroidManifest.xml"), recursive=True)
    return seen


def _patch(toolchain):
    for p in _manifests(toolchain):
        with open(p, encoding="utf8") as f: s = f.read()
        if SERVICE_CLASS in s or "</application>" not in s: continue
        with open(p, "w", encoding="utf8") as f: f.write(s.replace("</application>", SERVICE_XML + "    </application>", 1))
        print("[p4a_hook] NetFreeVpnService registered in", p)


def after_apk_build(toolchain): _patch(toolchain)
def before_apk_assemble(toolchain): _patch(toolchain)
