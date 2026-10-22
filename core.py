"""
Aminium core - Cloudflare API logic (no UI).

A port of BPB-Wizard (https://github.com/bia-pain-bache/BPB-Wizard)
by bia-pain-bache, licensed GPL-3.0. This program is released under GPL-3.0 too.
"""
import io
import json
import re
import secrets
import ssl
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Android ships no CA bundle that Python can see, so use certifi's.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:  # desktop fallback
    _SSL_CTX = ssl.create_default_context()

APP_NAME = "Aminium"
CF = "https://api.cloudflare.com/client/v4"
WORKER_URL = "https://github.com/bia-pain-bache/BPB-Worker-Panel/releases/latest/download/worker.js"
UA = "Aminium-Android/1.0"

# Same permission groups the original wizard requests (key, level, human name, why)
PERMISSIONS = [
    ("workers_scripts", "edit", "Workers Scripts", "upload the panel (Workers)"),
    ("workers_kv_storage", "edit", "Workers KV Storage", "database the panel stores settings in"),
    ("page", "edit", "Cloudflare Pages", "upload the panel (Pages)"),
    ("dns", "edit", "DNS", "used by the panel for custom domains"),
    ("user_details", "read", "User Details", "read your account email"),
]

PASS_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$&*_-+;:,."
PATH_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456780-_"
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


# ------------------------------------------------------------------ randomness
def rand_int(lo, hi):
    return lo + secrets.randbelow(hi - lo + 1)


def rand_string(charset, min_len, max_len):
    n = rand_int(min_len, max_len)
    return "".join(charset[secrets.randbelow(len(charset))] for _ in range(n))


def rand_subdomain():
    cs = "abcdefghijklmnopqrstuvwxyz0123456789-"
    while True:
        s = rand_string(cs, 16, 32)
        if not s.startswith("-") and not s.endswith("-"):
            return s


def rand_code():
    """Junk vars/functions prepended to every build so each deployment is unique."""
    cs = "abcdefghijklmnopqrstuvwxyz0123456789"
    out = []
    for i in range(rand_int(50, 500)):
        out.append(f"let __var_{rand_string(cs, 8, 16)}_{i} = {rand_int(0, 99999)};\n")
    for i in range(rand_int(50, 500)):
        out.append(f"function __func_{rand_string(cs, 8, 16)}_{i}() {{ return {rand_int(0, 999)}; }}\n")
    return "".join(out)


# ------------------------------------------------------------------- HTTP layer
class CFError(Exception):
    pass


def http_ex(method, url, token=None, data=None, headers=None, timeout=60):
    h = {"User-Agent": UA}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.status, r.read(), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read(), url


def http(method, url, token=None, data=None, headers=None, timeout=60):
    status, content, _ = http_ex(method, url, token, data, headers, timeout)
    return status, content


def cf(method, path, token, body=None, raw=None, headers=None):
    data, hdr = raw, dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdr["Content-Type"] = "application/json"
    status, content = http(method, CF + path, token, data, hdr)
    try:
        j = json.loads(content)
    except ValueError:
        raise CFError(f"HTTP {status}: {content[:200]!r}")
    if not j.get("success"):
        errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in j.get("errors", [])) \
            or f"HTTP {status}"
        raise CFError(errs)
    return j.get("result")


def multipart(fields):
    """fields: (name, filename|None, content_type|None, bytes|str)"""
    boundary = "----AminiumBoundary" + secrets.token_hex(8)
    buf = io.BytesIO()
    for name, filename, ctype, content in fields:
        buf.write(f"--{boundary}\r\n".encode())
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        buf.write((disp + "\r\n").encode())
        if ctype:
            buf.write(f"Content-Type: {ctype}\r\n".encode())
        buf.write(b"\r\n")
        buf.write(content if isinstance(content, bytes) else content.encode())
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


def utc_date():
    return time.strftime("%Y-%m-%d", time.gmtime())


# ------------------------------------------------------------ token / account
def build_token_url():
    perms = [{"key": k, "type": t} for k, t, _, _ in PERMISSIONS]
    q = urllib.parse.urlencode({
        "permissionGroupKeys": json.dumps(perms, separators=(",", ":")),
        "accountId": "*",
        "zoneId": "all",
        "name": APP_NAME,
    })
    return "https://dash.cloudflare.com/profile/api-tokens?" + q


def verify_token(token):
    r = cf("GET", "/user/tokens/verify", token)
    if r.get("status") != "active":
        raise CFError("Token is not active.")


def list_accounts(token):
    return cf("GET", "/accounts", token) or []


def get_email(token):
    return cf("GET", "/user", token).get("email", "")


def name_taken(token, acc, deploy_type, name):
    try:
        if deploy_type == "pages":
            cf("GET", f"/accounts/{acc}/pages/projects/{name}", token)
        else:
            cf("GET", f"/accounts/{acc}/workers/scripts/{name}", token)
        return True
    except CFError:
        return False


def create_kv(token, acc, name, deploy_type):
    title = f"{name}-{deploy_type}-{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
    return cf("POST", f"/accounts/{acc}/storage/kv/namespaces", token, {"title": title})["id"]


def get_workers_subdomain(token, acc, log):
    try:
        r = cf("GET", f"/accounts/{acc}/workers/subdomain", token)
        if r and r.get("subdomain"):
            log("Account workers subdomain is available!")
            return r["subdomain"] + ".workers.dev"
    except CFError:
        pass
    last = None
    for _ in range(3):
        try:
            r = cf("PUT", f"/accounts/{acc}/workers/subdomain", token, {"subdomain": rand_subdomain()})
            log("Fresh account, Workers subdomain created successfully!")
            return r["subdomain"] + ".workers.dev"
        except CFError as e:
            last = e
    raise CFError(f"Failed to create a unique workers.dev subdomain: {last}")


# ---------------------------------------------------------------- script build
def make_settings(acc_id, email, token, main_domain):
    return {
        "accID": acc_id,
        "accEmail": email,
        "apiToken": token,
        "vlUUID": str(uuid.uuid4()),
        "trPass": rand_string(PASS_CHARSET, 16, 32),
        "securePath": rand_string(PATH_CHARSET, 16, 32),
        "proxyIpMode": "proxyip",
        "proxyIPs": [],
        "prefixes": [],
        "fallback": "",
        "dohUrl": "",
        "mainDomain": main_domain,
    }


def build_script(raw, settings):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    blob = json.dumps(settings, separators=(",", ":"))
    return (f"// {settings['accEmail']}\n// {stamp}\n// @ts-nocheck\n"
            f"{rand_code()}\nconst EMBEDED_SETTINGS = {blob};{raw}")


def fetch_worker(log=None, source=None):
    """source: None = official release, 'https://...' = your own URL, else a local file path."""
    if source and not source.lower().startswith("http"):
        text = Path(source).expanduser().read_text(encoding="utf-8")
        if log:
            log(f"Panel script source: local file {source}")
            log(f"Panel script size: {len(text) // 1024} KB")
        return text
    url = source or WORKER_URL
    status, content, final = http_ex("GET", url, timeout=120)
    if status != 200:
        raise RuntimeError(f"Could not download the panel script (HTTP {status}) from {url}. "
                           "Check the address, your internet/VPN, and that the release is public.")
    text = content.decode("utf-8")
    if text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        raise RuntimeError("Downloaded an HTML page instead of the panel script (wrong address or network filter?).")
    if log:
        log(f"Panel script source: {final}")
        log(f"Panel script size: {len(text) // 1024} KB")
    return text


def deploy_worker(token, acc, name, script, kv_id):
    meta = {
        "main_module": "worker.js",
        "compatibility_date": utc_date(),
        "compatibility_flags": ["nodejs_compat"],
        "bindings": [{"type": "kv_namespace", "name": "kv", "namespace_id": kv_id}],
    }
    body, ctype = multipart([
        ("metadata", None, "application/json", json.dumps(meta)),
        ("worker.js", "worker.js", "application/javascript+module", script),
    ])
    cf("PUT", f"/accounts/{acc}/workers/scripts/{name}", token, raw=body, headers={"Content-Type": ctype})


def enable_worker_subdomain(token, acc, name):
    cf("POST", f"/accounts/{acc}/workers/scripts/{name}/subdomain", token, {"enabled": True})


def create_pages_project(token, acc, name, kv_id):
    body = {
        "name": name,
        "production_branch": "main",
        "deployment_configs": {"production": {
            "compatibility_date": utc_date(),
            "compatibility_flags": ["nodejs_compat"],
            "kv_namespaces": {"kv": {"namespace_id": kv_id}},
        }},
    }
    return cf("POST", f"/accounts/{acc}/pages/projects", token, body)["subdomain"]


def deploy_pages(token, acc, name, script):
    body, ctype = multipart([
        ("manifest", None, None, "{}"),
        ("branch", None, None, "main"),
        ("_worker.js", "_worker.js", "application/javascript+module", script),
    ])
    cf("POST", f"/accounts/{acc}/pages/projects/{name}/deployments", token, raw=body,
       headers={"Content-Type": ctype})


def health(url):
    """(HTTP status, body) from the live panel, or (None, "") if unreachable."""
    for _ in range(6):
        try:
            s, body = http("GET", url, timeout=15)
            return s, body.decode("utf-8", "replace")
        except Exception:
            time.sleep(5)
    return None, ""


# ------------------------------------------------------- high-level workflows
def run_check(token, log, set_perm, set_accounts):
    """Verify the token, list accounts and probe permissions. Raises RuntimeError on failure."""
    for k, *_ in PERMISSIONS:
        set_perm(k, "checking")
    log("Checking token...")
    try:
        verify_token(token)
    except CFError as e:
        raise RuntimeError(f"Token rejected: {e}")
    accs = list_accounts(token)
    if not accs:
        raise RuntimeError("Token is valid but no account is visible. Create it with 'All accounts'.")
    set_accounts({f"{a['name']}  ({a['id']})": a["id"] for a in accs})
    acc = accs[0]["id"]
    tests = {
        "user_details": "/user",
        "workers_scripts": f"/accounts/{acc}/workers/scripts",
        "workers_kv_storage": f"/accounts/{acc}/storage/kv/namespaces?per_page=5",
        "page": f"/accounts/{acc}/pages/projects",
    }
    for key, path in tests.items():
        try:
            cf("GET", path, token)
            set_perm(key, "OK")
        except CFError as e:
            set_perm(key, "MISSING")
            log(f"Permission problem ({key}): {e}")
    set_perm("dns", "n/a")
    log("Token check done. (DNS can't be tested here; Edit level is confirmed while installing.)")


def run_deploy(token, acc, name, dtype, rename, source, log, save_dir):
    """Install the panel. Returns the panel URL."""
    email = get_email(token)
    if name_taken(token, acc, dtype, name):
        raise RuntimeError("This project name is already used in your account. Tap Randomize.")

    log("Downloading the latest panel script...")
    raw = fetch_worker(log, source)
    patched = raw.replace("BPB", rename) if rename else raw
    if rename:
        log(f"Experimental rename: replaced {raw.count('BPB')} occurrence(s) of 'BPB'.")

    log("Installing panel...")
    kv_id = create_kv(token, acc, name, dtype)
    log("KV namespace created successfully!")

    if dtype == "pages":
        settings = make_settings(acc, email, token, f"{name}.pages.dev")
        host = create_pages_project(token, acc, name, kv_id)
        log("Pages project created successfully!")
        deploy_pages(token, acc, name, build_script(patched, settings))
        log("Pages deployed successfully!")
        base = f"https://{host}"
        redeploy = lambda code: deploy_pages(token, acc, name, build_script(code, settings))
    else:
        sub = get_workers_subdomain(token, acc, log)
        settings = make_settings(acc, email, token, f"{name}.{sub}")
        deploy_worker(token, acc, name, build_script(patched, settings), kv_id)
        log("Worker deployed successfully!")
        enable_worker_subdomain(token, acc, name)
        log("Worker subdomain enabled successfully!")
        base = f"https://{name}.{sub}"
        redeploy = lambda code: deploy_worker(token, acc, name, build_script(code, settings), kv_id)

    panel_url = f"{base}/{urllib.parse.quote_plus(settings['securePath'])}/panel"

    log("Checking that the panel starts...")
    status, body = health(base + "/")
    if rename and status is not None and status >= 500:
        log(f"Panel returned HTTP {status} after the rename. Reverting to the original script...")
        redeploy(raw)
        status, body = health(base + "/")
        log("Rename was reverted because it broke this panel version.")
    if status is None:
        log("Could not reach the panel from here (workers.dev / pages.dev may be blocked on your network). "
            "Try the link with a VPN or another network.")
    else:
        log(f"Panel responded (HTTP {status}).")
        if status >= 400:
            snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()[:300]
            log(f"Response text: {snippet}")
            log("If this says 'Error 1101' the Worker crashed on startup. In the Cloudflare dashboard open "
                "Workers & Pages > your worker > Logs and reload the page to see the exception.")

    try:
        info = Path(save_dir) / "Aminium-deployment.txt"
        with open(info, "a", encoding="utf-8") as fh:
            fh.write(f"\n[{time.strftime('%Y-%m-%d %H:%M')}] {dtype} {name}\npanel={panel_url}\n")
        log(f"{APP_NAME} panel successfully installed!  Saved to: {info}")
    except OSError:
        log(f"{APP_NAME} panel successfully installed!")
    return panel_url
