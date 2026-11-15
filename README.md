# Aminium Studio - Kivy / Android port

## What changed vs. the desktop app
- **Only functional addition**: a **"My configs"** screen (`ManageScreen` in `main.py`) that lists
  every deployment ever built on the device, lets you **load** it back into step 4, **rename** its
  label, or **delete** it from the local list. All scanning / Cloudflare / config-generation logic
  is byte-for-byte the same as the desktop app - it was only moved out of the tkinter classes into
  plain functions in `aminium_core.py` so the Kivy screens can call it.
- The UI itself is rewritten in Kivy (`main.py` + the `KV` string inside it) because `customtkinter`
  does not run on Android; nothing about *what* the app does was changed, only the toolkit.

## Files
| File | Purpose |
|---|---|
| `aminium_core.py` | Unmodified scanner + Cloudflare API client + config/QR generation, pulled out of the original script, plus the new `load_deployments / rename_deployment / delete_deployment` helpers. |
| `main.py` | Kivy app: Token → Clean IPs → Build → Configs (same 4 steps) + My configs. |
| `buildozer.spec` | Build recipe, targets **Android 14 (API 34)**, `minapi 24`. |
| `github_uploader.py` | Separate **desktop** tool (own Tk GUI) to push the built APK to a GitHub Release with a token. |

## Building the APK
```bash
pip install buildozer cython
# put your panel source next to main.py first:
cp /path/to/aminium-pages.zip .
buildozer -v android debug
# output: bin/aminiumstudio-1.0.0-arm64-v8a_armeabi-v7a-debug.apk
```
First run downloads the Android SDK/NDK (several GB) - only needed once.

For a **release** build (needed for the Play Store, or any store-signed install):
```bash
buildozer android release
# then sign + zipalign with your own keystore (see buildozer's own docs: the
# android.keystore / android.keyalias lines in buildozer.spec)
```

## A note on the install-time warning
A plain, self-signed **debug** APK installed outside the Play Store will normally trigger Android's
"unknown app" / Play Protect notice - that is expected behavior for *any* sideloaded app, not a
flag on this app specifically, and it is not something that can be removed by changing the app's
code. The two things that actually reduce it are outside the scope of a build script:
1. A **release build signed with your own long-lived keystore** (not the debug key) - lets Play
   Protect build a reputation for that signature over time.
2. **Publishing through Google Play** (even as an internal/closed test track) - Play-distributed
   apps go through Play Protect's pre-review and do not show the "unknown sources" warning at all.
I didn't add anything that tries to suppress or spoof that warning - that would mean hiding the
app's behavior from a security scanner, which isn't something I can help build, independent of the
app's own purpose.

## Uploading a build to GitHub automatically
```bash
pip install requests
python github_uploader.py
```
Enter a GitHub **personal access token** (classic PAT with the `repo` scope, or a fine-grained PAT
with "Contents: Read and write" on the target repo), the repo owner/name, a release tag, and the
`.apk` file - then press **Upload to GitHub**. It creates the release if it doesn't exist yet and
(re)uploads the file as a release asset. Tick "Remember on this PC" to save those fields (including
the token) in `~/.aminium_github_uploader.json` on that machine only.
