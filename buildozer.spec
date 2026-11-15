[app]
p4a.branch = v2024.01.21
title = Aminium Studio
package.name = aminiumstudio
package.domain = org.aminium

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,zip,json,txt,md,yml
# put aminium-pages.zip next to main.py before building so it ends up bundled in the APK
source.include_patterns = aminium-pages.zip

version = 1.0.0

requirements = python3,kivy==2.3.0,requests,pysocks,qrcode,certifi,pillow,pyjnius,urllib3,idna,charset-normalizer

orientation = portrait
fullscreen = 0

icon.filename = %(source.dir)s/icon.png

android.permissions = INTERNET,ACCESS_NETWORK_STATE

# Android 14 = API level 34
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a

# release builds need these, see step_card below for how to use them
#android.release_artifact = aab
#android.keystore = %(source.dir)s/release.keystore
#android.keyalias = aminium

android.allow_backup = True
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
