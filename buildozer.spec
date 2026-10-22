[app]
title = Aminium
package.name = aminium
package.domain = app.aminium
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,txt
version = 1.0.0

# core.py is imported by main.py, so both ship in the APK
requirements = python3,kivy==2.3.1,pyjnius,certifi,android

icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
android.presplash_color = #EDF0FF

orientation = portrait
fullscreen = 0

# Android 16 = API 36
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
android.allow_backup = False
android.permissions = INTERNET

# API 36 support needs the current python-for-android
p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1
