[app]
p4a.branch = v2024.01.21
android.ndk = 25b
title = Aether
package.name = aether
package.domain = org.aether
source.dir = .
source.include_exts = py,png,jpg,kv,json
version = 1.0
requirements = python3,kivy==2.3.0,pyjnius
orientation = portrait
fullscreen = 0

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE,POST_NOTIFICATIONS
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.accept_sdk_license = True

# the usque binary, renamed to libusque.so (see steps)
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so

[buildozer]
log_level = 2
warn_on_root = 1
