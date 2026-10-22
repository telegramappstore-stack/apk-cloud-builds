[app]
p4a.branch = v2024.01.21
android.ndk = 25b
title = NetFree
package.name = netfree
package.domain = org.netfree
source.dir = .
source.include_exts = py,png,jpg,ttf
version = 2.0
# openssl + certifi: needed for TLS; arabic-reshaper + python-bidi(0.4.2 = pure python): Persian text
requirements = python3,kivy==2.3.0,openssl,certifi,arabic-reshaper==3.0.0,python-bidi==0.4.2,six,pyjnius,android
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
