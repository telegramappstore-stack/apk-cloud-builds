[app]
title = NetFree
package.name = netfree
package.domain = org.netfree
source.dir = .
source.include_exts = py,png,jpg,ttf,java,sh,xml,yml
source.exclude_dirs = java,libs,bin,.github,.buildozer
version = 2.1
# openssl + certifi: TLS on Android; arabic-reshaper + python-bidi 0.4.2 (pure python): Persian text
requirements = python3,kivy==2.3.0,openssl,certifi,arabic-reshaper==3.0.0,python-bidi==0.4.2,six,pyjnius,android
orientation = portrait
fullscreen = 0

# background service = proxy engine, keeps running after the UI is closed
services = netfree:service.py:foreground:sticky

# VPN (key icon): Java VpnService + hev-socks5-tunnel native lib (built by the CI workflow into libs/)
android.add_src = java
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so
android.add_libs_armeabi_v7a = libs/armeabi-v7a/*.so
p4a.hook = p4a_hook.py
p4a.branch = v2024.01.21

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.ndk_api = 24
android.archs = arm64-v8a
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 0
