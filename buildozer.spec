[app]
title = Aminium
package.name = aminium
package.domain = org.aminium
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,java,md,xml
source.exclude_dirs = java,libs,bin,.buildozer,__pycache__
version = 2.0
requirements = python3,kivy==2.3.0,certifi,pyjnius,android
orientation = portrait
fullscreen = 0
# icon.filename = %(source.dir)s/icon.png
android.presplash_color = #070B16

android.permissions = INTERNET,ACCESS_NETWORK_STATE,QUERY_ALL_PACKAGES,FOREGROUND_SERVICE,POST_NOTIFICATIONS
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
p4a.branch = v2024.01.21

# Java VpnService + tun2socks stubs
android.add_src = java
android.extra_manifest_application_arguments = extra_manifest.xml

# Native pieces you must drop into libs/arm64-v8a/ (see SETUP.md):
#   libxray.so                 <- the "xray" binary from Xray-android-arm64-v8a.zip, renamed
#   libhev-socks5-tunnel.so    <- tun2socks library
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so
# Android must EXTRACT libxray.so to disk so it can be executed as a program
android.add_packaging_options = jniLibs.useLegacyPackaging = true

[buildozer]
log_level = 2
warn_on_root = 1
