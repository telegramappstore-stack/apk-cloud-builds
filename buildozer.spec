[app]
p4a.branch = master
android.ndk = 25b
title = AMINIUM
package.name = aminium
package.domain = org.aminium
source.dir = .
source.include_exts = py,png,jpg,kv,json,java,sh,xml
version = 1.0
requirements = python3,kivy==2.3.0,pyjnius,android,openssl,certifi
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/icon.png
android.presplash_color = #05050f

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE,POST_NOTIFICATIONS
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.accept_sdk_license = True
android.add_src = java
android.extra_manifest_application_arguments = ./manifest_app.xml

# the usque binary, renamed to libusque.so (see steps)
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so

[buildozer]
log_level = 2
warn_on_root = 1
