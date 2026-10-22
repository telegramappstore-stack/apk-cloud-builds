[app]
title = Amizoo
package.name = proxyscout
package.domain = org.proxyscout
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,java
version = 1.2
requirements = python3,kivy==2.3.0,certifi
orientation = portrait
icon.filename = %(source.dir)s/icon.png
icon.adaptive_foreground.filename = %(source.dir)s/icon_fg.png
icon.adaptive_background.filename = %(source.dir)s/icon_bg.png
presplash.filename = %(source.dir)s/presplash.png
presplash.color = #221850
fullscreen = 0
android.permissions = INTERNET,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
android.add_src = java
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so
p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1
