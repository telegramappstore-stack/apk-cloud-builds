# نسخه‌ی «امن» برای اولین بیلد: بدون جاوا، بدون فایل native، بدون packaging option.
# اگر این بیلد شد، یعنی مشکل از یکی از خط‌های حذف‌شده بوده. برای استفاده، نامش را به buildozer.spec تغییر بده.
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
android.presplash_color = #070B16

android.permissions = INTERNET,ACCESS_NETWORK_STATE,QUERY_ALL_PACKAGES,FOREGROUND_SERVICE,POST_NOTIFICATIONS
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1
