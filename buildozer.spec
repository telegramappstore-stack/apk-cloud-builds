[app]
p4a.branch = v2024.01.21
title = Proxy Checker
package.name = proxychecker
package.domain = org.proxy
source.dir = .
source.include_exts = py
version = 1.0
requirements = python3,kivy==2.3.0,requests,urllib3,chardet,idna,certifi,charset-normalizer,beautifulsoup4,soupsieve,typing_extensions
orientation = portrait
fullscreen = 0
android.permissions = INTERNET
android.api = 33
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
