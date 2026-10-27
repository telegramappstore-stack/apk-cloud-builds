[app]
android.accept_sdk_license = True
android.ndk = 25b
title = Aether WARP
package.name = aetherwarp
package.domain = org.aether.warptool

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,so,java,md,sh,txt,xml
version = 1.0

requirements = python3,kivy==2.3.0,requests,cryptography,pyjnius,android,certifi,charset_normalizer,idna,urllib3,cffi,pycparser

orientation = portrait
fullscreen = 0

# icon.filename = %(source.dir)s/icon.png   # uncomment and add icon.png if you want a custom icon

# -------- Android --------
# android.api = target SDK the app is compiled against (keep current/stable)
# android.minapi = lowest Android version still supported ("و پایین تر" -> as low as practical)
android.api = 33
android.minapi = 24
android.ndk_api = 21
android.archs = arm64-v8a

android.permissions = INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS

# Pulls in the Java VpnService subclass (android_src/org/aether/warptool/VpnTunnelService.java)
android.add_src = android_src

# Injects the <service> (VpnTunnelService) declaration into AndroidManifest.xml.
# Requires a reasonably recent python-for-android; if your p4a is older and
# ignores this key, see README.md for the manual-patch fallback.
android.extra_manifest_xml = %(source.dir)s/extra_manifest.xml

# usque / tun2socks binaries are fetched by download_binaries.sh (run in CI,
# see .github/workflows/build.yml) into libs/<abi>/lib*.so BEFORE buildozer
# runs, so p4a packages them into jniLibs and Android is allowed to exec()
# them (required since Android 10's W^X restrictions).
android.add_libs_arm64_v8a = libs/arm64-v8a/*.so
android.add_libs_armeabi_v7a = libs/armeabi-v7a/*.so

# Necessary so Android actually extracts the bundled lib*.so files to a
# real on-disk, executable path (nativeLibraryDir) instead of running them
# straight out of the (non-executable) APK zip.
android.extract_native_libs = True
android.useLegacyPackaging = True

p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
