#!/bin/bash
# Builds libhev-socks5-tunnel.so (arm64) and copies it to libs/arm64-v8a/. Run on Linux/WSL.
# Run `buildozer android debug` once BEFORE this (it downloads the NDK this script uses).
set -e
HERE=$(pwd)
NDK=$(ls -d ~/.buildozer/android/platform/android-ndk-r* 2>/dev/null | head -1)
[ -z "$NDK" ] && { echo "NDK not found. Run 'buildozer android debug' once first."; exit 1; }
W=$(mktemp -d); mkdir -p "$W/jni"; cd "$W/jni"
git clone --recursive https://github.com/heiher/hev-socks5-tunnel
echo 'include $(call all-subdir-makefiles)' > Android.mk
printf 'APP_ABI := arm64-v8a\nAPP_PLATFORM := android-24\nAPP_OPTIM := release\n' > Application.mk
cd "$W"
"$NDK/ndk-build" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk -j4
mkdir -p "$HERE/libs/arm64-v8a"
cp libs/arm64-v8a/libhev-socks5-tunnel.so "$HERE/libs/arm64-v8a/"
echo "DONE -> libs/arm64-v8a/libhev-socks5-tunnel.so"
