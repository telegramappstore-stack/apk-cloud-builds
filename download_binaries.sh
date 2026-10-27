#!/usr/bin/env bash
# Fetches the two native binaries the app needs and stages them where
# buildozer.spec expects them (libs/<abi>/lib*.so). Run this BEFORE
# `buildozer android debug` (the GitHub Actions workflow already does this).
#
# IMPORTANT: Android will only let the app exec() a bundled binary if it is
# shipped as lib<name>.so under jniLibs for a real ABI -- that's why plain
# binaries get renamed to libusque.so / libtun2socks.so below.
#
# These two upstream projects do not always publish ready-made Android
# binaries for every release, so this script tries a release asset first
# and falls back to cross-compiling from source with Go (which DOES
# support GOOS=android). Review/adjust the asset name patterns and repo
# URLs below if upstream renames things.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ROOT/libs/arm64-v8a" "$ROOT/libs/armeabi-v7a"

USQUE_REPO="Diniboy1123/usque"
TUN2SOCKS_REPO="xjasonlyu/tun2socks"

fetch_release_asset() {
  # $1 = repo, $2 = grep pattern for asset name, $3 = output path
  local repo="$1" pattern="$2" out="$3"
  local api="https://api.github.com/repos/${repo}/releases/latest"
  echo "Looking for '${pattern}' in latest release of ${repo}..."
  local url
  url=$(curl -fsSL "$api" | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
        | sed -E 's/.*"(https[^"]+)"/\1/' | grep -Ei "$pattern" | head -n1 || true)
  if [[ -z "$url" ]]; then
    echo "  -> no matching asset found."
    return 1
  fi
  echo "  -> $url"
  curl -fsSL "$url" -o "$out"
  chmod +x "$out"
  return 0
}

build_usque_from_source() {
  local out_arm64="$1" out_arm="$2"
  echo "Building usque from source for android/arm64 and android/arm..."
  command -v go >/dev/null || { echo "go not installed; cannot build usque from source"; return 1; }
  local tmp; tmp=$(mktemp -d)
  git clone --depth 1 "https://github.com/${USQUE_REPO}.git" "$tmp/usque"
  pushd "$tmp/usque" >/dev/null
  GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o "$out_arm64" . || echo "  arm64 build failed"
  GOOS=android GOARCH=arm  CGO_ENABLED=0 go build -o "$out_arm"   . || echo "  armv7 build failed"
  popd >/dev/null
  rm -rf "$tmp"
}

build_tun2socks_from_source() {
  local out_arm64="$1" out_arm="$2"
  echo "Building tun2socks from source for android/arm64 and android/arm..."
  command -v go >/dev/null || { echo "go not installed; cannot build tun2socks from source"; return 1; }
  local tmp; tmp=$(mktemp -d)
  git clone --depth 1 "https://github.com/${TUN2SOCKS_REPO}.git" "$tmp/tun2socks"
  pushd "$tmp/tun2socks" >/dev/null
  GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o "$out_arm64" ./cmd/tun2socks || echo "  arm64 build failed"
  GOOS=android GOARCH=arm  CGO_ENABLED=0 go build -o "$out_arm"   ./cmd/tun2socks || echo "  armv7 build failed"
  popd >/dev/null
  rm -rf "$tmp"
}

# ---- usque ----
if ! fetch_release_asset "$USQUE_REPO" 'android.*arm64|arm64.*android' \
      "$ROOT/libs/arm64-v8a/libusque.so"; then
  build_usque_from_source "$ROOT/libs/arm64-v8a/libusque.so" "$ROOT/libs/armeabi-v7a/libusque.so" || true
fi
if [[ ! -f "$ROOT/libs/armeabi-v7a/libusque.so" ]]; then
  fetch_release_asset "$USQUE_REPO" 'android.*arm[^6]|armv7.*android' \
      "$ROOT/libs/armeabi-v7a/libusque.so" || true
fi

# ---- tun2socks ----
if ! fetch_release_asset "$TUN2SOCKS_REPO" 'android-arm64' \
      "$ROOT/libs/arm64-v8a/libtun2socks.so"; then
  build_tun2socks_from_source "$ROOT/libs/arm64-v8a/libtun2socks.so" "$ROOT/libs/armeabi-v7a/libtun2socks.so" || true
fi
if [[ ! -f "$ROOT/libs/armeabi-v7a/libtun2socks.so" ]]; then
  fetch_release_asset "$TUN2SOCKS_REPO" 'android-armv7|android-arm[^6]' \
      "$ROOT/libs/armeabi-v7a/libtun2socks.so" || true
fi

echo
echo "Result:"
ls -la "$ROOT/libs/arm64-v8a" "$ROOT/libs/armeabi-v7a" 2>/dev/null || true

missing=0
for f in "$ROOT/libs/arm64-v8a/libusque.so" "$ROOT/libs/arm64-v8a/libtun2socks.so"; do
  [[ -s "$f" ]] || { echo "MISSING (required): $f"; missing=1; }
done
if [[ "$missing" == "1" ]]; then
  echo
  echo "Could not obtain arm64 binaries automatically. Download/build them"
  echo "yourself and place them at the paths above before running buildozer,"
  echo "or re-run this script once the upstream release asset names are fixed."
  exit 1
fi
