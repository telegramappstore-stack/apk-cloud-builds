# Aminium - راه‌اندازی

## ساختار پوشه
```
main.py  proxycore.py  xraycore.py  androidbridge.py
buildozer.spec  extra_manifest.xml
java/            (سرویس VPN - آماده است)
libs/arm64-v8a/  (دو فایل را خودت اینجا می‌گذاری)
```

## دو فایل native که باید بگذاری
1. `libs/arm64-v8a/libxray.so`
   از https://github.com/XTLS/Xray-core/releases فایل `Xray-android-arm64-v8a.zip` را بگیر،
   فایل `xray` داخلش را به `libxray.so` تغییر نام بده. (نسخه‌ی جدید بگیر؛ transport نوع xhttp فقط در نسخه‌های جدید هست.)
2. `libs/arm64-v8a/libhev-socks5-tunnel.so`
   (tun2socks برای VPN کل گوشی). ساده‌ترین راه: APK نسخه‌ی arm64 برنامه‌ی v2rayNG را مثل zip باز کن و
   `lib/arm64-v8a/libhev-socks5-tunnel.so` را کپی کن. یا از https://github.com/heiher/hev-socks5-tunnel بساز.

بدون فایل دوم برنامه کار می‌کند ولی فقط به صورت «پروکسی محلی» (127.0.0.1:10808 / 10809).

## ساخت
```
buildozer android debug
```
نام بسته عوض شده (org.aminium.aminium)، پس روی گوشی به عنوان برنامه‌ی جدید نصب می‌شود؛ ProxyScout قدیمی را خودت پاک کن.

## اگر libxray.so اجرا نشد
پیام «Xray core not found» یعنی اندروید فایل را روی دیسک extract نکرده. خط
`android.add_packaging_options = jniLibs.useLegacyPackaging = true` در buildozer.spec همین کار را می‌کند؛
اگر نسخه‌ی p4a شما این را قبول نکرد، لاگ gradle را ببین.
