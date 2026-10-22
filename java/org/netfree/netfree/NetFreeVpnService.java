package org.netfree.netfree;

import android.content.Intent;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * Establishes a VPN session (status-bar key icon). It has no tunnel routes, so normal traffic is untouched;
 * on Android 10+ the VPN network carries an HTTP proxy 127.0.0.1:<port> (the app's local SOCKS5/HTTP server),
 * which every app that honours the system proxy (browsers, many apps) uses automatically.
 */
public class NetFreeVpnService extends VpnService {
    public static volatile boolean running = false;
    public static volatile String error = "";
    private ParcelFileDescriptor tun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        int port = 1080;
        try {
            String p = intent == null ? null : intent.getStringExtra("port");
            if (p != null) port = Integer.parseInt(p);
        } catch (Exception ignored) { }
        closeTun();
        error = "";
        try {
            Builder b = new Builder();
            b.setSession("NetFree");
            b.addAddress("10.77.0.2", 32);
            b.setMtu(1500);
            try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignored) { }
            if (Build.VERSION.SDK_INT >= 29) {
                b.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", port));
            }
            tun = b.establish();
            running = (tun != null);
            if (!running) error = "establish() returned null (permission revoked?)";
        } catch (Throwable t) {
            running = false;
            error = String.valueOf(t);
        }
        return START_NOT_STICKY;
    }

    private void closeTun() {
        running = false;
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) { }
            tun = null;
        }
    }

    @Override
    public void onRevoke() {
        closeTun();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        closeTun();
        super.onDestroy();
    }
}
