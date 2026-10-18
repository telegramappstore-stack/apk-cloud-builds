package org.aminium.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * Foreground service for Aminium.
 *   mode "vpn"   : builds the TUN interface and hands it to tun2socks (-> Xray's local SOCKS5 on 127.0.0.1).
 *   mode "proxy" : no TUN, only the foreground notification so Android keeps the app (and the Xray child process) alive.
 * Xray itself is started from Python; this app is excluded from the VPN so Xray's own sockets leave directly.
 */
public class AminiumVpnService extends VpnService {
    private static final String CHANNEL = "aminium_conn";
    private static volatile boolean running = false;
    private static volatile boolean tunnelUp = false;
    private static volatile String lastError = "";

    private ParcelFileDescriptor tun;

    public static boolean isRunning() { return running; }
    public static boolean isTunnelUp() { return tunnelUp; }
    public static String getLastError() { return lastError; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String mode = intent == null ? null : intent.getStringExtra("mode");
        String cfg = intent == null ? null : intent.getStringExtra("config");
        if (mode == null) { stopSelf(); return START_NOT_STICKY; }
        lastError = "";
        startForegroundCompat(mode);
        running = true;
        if ("vpn".equals(mode)) {
            try {
                startTunnel(cfg);
            } catch (Throwable t) {
                lastError = t.getClass().getSimpleName() + ": " + t.getMessage();
                stopTunnel();
                running = false;
                stopSelf();
            }
        }
        return START_NOT_STICKY;
    }

    private void startTunnel(String cfg) throws Exception {
        if (cfg == null || cfg.length() == 0) throw new IllegalArgumentException("no tunnel config");
        Builder b = new Builder();
        b.setSession("Aminium");
        b.setMtu(1500);
        b.addAddress("198.18.0.1", 32);
        b.addRoute("0.0.0.0", 0);
        b.addDnsServer("198.18.0.2");                    // answered by tun2socks "mapdns"
        try { b.addDisallowedApplication(getPackageName()); } catch (PackageManager.NameNotFoundException ignored) { }
        tun = b.establish();
        if (tun == null) throw new IllegalStateException("VPN permission was not granted");
        Tun2Socks.start(cfg, tun.getFd());
        tunnelUp = true;
    }

    private void stopTunnel() {
        if (tunnelUp) {
            try { Tun2Socks.stop(); } catch (Throwable ignored) { }
            tunnelUp = false;
        }
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) { }
            tun = null;
        }
    }

    private void startForegroundCompat(String mode) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_LOW));
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        int icon = getApplicationInfo().icon;
        if (icon == 0) icon = android.R.drawable.ic_dialog_info;
        b.setContentTitle("Aminium")
         .setContentText("vpn".equals(mode) ? "VPN connected" : "Local proxy running on 127.0.0.1")
         .setSmallIcon(icon)
         .setOngoing(true);
        Intent launch = getPackageManager().getLaunchIntentForPackage(getPackageName());
        if (launch != null) {
            b.setContentIntent(PendingIntent.getActivity(this, 0, launch,
                    Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
        }
        startForeground(1, b.build());
    }

    @Override
    public void onRevoke() {            // user turned the VPN off from system settings
        stopTunnel();
        running = false;
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        running = false;
        super.onDestroy();
    }
}
