package org.aether.warptool;

/*
 * VpnTunnelService - a standard Android VpnService that:
 *   1) establishes a TUN interface (0.0.0.0/0 route -> this is what makes
 *      Android show the little "key" / VPN icon in the status bar),
 *   2) hands the TUN file descriptor to a bundled tun2socks binary,
 *   3) tun2socks converts all IP packets on the TUN device into SOCKS5
 *      connections against 127.0.0.1:<usqueSocksPort>, where usque (the
 *      MASQUE/WARP client) is already listening.
 *
 * This is the same overall pattern used by most open-source Android
 * SOCKS-based VPN front-ends (shadowsocks-android, v2rayNG, etc.): the
 * Python/Kivy side starts `usque` first (as a local SOCKS5 proxy), then
 * asks Android to start this service, which in turn starts `tun2socks`.
 *
 * Build note: both binaries (usque, tun2socks) must be shipped as
 * lib*.so under jniLibs/<abi>/ (see download_binaries.sh + buildozer.spec)
 * so Android actually permits exec()'ing them -- this is required since
 * Android 10 (API 29) W^X / scoped-storage restrictions block executing
 * any binary that isn't packaged that way.
 */

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;

public class VpnTunnelService extends VpnService {

    public static final String TAG = "AetherVpnService";
    public static final String ACTION_CONNECT = "org.aether.warptool.CONNECT";
    public static final String ACTION_DISCONNECT = "org.aether.warptool.DISCONNECT";
    public static final String EXTRA_SOCKS_PORT = "socks_port";
    public static final String EXTRA_DNS = "dns";

    private static final String CHANNEL_ID = "aether_vpn_channel";
    private static final int NOTIF_ID = 1;

    private ParcelFileDescriptor tunFd;
    private Process tun2socksProcess;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            stopTunnel();
            stopSelf();
            return START_NOT_STICKY;
        }
        int socksPort = intent != null ? intent.getIntExtra(EXTRA_SOCKS_PORT, 10820) : 10820;
        String dns = intent != null ? intent.getStringExtra(EXTRA_DNS) : null;
        if (dns == null) dns = "1.1.1.1";
        startTunnel(socksPort, dns);
        return START_STICKY;
    }

    private void startTunnel(int socksPort, String dns) {
        stopTunnel(); // clean any previous instance first
        try {
            Builder b = new Builder();
            b.setSession("Aether WARP");
            b.setMtu(1500);
            b.addAddress("10.0.85.1", 32);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer(dns);
            b.setBlocking(false);
            // Keep the app itself out of the tunnel to avoid loopback loops
            // (usque / this app talk to the real network directly).
            try {
                b.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {
            }
            tunFd = b.establish();
            if (tunFd == null) {
                Log.e(TAG, "VpnService.Builder.establish() returned null (permission not granted?)");
                return;
            }
            showForegroundNotification();
            launchTun2socks(tunFd, socksPort);
        } catch (Exception e) {
            Log.e(TAG, "startTunnel failed", e);
        }
    }

    private void launchTun2socks(ParcelFileDescriptor pfd, int socksPort) {
        try {
            String libDir = getApplicationInfo().nativeLibraryDir;
            File bin = new File(libDir, "libtun2socks.so");
            if (!bin.exists()) {
                Log.e(TAG, "libtun2socks.so not found in " + libDir);
                return;
            }
            int fd = pfd.getFd();
            // tun2socks (xjasonlyu/tun2socks-style CLI flags). If you bundle a
            // different tun2socks fork, adjust these arguments to match it.
            ProcessBuilder pb = new ProcessBuilder(
                    bin.getAbsolutePath(),
                    "-device", "fd://" + fd,
                    "-proxy", "socks5://127.0.0.1:" + socksPort,
                    "-loglevel", "warning"
            );
            pb.redirectErrorStream(true);
            pb.directory(getFilesDir());
            tun2socksProcess = pb.start();
            Log.i(TAG, "tun2socks started, pid=" + tun2socksProcess);
        } catch (Exception e) {
            Log.e(TAG, "launchTun2socks failed", e);
        }
    }

    private void stopTunnel() {
        if (tun2socksProcess != null) {
            try {
                tun2socksProcess.destroy();
            } catch (Exception ignored) {
            }
            tun2socksProcess = null;
        }
        if (tunFd != null) {
            try {
                tunFd.close();
            } catch (Exception ignored) {
            }
            tunFd = null;
        }
        stopForeground(true);
    }

    private void showForegroundNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "Aether WARP", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(getPackageName());
        PendingIntent pi = PendingIntent.getActivity(this, 0, launch,
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                        ? PendingIntent.FLAG_IMMUTABLE : 0);
        Notification n = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Aether WARP")
                .setContentText("Tunnel is active")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
        startForeground(NOTIF_ID, n);
    }

    @Override
    public void onRevoke() {
        stopTunnel();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }
}
