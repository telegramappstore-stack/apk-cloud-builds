package org.aminium.vpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import hev.htproxy.TProxyService;
import java.io.File;
import java.io.FileWriter;

/** Real Android VPN (key icon). TUN -> hev-socks5-tunnel -> local SOCKS5 relay -> usque -> WARP. */
public class AminiumVpnService extends VpnService {
    public static volatile boolean running = false;
    private ParcelFileDescriptor tun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) { stopSelf(); return START_NOT_STICKY; }
        stopVpn();
        try {
            int port = intent.getIntExtra("port", 10820);
            String user = intent.getStringExtra("user"), pw = intent.getStringExtra("pw");
            Builder b = new Builder().setSession("AMINIUM").setMtu(1500)
                    .addAddress("198.18.0.1", 32).addRoute("0.0.0.0", 0)
                    .addDnsServer("198.18.0.2");           // answered locally by hev "mapdns"
            b.addDisallowedApplication(getPackageName());   // usque runs in our UID -> no routing loop
            tun = b.establish();
            if (tun == null) { stopSelf(); return START_NOT_STICKY; }
            StringBuilder y = new StringBuilder();
            y.append("tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n");
            y.append("socks5:\n  port: ").append(port).append("\n  address: 127.0.0.1\n  udp: 'tcp'\n");
            if (user != null && !user.isEmpty())
                y.append("  username: '").append(user).append("'\n  password: '").append(pw).append("'\n");
            y.append("mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n");
            y.append("  netmask: 255.192.0.0\n  cache-size: 10000\n");
            File f = new File(getFilesDir(), "hev.yml");
            FileWriter w = new FileWriter(f); w.write(y.toString()); w.close();
            TProxyService.TProxyStartService(f.getAbsolutePath(), tun.getFd());
            running = true;
        } catch (Throwable e) {
            stopVpn(); stopSelf();
        }
        return START_NOT_STICKY;
    }

    private void stopVpn() {
        if (running) { try { TProxyService.TProxyStopService(); } catch (Throwable t) { } }
        running = false;
        try { if (tun != null) tun.close(); } catch (Exception e) { }
        tun = null;
    }

    @Override public void onRevoke() { stopVpn(); stopSelf(); }
    @Override public void onDestroy() { stopVpn(); super.onDestroy(); }
}
