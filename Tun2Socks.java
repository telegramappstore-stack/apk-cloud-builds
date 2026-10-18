package org.aminium.vpn;

/**
 * Loads libhev-socks5-tunnel.so. That library registers its native methods on a class name fixed at build time:
 * hev.htproxy.TProxyService (official build) or com.v2ray.ang.service.TProxyService (the copy inside v2rayNG).
 * Both stub classes are in this app, so either .so works; we simply try both.
 */
final class Tun2Socks {
    private static boolean loaded = false;
    private static int which = 0;

    static synchronized void start(String cfg, int fd) {
        if (!loaded) {
            System.loadLibrary("hev-socks5-tunnel");
            loaded = true;
        }
        try {
            hev.htproxy.TProxyService.TProxyStartService(cfg, fd);
            which = 1;
            return;
        } catch (UnsatisfiedLinkError ignored) { }
        com.v2ray.ang.service.TProxyService.TProxyStartService(cfg, fd);
        which = 2;
    }

    static synchronized void stop() {
        if (which == 1) hev.htproxy.TProxyService.TProxyStopService();
        else if (which == 2) com.v2ray.ang.service.TProxyService.TProxyStopService();
        which = 0;
    }
}
