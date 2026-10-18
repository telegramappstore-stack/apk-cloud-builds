package com.v2ray.ang.service;

/** Native binding target for the hev-socks5-tunnel copy taken from v2rayNG. Do not rename. */
public class TProxyService {
    public static native void TProxyStartService(String configPath, int fd);
    public static native void TProxyStopService();
    public static native long[] TProxyGetStats();
}
