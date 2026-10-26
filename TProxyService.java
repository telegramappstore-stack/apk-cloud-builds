package hev.htproxy;

/** JNI bridge to libhev-socks5-tunnel.so (class name must stay hev.htproxy.TProxyService). */
public class TProxyService {
    static { System.loadLibrary("hev-socks5-tunnel"); }
    public static native void TProxyStartService(String configPath, int fd);
    public static native void TProxyStopService();
}
