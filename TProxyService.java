package hev.htproxy;

/** Native binding target for the official hev-socks5-tunnel build. Do not rename. */
public class TProxyService {
    public static native void TProxyStartService(String configPath, int fd);
    public static native void TProxyStopService();
    public static native long[] TProxyGetStats();
}
