using System.Net;
using System.Net.Sockets;

namespace Schleuse;

internal static class Net
{
    /// <summary>Zerlegt "host:port", "0.0.0.0:443", ":443" oder "[::1]:443".</summary>
    public static (string Host, int Port) SplitHostPort(string s)
    {
        var i = s.LastIndexOf(':');
        if (i < 0) throw new FormatException($"'{s}': erwartet host:port");
        var host = s[..i];
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        if (host.Length == 0) host = "0.0.0.0";
        if (!int.TryParse(s[(i + 1)..], out var port) || port is < 1 or > 65535)
            throw new FormatException($"'{s}': ungueltiger Port");
        return (host, port);
    }

    public static IPEndPoint ParseEndpoint(string s)
    {
        var (host, port) = SplitHostPort(s);
        if (!IPAddress.TryParse(host, out var ip))
        {
            var addrs = Dns.GetHostAddresses(host);
            if (addrs.Length == 0) throw new FormatException($"'{host}' nicht aufloesbar");
            ip = addrs[0];
        }
        return new IPEndPoint(ip, port);
    }

    public static async Task<Socket> ConnectAsync(string hostPort, TimeSpan timeout, CancellationToken ct)
    {
        var (host, port) = SplitHostPort(hostPort);
        var sock = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await sock.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            Tune(sock);
            return sock;
        }
        catch { sock.Dispose(); throw; }
    }

    /// <summary>
    /// Nagle aus (interaktive Protokolle wie SSH leiden sonst spuerbar) und
    /// TCP-Keepalive an, damit tote Verbindungen hinter NAT auffallen.
    /// </summary>
    public static void Tune(Socket s)
    {
        try
        {
            s.NoDelay = true;
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 60);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 15);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 4);
        }
        catch (SocketException) { }
        catch (PlatformNotSupportedException) { }
    }
}
