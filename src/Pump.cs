using System.Buffers;
using System.Net.Security;
using System.Net.Sockets;

namespace Schleuse;

/// <summary>
/// Verbindet zwei Streams bidirektional.
///
/// Wichtig ist die Behandlung von EOF: erreicht eine Richtung ihr Ende, wird das
/// dem Ziel als Halb-Schliessung weitergereicht (TCP FIN bzw. TLS close_notify),
/// statt die ganze Verbindung abzuraeumen. Sonst wuerde z.B. eine HTTP-Antwort
/// abgeschnitten, wenn der Client seine Senderichtung frueh schliesst.
/// Erst wenn beide Richtungen fertig sind, faellt die Verbindung.
/// </summary>
internal static class Pump
{
    const int BufferSize = 64 * 1024;

    public static async Task RunAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = OneWayAsync(a, b, abort);
        var t2 = OneWayAsync(b, a, abort);
        await Task.WhenAll(t1, t2).ConfigureAwait(false);
    }

    static async Task OneWayAsync(Stream src, Stream dst, CancellationTokenSource abort)
    {
        var buf = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                int n = await src.ReadAsync(buf.AsMemory(0, BufferSize), abort.Token).ConfigureAwait(false);
                if (n == 0) break;
                await dst.WriteAsync(buf.AsMemory(0, n), abort.Token).ConfigureAwait(false);
            }
            await HalfCloseAsync(dst).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // Ein Fehler betrifft immer beide Richtungen; sauberes EOF nicht.
            if (e is not OperationCanceledException) Log.Dbg("pump", "Abbruch: " + e.Message);
            await abort.CancelAsync().ConfigureAwait(false);
        }
        finally
        {
            // Geleert zurueckgeben: der Puffer wandert an die naechste Sitzung -
            // moeglicherweise die eines anderen Bedieners oder Geraets - und soll
            // deren Daten nicht mit Resten der eigenen antreten.
            ArrayPool<byte>.Shared.Return(buf, clearArray: true);
        }
    }

    /// <summary>Senderichtung schliessen, Empfangsrichtung offen lassen.</summary>
    static async ValueTask HalfCloseAsync(Stream s)
    {
        try
        {
            switch (s)
            {
                case SslStream ssl:
                    await ssl.ShutdownAsync().ConfigureAwait(false);
                    break;
                case NetworkStream ns:
                    ns.Socket.Shutdown(SocketShutdown.Send);
                    break;
                case StdioStream io:
                    io.CloseWrite();
                    break;
                default:
                    await s.FlushAsync().ConfigureAwait(false);
                    break;
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or SocketException
                                    or NotSupportedException or InvalidOperationException)
        {
            // Gegenstelle war schneller - kein Problem.
        }
    }
}

/// <summary>stdin/stdout als ein Stream, fuer den ProxyCommand-Modus des Clients.</summary>
internal sealed class StdioStream : Stream
{
    readonly Stream _in = Console.OpenStandardInput();
    readonly Stream _out = Console.OpenStandardOutput();

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override ValueTask<int> ReadAsync(Memory<byte> b, CancellationToken ct) => _in.ReadAsync(b, ct);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> b, CancellationToken ct) => _out.WriteAsync(b, ct);
    public override Task FlushAsync(CancellationToken ct) => _out.FlushAsync(ct);
    public override void Flush() => _out.Flush();
    public void CloseWrite() { _out.Flush(); _out.Dispose(); }

    public override int Read(byte[] b, int o, int c) => _in.Read(b, o, c);
    public override void Write(byte[] b, int o, int c) => _out.Write(b, o, c);
    public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
    public override void SetLength(long v) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) { try { _out.Dispose(); } catch (IOException) { } try { _in.Dispose(); } catch (IOException) { } }
        base.Dispose(disposing);
    }
}
