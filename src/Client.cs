using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Client
//
// Laeuft auf dem Rechner des Bedieners. Drei Betriebsarten:
//
//   -forward     ein oder mehrere lokale Ports, jeder auf einen Dienst eines
//                Geraets. Ein Prozess bedient beliebig viele Geraete und
//                Protokolle gleichzeitig; die Weiterleitungen wissen nichts
//                voneinander und teilen sich nur die Zertifikate.
//
//   -stdio       eine einzelne Sitzung ueber stdin/stdout, gedacht als
//                ProxyCommand von OpenSSH. Kein offener Port.
//
//   -list        zeigt, welche Geraete gerade erreichbar sind - gefiltert auf
//                das, was dieser Zugang laut ACL sehen darf.
//
// Jede eingehende Verbindung an einem lokalen Port bekommt ihre eigene
// TLS-Verbindung zum Relay. Es gibt keinen gemeinsamen Zustand zwischen zwei
// Sitzungen und keinen zwischen zwei Weiterleitungen.
// ---------------------------------------------------------------------------

internal sealed class TunnelClient(ClientConfig cfg, string cfgPath)
{
    X509Certificate2 _ca = null!, _me = null!;
    X509Certificate2[] _chainRest = [];

    void LoadCerts()
    {
        _ca = Tls.LoadCa(Cfg.Rel(cfgPath, cfg.Ca));
        _me = Tls.LoadIdentity(Cfg.Rel(cfgPath, cfg.Cert), Cfg.Rel(cfgPath, cfg.Key));
        _chainRest = Tls.LoadChainRest(Cfg.Rel(cfgPath, cfg.Cert));
        var cn = _me.GetNameInfo(X509NameType.SimpleName, false) ?? "";
        if (!Tls.SplitIdentity(cn, out var kind, out _) || kind != "client")
            throw new InvalidDataException($"Zertifikat-CN '{cn}' ist keine Bediener-Identitaet (erwartet 'client:<name>')");
    }

    /// <summary>Baut eine Sitzung zum Geraet auf; der zurueckgegebene Stream ist der Tunnel.</summary>
    async Task<SslStream> DialAsync(string device, string service, CancellationToken ct)
    {
        var (host, _) = Net.SplitHostPort(cfg.Relay);
        var sock = await Net.ConnectAsync(cfg.Relay, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        var tls = new SslStream(new NetworkStream(sock, ownsSocket: true), leaveInnerStreamOpen: false);
        try
        {
            using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
            hs.CancelAfter(TimeSpan.FromSeconds(30));
            await tls.AuthenticateAsClientAsync(Tls.ClientOptions(_ca, _me, _chainRest, host), hs.Token).ConfigureAwait(false);

            await Wire.WriteAsync(tls, new Hello
            {
                Role = service.Length == 0 ? Proto.RoleList : Proto.RoleClient,
                Device = device.Length == 0 ? null : device,
                Service = service.Length == 0 ? null : service,
            }, WireJson.Default.Hello, hs.Token).ConfigureAwait(false);

            var reply = await ReadReplyAsync(tls, hs.Token).ConfigureAwait(false);
            if (!reply.Ok) throw new ProtocolException(reply.Error ?? "abgelehnt");
            return tls;
        }
        catch { await tls.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>
    /// Bei TLS 1.3 merkt der Client erst beim ersten Lesen, dass sein Zertifikat
    /// abgelehnt wurde - der Handshake gilt vorher schon als gelungen. Aus dem
    /// nackten EOF wird hier eine Meldung, mit der man etwas anfangen kann.
    /// </summary>
    static async Task<Reply> ReadReplyAsync(SslStream tls, CancellationToken ct)
    {
        try { return await Wire.ReadAsync(tls, WireJson.Default.Reply, ct).ConfigureAwait(false); }
        catch (Exception e) when (e is EndOfStreamException or IOException)
        {
            throw new ProtocolException(
                "Relay hat die Verbindung ohne Antwort geschlossen - vermutlich wurde das " +
                "Zertifikat abgelehnt (fremde CA, abgelaufen oder in acl.json gesperrt)");
        }
    }

    public async Task<int> RunStdioAsync(string device, string service, CancellationToken ct)
    {
        LoadCerts();
        await using var tunnel = await DialAsync(device, service, ct).ConfigureAwait(false);
        await using var io = new StdioStream();
        await Pump.RunAsync(io, tunnel, ct).ConfigureAwait(false);
        return 0;
    }

    /// <summary>Zeigt die erreichbaren Geraete. Der Relay filtert die Liste bereits nach ACL.</summary>
    public async Task<int> RunListAsync(CancellationToken ct)
    {
        LoadCerts();
        await using var tls = await DialAsync("", "", ct).ConfigureAwait(false);
        var listing = await Wire.ReadAsync(tls, WireJson.Default.Listing, ct).ConfigureAwait(false);

        if (listing.Devices.Length == 0)
        {
            Console.WriteLine("keine erreichbaren Geraete");
            return 1;
        }
        var mitNotiz = listing.Devices.Any(d => !string.IsNullOrEmpty(d.Note));
        Console.WriteLine($"{"GERAET",-24} {"DIENSTE",-30} {"ONLINE",7} {"SITZ.",6}" + (mitNotiz ? "  NOTIZ" : ""));
        foreach (var d in listing.Devices)
            Console.WriteLine($"{d.Device,-24} {string.Join(",", d.Services),-30} {Dauer(d.OnlineSec),7} {d.Streams,6}"
                              + (mitNotiz ? "  " + d.Note : ""));
        return 0;
    }

    static string Dauer(long sek) => sek switch
    {
        < 60 => $"{sek}s",
        < 3600 => $"{sek / 60}m",
        < 86400 => $"{sek / 3600}h",
        _ => $"{sek / 86400}t",
    };

    /// <summary>
    /// Startet alle Weiterleitungen nebeneinander. Faellt eine aus - etwa weil
    /// ihr Port belegt ist -, laufen die anderen weiter; nur wenn keine einzige
    /// steht, endet das Programm mit Fehler.
    /// </summary>
    public async Task<int> RunForwardsAsync(IReadOnlyList<Forward> forwards, CancellationToken ct)
    {
        LoadCerts();

        var laufend = new List<Task>();
        foreach (var f in forwards)
        {
            Socket listener;
            try { listener = Bind(f); }
            catch (Exception e) when (e is SocketException or FormatException)
            {
                Log.Err("client", $"{f}: {e.Message}");
                continue;
            }
            laufend.Add(AcceptLoopAsync(listener, f, ct));
        }

        if (laufend.Count == 0) { Log.Err("client", "keine Weiterleitung konnte eingerichtet werden"); return 1; }
        await Task.WhenAll(laufend).ConfigureAwait(false);
        return 0;
    }

    Socket Bind(Forward f)
    {
        if (!Tls.IsSaneName(f.Device) || !Tls.IsSaneName(f.Service))
            throw new FormatException($"'{f}': Geraet oder Dienst fehlt");

        var ep = Net.ParseEndpoint(f.Listen);
        var listener = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Bind(ep);
            listener.Listen(128);
        }
        catch { listener.Dispose(); throw; }

        if (!System.Net.IPAddress.IsLoopback(ep.Address))
            Log.Warn("client", $"{ep} ist nicht loopback - dieser Port ist fuer andere im Netz offen");

        Log.Info("client", $"{ep} -> {f.Device}/{f.Service} ueber {cfg.Relay}");
        return listener;
    }

    async Task AcceptLoopAsync(Socket listener, Forward f, CancellationToken ct)
    {
        using (listener)
        {
            while (!ct.IsCancellationRequested)
            {
                Socket sock;
                try { sock = await listener.AcceptAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                catch (SocketException e) { Log.Warn("client", $"{f}: accept: {e.Message}"); continue; }
                _ = ForwardAsync(sock, f, ct);
            }
        }
    }

    async Task ForwardAsync(Socket sock, Forward f, CancellationToken ct)
    {
        Net.Tune(sock);
        var von = sock.RemoteEndPoint?.ToString() ?? "?";
        try
        {
            await using var local = new NetworkStream(sock, ownsSocket: true);
            await using var tunnel = await DialAsync(f.Device, f.Service, ct).ConfigureAwait(false);
            Log.Info("client", $"{f.Device}/{f.Service}: {von} verbunden");
            await Pump.RunAsync(local, tunnel, ct).ConfigureAwait(false);
            Log.Info("client", $"{f.Device}/{f.Service}: {von} getrennt");
        }
        catch (Exception e)
        {
            Log.Err("client", $"{f.Device}/{f.Service}: {von}: {e.Message}");
            sock.Dispose();
        }
    }
}
