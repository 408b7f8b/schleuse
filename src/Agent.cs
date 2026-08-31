using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Agent
//
// Laeuft als Dienst auf dem Geraet. Oeffnet keinen einzigen Port: er baut nur
// eine ausgehende TLS-Verbindung zum Relay auf und haelt sie offen. Faellt sie
// weg, verbindet er sich mit wachsender Wartezeit neu.
//
// Die Sicherheitsgrenze ist die Dienstetabelle in der Konfiguration. Das Relay
// nennt in einer open-Nachricht nur einen Dienstnamen; welches lokale Ziel
// dahinter steht, entscheidet allein das Geraet. Ein uebernommenes Relay kann
// damit nicht auf beliebige Adressen im Anlagennetz zugreifen.
// ---------------------------------------------------------------------------

internal sealed class Agent(AgentConfig cfg, string cfgPath)
{
    X509Certificate2 _ca = null!, _me = null!;
    X509Certificate2[] _chainRest = [];
    SemaphoreSlim _slots = null!;
    string _device = "";

    public async Task<int> RunAsync(CancellationToken ct)
    {
        _ca = Tls.LoadCa(Cfg.Rel(cfgPath, cfg.Ca));
        _me = Tls.LoadIdentity(Cfg.Rel(cfgPath, cfg.Cert), Cfg.Rel(cfgPath, cfg.Key));
        _chainRest = Tls.LoadChainRest(Cfg.Rel(cfgPath, cfg.Cert));
        _slots = new SemaphoreSlim(cfg.MaxStreams);

        var cn = _me.GetNameInfo(X509NameType.SimpleName, false) ?? "";
        if (!Tls.SplitIdentity(cn, out var kind, out _device) || kind != "device")
            throw new InvalidDataException($"Zertifikat-CN '{cn}' ist keine Geraete-Identitaet (erwartet 'device:<id>')");

        foreach (var (name, target) in cfg.Services)
        {
            if (!Tls.IsSaneName(name)) throw new InvalidDataException($"unbrauchbarer Dienstname '{name}'");
            Net.SplitHostPort(target); // fruehe Pruefung, damit Tippfehler beim Start auffallen
        }
        if (cfg.Services.Count == 0) throw new InvalidDataException("keine Dienste konfiguriert");

        Log.Info("agent", $"Geraet={_device} Relay={cfg.Relay} Dienste=[{string.Join(",", cfg.Services.Keys)}]");

        var delay = cfg.ReconnectMinSec;
        while (!ct.IsCancellationRequested)
        {
            var t0 = Environment.TickCount64;
            try
            {
                await SessionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                Log.Warn("agent", "Verbindung: " + e.Message);
            }

            // Lief die Sitzung eine Weile, war der Relay erreichbar - dann von
            // vorn zaehlen. Sonst weiter zuruecklehnen.
            if (Environment.TickCount64 - t0 > 60_000) delay = cfg.ReconnectMinSec;
            else delay = Math.Min(cfg.ReconnectMaxSec, Math.Max(cfg.ReconnectMinSec, delay * 2));

            var jitter = RandomNumberGenerator.GetInt32(0, 1000);
            Log.Info("agent", $"neuer Versuch in {delay}s");
            try { await Task.Delay(TimeSpan.FromSeconds(delay) + TimeSpan.FromMilliseconds(jitter), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        return 0;
    }

    async Task<SslStream> DialRelayAsync(CancellationToken ct)
    {
        var (host, _) = Net.SplitHostPort(cfg.Relay);
        var sock = await Net.ConnectAsync(cfg.Relay, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        var tls = new SslStream(new NetworkStream(sock, ownsSocket: true), leaveInnerStreamOpen: false);
        try
        {
            using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
            hs.CancelAfter(TimeSpan.FromSeconds(15));
            await tls.AuthenticateAsClientAsync(Tls.ClientOptions(_ca, _me, _chainRest, host), hs.Token).ConfigureAwait(false);
            return tls;
        }
        catch { await tls.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>Eine Anmeldung samt Control-Schleife; kehrt zurueck, wenn die Verbindung endet.</summary>
    async Task SessionAsync(CancellationToken ct)
    {
        await using var tls = await DialRelayAsync(ct).ConfigureAwait(false);

        await Wire.WriteAsync(tls, new Hello
        {
            Role = Proto.RoleAgent,
            Services = [.. cfg.Services.Keys],
        }, WireJson.Default.Hello, ct).ConfigureAwait(false);

        Reply reply;
        try { reply = await Wire.ReadAsync(tls, WireJson.Default.Reply, ct).ConfigureAwait(false); }
        catch (Exception e) when (e is EndOfStreamException or IOException)
        {
            // TLS 1.3 meldet ein abgelehntes Client-Zertifikat erst beim ersten Lesen.
            throw new ProtocolException("Relay hat die Verbindung ohne Antwort geschlossen - " +
                "vermutlich wurde das Geraetezertifikat abgelehnt (fremde CA, abgelaufen oder gesperrt)");
        }
        if (!reply.Ok) throw new ProtocolException("Relay lehnt Anmeldung ab: " + (reply.Error ?? "?"));
        Log.Info("agent", "angemeldet");

        var write = new SemaphoreSlim(1, 1);
        while (!ct.IsCancellationRequested)
        {
            using var read = CancellationTokenSource.CreateLinkedTokenSource(ct);
            read.CancelAfter(TimeSpan.FromSeconds(cfg.ControlTimeoutSec));
            var msg = await Wire.ReadAsync(tls, WireJson.Default.Ctl, read.Token).ConfigureAwait(false);

            switch (msg.Type)
            {
                case Proto.CtlPing:
                    await write.WaitAsync(ct).ConfigureAwait(false);
                    try { await Wire.WriteAsync(tls, new Ctl { Type = Proto.CtlPong }, WireJson.Default.Ctl, ct).ConfigureAwait(false); }
                    finally { write.Release(); }
                    break;

                case Proto.CtlOpen when msg.Stream is { Length: > 0 } && msg.Service is not null:
                    _ = OpenStreamAsync(msg.Stream, msg.Service, ct);
                    break;

                default:
                    Log.Warn("agent", $"unbekannte Control-Nachricht '{msg.Type}'");
                    break;
            }
        }
    }

    /// <summary>Baut auf Anforderung eine Datenverbindung zum Relay auf und haengt den lokalen Dienst daran.</summary>
    async Task OpenStreamAsync(string id, string service, CancellationToken ct)
    {
        if (!cfg.Services.TryGetValue(service, out var target))
        {
            Log.Warn("agent", $"Dienst '{service}' nicht freigegeben - Anforderung verworfen");
            return;
        }
        if (!await _slots.WaitAsync(TimeSpan.Zero, ct).ConfigureAwait(false))
        {
            Log.Warn("agent", $"Grenze von {cfg.MaxStreams} Sitzungen erreicht - '{service}' abgewiesen");
            return;
        }

        SslStream? up = null;
        Socket? down = null;
        try
        {
            // Zuerst der lokale Dienst: schlaegt er fehl, laesst sich der Grund
            // ueber dieselbe Datenverbindung bis zum Bediener melden.
            try
            {
                down = await Net.ConnectAsync(target, TimeSpan.FromSeconds(cfg.DialTimeoutSec), ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException or FormatException)
            {
                var why = e is OperationCanceledException ? $"'{service}' antwortet nicht" : $"'{service}' nicht erreichbar ({e.Message})";
                Log.Warn("agent", $"{service} -> {target}: {why}");
                await ReportFailureAsync(id, why, ct).ConfigureAwait(false);
                return;
            }

            up = await DialRelayAsync(ct).ConfigureAwait(false);
            await Wire.WriteAsync(up, new Hello { Role = Proto.RoleAgentData, Stream = id }, WireJson.Default.Hello, ct).ConfigureAwait(false);
            var reply = await Wire.ReadAsync(up, WireJson.Default.Reply, ct).ConfigureAwait(false);
            if (!reply.Ok) throw new ProtocolException("Relay: " + (reply.Error ?? "?"));
            Log.Info("agent", $"{service} -> {target}: offen");

            await using var local = new NetworkStream(down, ownsSocket: true);
            down = null;
            await Pump.RunAsync(up, local, ct).ConfigureAwait(false);
            Log.Info("agent", $"{service} -> {target}: zu");
        }
        catch (Exception e)
        {
            Log.Warn("agent", $"{service} -> {target}: {e.Message}");
        }
        finally
        {
            down?.Dispose();
            if (up is not null) { try { await up.DisposeAsync().ConfigureAwait(false); } catch (IOException) { } }
            _slots.Release();
        }
    }

    /// <summary>Meldet dem Relay, dass der angeforderte Stream nicht zustande kommt.</summary>
    async Task ReportFailureAsync(string id, string reason, CancellationToken ct)
    {
        try
        {
            await using var up = await DialRelayAsync(ct).ConfigureAwait(false);
            await Wire.WriteAsync(up, new Hello
            {
                Role = Proto.RoleAgentData,
                Stream = id,
                Error = reason,
            }, WireJson.Default.Hello, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or AuthenticationException)
        {
            Log.Dbg("agent", "Fehlermeldung konnte nicht zugestellt werden: " + e.Message);
        }
    }
}
