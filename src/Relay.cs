using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Relay
//
// Der Relay ist der einzige Teil mit einem offenen Port im Internet. Er haelt
// keine Konfiguration ueber Geraete vor und kann von sich aus nichts anstossen:
// er vermittelt nur zwischen einem angemeldeten Agent und einem berechtigten
// Bediener. Alles laeuft ueber genau einen Port.
//
//   Agent  --TLS--> Relay <--TLS--  Client
//     |                                |
//     '-- Control-Kanal (dauerhaft)    '-- eine Verbindung je Nutzsitzung
//     '-- Datenverbindung je Sitzung, vom Agent nach aussen aufgebaut
//
// Der Relay sieht nur den Ciphertext des durchgereichten Protokolls (SSH ist
// Ende-zu-Ende verschluesselt, HTTPS ebenso). Klartext saehe er nur bei
// ungesichertem HTTP - dann schuetzt ihn immerhin noch der TLS-Mantel.
// ---------------------------------------------------------------------------

internal sealed class Relay(RelayConfig cfg, string cfgPath)
{
    readonly ConcurrentDictionary<string, AgentSession> _devices = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<long, LiveTunnel> _tunnels = new();
    readonly SemaphoreSlim _handshakes = new(Math.Max(1, cfg.MaxConcurrentHandshakes));
    readonly Lock _aclGate = new();
    long _tunnelSeq;
    X509Certificate2 _ca = null!, _me = null!;
    X509Certificate2[] _extra = [];
    DeviceIssuer? _issuer;
    PendingStore? _pending;
    string _rootThumbprint = "";

    public DeviceIssuer? Issuer => _issuer;

    /// <summary>Was gerade angemeldet ist - fuer die Uebersicht der Weboberflaeche.</summary>
    public IReadOnlyList<DeviceInfo> Online()
    {
        var acl = _acl;
        return [.. _devices.Select(kv => new DeviceInfo
        {
            Device = kv.Key,
            Services = [.. kv.Value.Services.OrderBy(x => x, StringComparer.Ordinal)],
            OnlineSec = kv.Value.OnlineSeconds,
            Streams = kv.Value.ActiveStreams,
            Note = acl.NoteFor(kv.Key),
        }).OrderBy(d => d.Device, StringComparer.Ordinal)];
    }

    public IReadOnlyList<LiveTunnel> Tunnels() => [.. _tunnels.Values];

    /// <summary>
    /// Aendert die Zugriffsliste unter einem Schloss: Kopie ziehen, aendern,
    /// speichern, uebernehmen, durchsetzen.
    ///
    /// Lesen-Aendern-Schreiben muss zusammenhaengen. Sonst koennten zwei
    /// gleichzeitige Aufrufe - einer aus der Oberflaeche, einer ueber die
    /// Schnittstelle - jeweils von derselben Fassung ausgehen und die Aenderung
    /// des anderen ueberschreiben. Ausgerechnet eine verlorene Sperre waere so
    /// ein Fall.
    ///
    /// Die Reihenfolge innen ist ebenfalls Absicht: erst auf die Platte, dann in
    /// den Betrieb. Ein Absturz mittendrin verliert damit keinen Entzug.
    /// </summary>
    public void UpdateAcl(Action<Acl> aendern)
    {
        lock (_aclGate)
        {
            var kopie = AclCopy();
            aendern(kopie);
            Store.Save(Cfg.Rel(cfgPath, cfg.Acl), kopie, JsonCfg.Default.Acl);
            _acl = kopie;
            EnforceAcl(kopie);
        }
    }

    /// <summary>Arbeitskopie der Zugriffsliste, zum Lesen und Anzeigen.</summary>
    public Acl AclCopy()
    {
        var text = System.Text.Json.JsonSerializer.Serialize(_acl, JsonCfg.Default.Acl);
        return System.Text.Json.JsonSerializer.Deserialize(text, JsonCfg.Default.Acl) ?? new Acl();
    }
    public PendingStore? Pending => _pending;
    public Acl CurrentAcl => _acl;
    public X509Certificate2 RootCa => _ca;
    public X509Certificate2 OwnCertificate => _me;
    public string ListenAddress => cfg.Listen;
    public bool AllowUnlistedDevices => cfg.AllowUnlistedDevices;
    volatile Acl _acl = new();

    bool _bereit;

    /// <summary>
    /// Laedt Zertifikate und Zugriffsliste. Getrennt vom Lauschen, damit die
    /// Weboberflaeche schon vor dem ersten Verbindungsversuch auf einen
    /// vollstaendig eingerichteten Relay zugreifen kann.
    /// </summary>
    public void Initialize()
    {
        if (_bereit) return;
        _bereit = true;
        _ca = Tls.LoadCa(Cfg.Rel(cfgPath, cfg.Ca));
        _rootThumbprint = _ca.Thumbprint;
        _me = Tls.LoadIdentity(Cfg.Rel(cfgPath, cfg.Cert), Cfg.Rel(cfgPath, cfg.Key));

        if (cfg.Enrollment is { } en)
        {
            var zwischen = Tls.LoadIdentity(Cfg.Rel(cfgPath, en.Ca), Cfg.Rel(cfgPath, en.Key));
            _issuer = new DeviceIssuer(zwischen, en.CertDays);
            _extra = [zwischen];
            _pending = new PendingStore(Cfg.Rel(cfgPath, en.Queue),
                                        en.MaxPending, TimeSpan.FromHours(en.PendingHours));
            Log.Info("relay", $"Selbstanmeldung aktiv, Zwischen-CA {zwischen.Subject}");
            Log.Info("relay", $"CA-Fingerabdruck fuer 'schleuse enroll': {Fingerprint.OfCertificate(_ca)}");
        }
        else
        {
            Log.Info("relay", "Selbstanmeldung nicht eingerichtet - der Relay stellt keine Zertifikate aus");
        }

        ReloadAcl();
    }

    public async Task<int> RunAsync(CancellationToken ct)
    {
        Initialize();

        using var hup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, c => { c.Cancel = true; ReloadAcl(); });

        var ep = Net.ParseEndpoint(cfg.Listen);
        using var listener = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Bind(ep);
        listener.Listen(512);
        Log.Info("relay", $"lauscht auf {ep}, CA={_ca.Subject}");

        while (!ct.IsCancellationRequested)
        {
            Socket sock;
            try { sock = await listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (SocketException e) { Log.Warn("relay", "accept: " + e.Message); continue; }

            _ = HandleAsync(sock, ct);
        }
        return 0;
    }

    static SslServerAuthenticationOptions Setze(Tls.PeerName peer, SslServerAuthenticationOptions o)
    {
        peer.Enrollment = true;
        return o;
    }

    // -- Selbstanmeldung -----------------------------------------------------

    /// <summary>
    /// Nimmt Antraege entgegen und beantwortet Nachfragen. Ohne gueltiges
    /// Client-Zertifikat - deshalb passiert hier ausser dem Eintrag in die
    /// Warteschlange nichts, und der Eintrag allein berechtigt zu nichts.
    /// </summary>
    async Task ServeEnrollAsync(SslStream tls, string remote, CancellationToken ct)
    {
        var store = _pending!;
        var issuer = _issuer!;

        // Hoechstens ein paar Anfragen je Verbindung: die Vorstellung der CA und
        // danach der eigentliche Antrag beziehungsweise die Nachfrage.
        for (int i = 0; i < 3; i++)
        {
            EnrollReply antwort;
            try
            {
                var req = await Wire.ReadAsync(tls, WireJson.Default.EnrollRequest, ct).ConfigureAwait(false);
                if (req.Version != Proto.Version) throw new ProtocolException("Protokollversion nicht unterstuetzt");

                antwort = req.Action switch
                {
                    Proto.EnrollCa => new EnrollReply { Ok = true, Ca = Pem.Certificate(_ca) },
                    Proto.EnrollSubmit => Aufnehmen(store, req, remote),
                    Proto.EnrollPoll => Nachfragen(store, issuer, req),
                    _ => throw new ProtocolException($"unbekannte Anfrage '{Log.Safe(req.Action)}'"),
                };
            }
            catch (EndOfStreamException) { return; }
            catch (Exception e) when (e is ProtocolException or IOException)
            {
                Log.Warn("relay", $"Selbstanmeldung von {remote}: {e.Message}");
                antwort = new EnrollReply { Ok = false, Error = e.Message };
            }

            try { await Wire.WriteAsync(tls, antwort, WireJson.Default.EnrollReply, ct).ConfigureAwait(false); }
            catch (Exception e) when (e is IOException or ObjectDisposedException) { return; }
            if (!antwort.Ok) return;
        }
    }

    EnrollReply Aufnehmen(PendingStore store, EnrollRequest req, string remote)
    {
        if (req.Csr is not { Length: > 0 } csr) throw new ProtocolException("Zertifikatsantrag fehlt");
        if (csr.Length > 8192) throw new ProtocolException("Zertifikatsantrag zu gross");

        var antrag = DeviceIssuer.PruefeAntrag(csr);
        var fp = Fingerprint.OfPublicKey(antrag.PublicKey);

        var vorschlag = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, ziel) in req.Services ?? [])
        {
            if (vorschlag.Count >= 32) break;
            if (!Tls.IsSaneName(name) || ziel.Length > 128) continue;
            vorschlag[name] = ziel;
        }

        var (eintrag, claim) = store.Aufnehmen(csr, fp, Kuerze(req.Hostname), vorschlag, remote);

        if (claim is not null)
            Log.Warn("relay", $"neue Selbstanmeldung wartet auf Freigabe: {eintrag.Id} " +
                              $"Fingerabdruck={fp} von {remote} Name='{Log.Safe(eintrag.Hostname ?? "")}'");

        return new EnrollReply
        {
            Ok = true,
            Status = Proto.StatePending,
            Id = eintrag.Id,
            Claim = claim,
            Fingerprint = fp,
        };
    }

    EnrollReply Nachfragen(PendingStore store, DeviceIssuer issuer, EnrollRequest req)
    {
        if (req.Id is not { Length: > 0 } id || req.Claim is not { Length: > 0 } claim)
            throw new ProtocolException("Kennung oder Abholgeheimnis fehlt");

        var e = store.Nachfragen(id, claim)
                ?? throw new ProtocolException("Antrag unbekannt oder Abholgeheimnis falsch");

        return e.State switch
        {
            PendingState.Approved => new EnrollReply
            {
                Ok = true,
                Status = Proto.StateApproved,
                Device = e.Device,
                Cert = e.Cert,
                Chain = Pem.Certificate(issuer.Ca),
                Ca = Pem.Certificate(_ca),
                Services = e.Services,
            },
            PendingState.Rejected => new EnrollReply { Ok = true, Status = Proto.StateRejected },
            _ => new EnrollReply { Ok = true, Status = Proto.StatePending, Fingerprint = e.Fingerprint },
        };
    }

    static string? Kuerze(string? s) => s is null ? null : Log.Safe(s.Length > 64 ? s[..64] : s);

    void ReloadAcl()
    {
        var path = Cfg.Rel(cfgPath, cfg.Acl);
        lock (_aclGate)
        try
        {
            if (!File.Exists(path))
            {
                // Erster Start: leere Liste anlegen, damit die Weboberflaeche
                // etwas zum Bearbeiten hat. Leer heisst: noch kein Geraet darf sich
                // anmelden - das ist die richtige Voreinstellung.
                Store.Save(path, new Acl { Devices = new Dictionary<string, AclDevice>(StringComparer.Ordinal) },
                           JsonCfg.Default.Acl);
                Log.Info("relay", $"{path} angelegt - noch keine Geraete und keine Bediener eingetragen");
            }

            var neu = Cfg.Load(path, JsonCfg.Default.Acl);
            _acl = neu;
            if (neu.DeviceListActive)
                Log.Info("relay", $"ACL geladen: {neu.Devices!.Count} zugelassene Geraete, " +
                                  $"{neu.Clients.Count} Bediener, {neu.Revoked.Length} gesperrt");
            else if (cfg.AllowUnlistedDevices)
                Log.Warn("relay", "ACL geladen: keine Geraeteliste und allow_unlisted_devices ist gesetzt - " +
                                  "jedes Zertifikat dieser CA darf sich als Geraet anmelden " +
                                  $"({neu.Clients.Count} Bediener, {neu.Revoked.Length} gesperrt)");
            else
                Log.Info("relay", "ACL geladen: die Geraeteliste ist leer, es kann sich noch kein Geraet " +
                                  $"anmelden ({neu.Clients.Count} Bediener, {neu.Revoked.Length} gesperrt)");
            EnforceAcl(neu);
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException)
        {
            Log.Err("relay", $"ACL {path} nicht ladbar ({e.Message}) - bisherige Regeln bleiben aktiv");
        }
    }

    /// <summary>
    /// Wendet eine frisch geladene ACL auf bereits laufende Sitzungen an.
    /// Ohne das wuerde eine Sperre erst beim naechsten Verbindungsaufbau
    /// greifen - eine offene SSH-Sitzung liefe weiter, obwohl der Zugang
    /// gerade entzogen wurde.
    /// </summary>
    void EnforceAcl(Acl acl)
    {
        foreach (var t in _tunnels.Values)
        {
            if (!acl.IsRevoked("client:" + t.Client) && acl.Allows(t.Client, t.Device, t.Service)) continue;
            Log.Warn("relay", $"client:{t.Client} -> {t.Device}/{t.Service}: laufende Sitzung durch ACL beendet");
            // Die Sitzung kann in genau diesem Augenblick von selbst enden.
            // Dann ist ihr Abbruchgeber schon fort - kein Grund, deswegen die
            // uebrigen Entzuege ausfallen zu lassen.
            try { t.Cts.Cancel(); } catch (ObjectDisposedException) { }
        }

        foreach (var (device, session) in _devices)
        {
            if (acl.IsRevoked("device:" + device))
                Log.Warn("relay", $"{device}: gesperrt, Anmeldung wird beendet");
            else if (!acl.DeviceKnown(device, cfg.AllowUnlistedDevices))
                Log.Warn("relay", $"{device}: nicht mehr in der Geraeteliste, Anmeldung wird beendet");
            else continue;
            session.Dispose();
        }
    }

    async Task HandleAsync(Socket sock, CancellationToken ct)
    {
        var remote = sock.RemoteEndPoint?.ToString() ?? "?";
        var cn = "?";
        SslStream? tls = null;
        bool handedOver = false;
        try
        {
            if (!await _handshakes.WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false))
            {
                Log.Warn("relay", $"{remote}: ueberlastet, abgewiesen");
                sock.Dispose();
                return;
            }
            var throttled = true;
            try
            {
                Net.Tune(sock);
                var peer = new Tls.PeerName();
                tls = new SslStream(new NetworkStream(sock, ownsSocket: true), leaveInnerStreamOpen: false);

                using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
                hs.CancelAfter(TimeSpan.FromSeconds(cfg.HandshakeTimeoutSec));

                // Die Weiche muss vor den Handshake: ob ein Client-Zertifikat
                // verlangt wird, entscheidet sich dort. Ein Geraet in der
                // Erstanmeldung hat noch keines und spricht darum unter einem
                // eigenen Servernamen an - die Tunnelrollen behalten ihre Pflicht.
                await tls.AuthenticateAsServerAsync(
                    (_, hallo, _, _) => ValueTask.FromResult(
                        hallo.ServerName == Proto.EnrollSni && _issuer is not null
                            ? Setze(peer, Tls.EnrollServerOptions(_me, _ca))
                            : Tls.ServerOptions(_ca, _extra, _me, peer)),
                    state: null, hs.Token).ConfigureAwait(false);

                if (peer.Enrollment)
                {
                    await ServeEnrollAsync(tls, remote, hs.Token).ConfigureAwait(false);
                    return;
                }

                cn = peer.Cn;
                if (_acl.IsRevoked(cn)) throw new ProtocolException($"Identitaet gesperrt: {Log.Safe(cn)}");
                if (!Tls.SplitIdentity(cn, out var kind, out var name))
                    throw new ProtocolException($"unbrauchbarer CN: '{Log.Safe(cn)}'");

                // Ein gueltiges Zertifikat sagt nur, dass die CA es ausgestellt
                // hat - nicht, dass dieses Geraet hier erwuenscht ist. Steht eine
                // Geraeteliste in der ACL, entscheidet sie.
                // Die Zwischen-CA darf ausschliesslich Geraete beglaubigen. Wer
                // ihren Schluessel erbeutet, kann damit keinen Bediener-Zugang
                // erzeugen - hier wird das durchgesetzt, nicht nur versprochen.
                if (kind == "client" && !string.Equals(peer.IssuerThumbprint, _rootThumbprint, StringComparison.OrdinalIgnoreCase))
                    throw new ProtocolException("Bediener-Zertifikate muessen unmittelbar von der Wurzel-CA stammen");

                if (kind == "device" && !_acl.DeviceKnown(name, cfg.AllowUnlistedDevices))
                    throw new ProtocolException($"Geraet '{name}' steht nicht in der Geraeteliste");

                var hello = await Wire.ReadAsync(tls, WireJson.Default.Hello, hs.Token).ConfigureAwait(false);
                if (hello.Version != Proto.Version)
                    throw new ProtocolException($"Protokollversion {hello.Version} nicht unterstuetzt");

                // Ab hier ist die Gegenstelle beglaubigt und die Verbindung wird
                // lange leben. Die Drossel begrenzt nur den rechenintensiven
                // Handshake - wuerde sie bis zum Sitzungsende gehalten, koennten
                // schon 256 angemeldete Geraete den Relay verstopfen.
                _handshakes.Release();
                throttled = false;

                switch (hello.Role)
                {
                    case Proto.RoleAgent when kind == "device":
                        await ServeAgentAsync(name, tls, hello, ct).ConfigureAwait(false);
                        break;

                    case Proto.RoleAgentData when kind == "device":
                        handedOver = await ServeAgentDataAsync(name, tls, hello, hs.Token).ConfigureAwait(false);
                        break;

                    case Proto.RoleClient when kind == "client":
                        await ServeClientAsync(name, tls, hello, ct).ConfigureAwait(false);
                        break;

                    case Proto.RoleList when kind == "client":
                        await ServeListAsync(name, tls, hs.Token).ConfigureAwait(false);
                        break;

                    default:
                        throw new ProtocolException($"Rolle '{Log.Safe(hello.Role)}' passt nicht zur Identitaet '{Log.Safe(cn)}'");
                }
            }
            finally { if (throttled) _handshakes.Release(); }
        }
        catch (Exception e)
        {
            // Abgewiesene Anfragen eines beglaubigten Gegenuebers sind
            // sicherheitsrelevant und gehoeren immer ins Protokoll. Gescheiterte
            // TLS-Handshakes dagegen kann jeder Portscanner ausloesen - die
            // bleiben im Debug-Log, damit es nicht ueberlaeuft.
            if (e is ProtocolException) Log.Warn("relay", $"{Log.Safe(cn)} von {remote}: abgewiesen - {e.Message}");
            else Log.Dbg("relay", $"{remote}: {(e is AuthenticationException ? "TLS abgelehnt: " : "")}{e.Message}");
            if (e is ProtocolException && tls is not null)
                try { await Wire.WriteAsync(tls, Reply.Bad(e.Message), WireJson.Default.Reply, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception w) when (w is IOException or ObjectDisposedException) { }
        }
        finally
        {
            if (!handedOver) { try { tls?.Dispose(); } catch (IOException) { } sock.Dispose(); }
        }
    }

    // -- Agent: Control-Kanal ------------------------------------------------

    async Task ServeAgentAsync(string device, SslStream tls, Hello hello, CancellationToken ct)
    {
        var services = new HashSet<string>(hello.Services ?? [], StringComparer.Ordinal);
        services.RemoveWhere(s => !Tls.IsSaneName(s));
        if (services.Count == 0) throw new ProtocolException("keine Dienste angeboten");

        var session = new AgentSession(device, tls, services, cfg);

        // Ein Geraet startet neu und meldet sich erneut an, waehrend die alte
        // Verbindung noch als lebend gilt - die alte wird verdraengt.
        if (_devices.TryRemove(device, out var old))
        {
            Log.Info("relay", $"{device}: alte Anmeldung verdraengt");
            old.Dispose();
        }
        _devices[device] = session;

        await Wire.WriteAsync(tls, Reply.Good(), WireJson.Default.Reply, ct).ConfigureAwait(false);
        Log.Info("relay", $"{device}: online, Dienste=[{string.Join(",", services)}]");

        try { await session.RunAsync(ct).ConfigureAwait(false); }
        finally
        {
            _devices.TryRemove(new KeyValuePair<string, AgentSession>(device, session));
            session.Dispose();
            Log.Info("relay", $"{device}: offline");
        }
    }

    // -- Agent: Datenverbindung ---------------------------------------------

    /// <returns>true, wenn der Stream an einen wartenden Client uebergeben wurde.</returns>
    async Task<bool> ServeAgentDataAsync(string device, SslStream tls, Hello hello, CancellationToken ct)
    {
        if (!_devices.TryGetValue(device, out var session))
            throw new ProtocolException("Geraet nicht angemeldet");
        if (hello.Stream is not { Length: > 0 } id || !session.HasPending(id))
            throw new ProtocolException("unbekannte Stream-Id");

        if (hello.Error is { Length: > 0 } err)
        {
            // Der Agent kam durch, aber sein lokaler Dienst nicht.
            session.Fail(id, $"Geraet '{device}': {err}");
            return false;
        }

        await Wire.WriteAsync(tls, Reply.Good(), WireJson.Default.Reply, ct).ConfigureAwait(false);
        return session.Deliver(id, tls);
    }

    // -- Uebersicht ----------------------------------------------------------

    /// <summary>
    /// Beantwortet die Frage "welche Geraete kann ich erreichen?". Jeder
    /// Bediener bekommt eine andere Antwort: gefiltert wird mit derselben ACL,
    /// die auch den Zugriff regelt, und zwar je Geraet und je Dienst einzeln.
    /// Ein Geraet, von dem kein einziger Dienst freigegeben ist, taucht gar
    /// nicht erst auf.
    /// </summary>
    async Task ServeListAsync(string client, SslStream tls, CancellationToken ct)
    {
        var acl = _acl;
        var liste = new List<DeviceInfo>();

        foreach (var (device, session) in _devices)
        {
            var erlaubt = session.Services.Where(svc => acl.ServiceReleased(device, svc) && acl.Allows(client, device, svc))
                                          .OrderBy(svc => svc, StringComparer.Ordinal)
                                          .ToArray();
            if (erlaubt.Length == 0) continue;
            liste.Add(new DeviceInfo
            {
                Device = device,
                Services = erlaubt,
                OnlineSec = session.OnlineSeconds,
                Streams = session.ActiveStreams,
                Note = acl.NoteFor(device),
            });
        }
        liste.Sort((a, b) => string.CompareOrdinal(a.Device, b.Device));

        await Wire.WriteAsync(tls, Reply.Good(), WireJson.Default.Reply, ct).ConfigureAwait(false);
        await Wire.WriteAsync(tls, new Listing { Devices = [.. liste] }, WireJson.Default.Listing, ct).ConfigureAwait(false);
        Log.Info("relay", $"client:{client}: Uebersicht, {liste.Count} Geraete sichtbar");
    }

    // -- Client --------------------------------------------------------------

    async Task ServeClientAsync(string client, SslStream tls, Hello hello, CancellationToken ct)
    {
        var device = hello.Device ?? "";
        var service = hello.Service ?? "";
        if (!Tls.IsSaneName(device) || !Tls.IsSaneName(service))
            throw new ProtocolException("Geraet oder Dienst fehlt");

        // Reihenfolge bewusst: erst Berechtigung, dann Existenz. Ein Client ohne
        // Recht auf ein Geraet erfaehrt nicht, ob es das Geraet ueberhaupt gibt.
        if (!_acl.Allows(client, device, service))
        {
            Log.Warn("relay", $"client:{client} -> {device}/{service}: abgelehnt");
            throw new ProtocolException("nicht berechtigt");
        }
        if (!_devices.TryGetValue(device, out var session))
            throw new ProtocolException($"Geraet '{device}' ist nicht online");
        if (!session.Offers(service))
            throw new ProtocolException($"Geraet '{device}' bietet '{service}' nicht an");
        if (!_acl.ServiceReleased(device, service))
            throw new ProtocolException($"Dienst '{service}' ist fuer '{device}' nicht freigegeben");

        using var lease = await session.OpenStreamAsync(client, service, ct).ConfigureAwait(false);
        await Wire.WriteAsync(tls, Reply.Good(), WireJson.Default.Reply, ct).ConfigureAwait(false);

        // Eintragen, damit ein spaeterer ACL-Reload diese Sitzung erreichen kann.
        using var live = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var id = Interlocked.Increment(ref _tunnelSeq);
        _tunnels[id] = new LiveTunnel(client, device, service, live);

        Log.Info("relay", $"client:{client} -> {device}/{service}: offen");
        var t0 = Environment.TickCount64;
        try { await Pump.RunAsync(tls, lease.Stream, live.Token).ConfigureAwait(false); }
        finally
        {
            _tunnels.TryRemove(id, out _);
            Log.Info("relay", $"client:{client} -> {device}/{service}: zu nach {(Environment.TickCount64 - t0) / 1000}s");
        }
    }
}

/// <summary>Eine laufende Nutzsitzung, damit eine ACL-Aenderung sie erreichen kann.</summary>
internal sealed record LiveTunnel(string Client, string Device, string Service, CancellationTokenSource Cts);

/// <summary>Ein angemeldetes Geraet samt seinem Control-Kanal.</summary>
internal sealed class AgentSession(string device, SslStream control, HashSet<string> services, RelayConfig cfg) : IDisposable
{
    readonly ConcurrentDictionary<string, TaskCompletionSource<Stream>> _pending = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<string, int> _perClient = new(StringComparer.Ordinal);
    readonly SemaphoreSlim _write = new(1, 1);
    readonly CancellationTokenSource _dead = new();
    readonly long _since = Environment.TickCount64;
    int _active;

    public bool Offers(string service) => services.Contains(service);
    public bool HasPending(string id) => _pending.ContainsKey(id);
    public IEnumerable<string> Services => services;
    public long OnlineSeconds => (Environment.TickCount64 - _since) / 1000;
    public int ActiveStreams => Volatile.Read(ref _active);

    public async Task RunAsync(CancellationToken ct)
    {
        using var link = CancellationTokenSource.CreateLinkedTokenSource(ct, _dead.Token);
        var ping = PingLoopAsync(link.Token);
        try
        {
            while (!link.IsCancellationRequested)
            {
                using var read = CancellationTokenSource.CreateLinkedTokenSource(link.Token);
                read.CancelAfter(TimeSpan.FromSeconds(cfg.PingTimeoutSec));
                var msg = await Wire.ReadAsync(control, WireJson.Default.Ctl, read.Token).ConfigureAwait(false);
                if (msg.Type != Proto.CtlPong) Log.Dbg("relay", $"{device}: unerwartet '{msg.Type}'");
            }
        }
        catch (Exception e) when (e is IOException or EndOfStreamException or OperationCanceledException or ProtocolException)
        {
            Log.Dbg("relay", $"{device}: Control-Kanal beendet ({e.GetType().Name})");
        }
        finally
        {
            await _dead.CancelAsync().ConfigureAwait(false);
            try { await ping.ConfigureAwait(false); } catch (OperationCanceledException) { }
            foreach (var kv in _pending)
                kv.Value.TrySetException(new IOException("Geraet abgemeldet"));
        }
    }

    async Task PingLoopAsync(CancellationToken ct)
    {
        var iv = TimeSpan.FromSeconds(cfg.PingIntervalSec);
        try
        {
            while (true)
            {
                await Task.Delay(iv, ct).ConfigureAwait(false);
                await SendAsync(new Ctl { Type = Proto.CtlPing }, ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException) { }
    }

    async Task SendAsync(Ctl msg, CancellationToken ct)
    {
        await _write.WaitAsync(ct).ConfigureAwait(false);
        try { await Wire.WriteAsync(control, msg, WireJson.Default.Ctl, ct).ConfigureAwait(false); }
        finally { _write.Release(); }
    }

    /// <summary>Fordert vom Agent eine neue Datenverbindung an und wartet auf deren Eintreffen.</summary>
    public async Task<StreamLease> OpenStreamAsync(string client, string service, CancellationToken ct)
    {
        if (Interlocked.Increment(ref _active) > cfg.MaxStreamsPerDevice)
        {
            Interlocked.Decrement(ref _active);
            throw new ProtocolException($"Geraet '{device}': Grenze von {cfg.MaxStreamsPerDevice} gleichzeitigen Sitzungen erreicht");
        }
        // Zweites, engeres Budget je Bediener. Ohne das koennte ein einzelner
        // Zugang das Geraet fuer alle anderen dichtmachen - versehentlich durch
        // einen Browser mit vielen Verbindungen ebenso wie absichtlich.
        if (_perClient.AddOrUpdate(client, 1, static (_, v) => v + 1) > cfg.MaxStreamsPerClient)
        {
            ReleaseFor(client);
            throw new ProtocolException($"Geraet '{device}': Grenze von {cfg.MaxStreamsPerClient} gleichzeitigen Sitzungen je Bediener erreicht");
        }

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var tcs = new TaskCompletionSource<Stream>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        try
        {
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct, _dead.Token);
            wait.CancelAfter(TimeSpan.FromSeconds(cfg.StreamOpenTimeoutSec));
            await using var _ = wait.Token.Register(() =>
                tcs.TrySetException(new ProtocolException($"Geraet '{device}' hat den Stream nicht geoeffnet"))).ConfigureAwait(false);

            await SendAsync(new Ctl { Type = Proto.CtlOpen, Stream = id, Service = service }, ct).ConfigureAwait(false);
            var stream = await tcs.Task.ConfigureAwait(false);
            return new StreamLease(this, client, stream);
        }
        catch
        {
            ReleaseFor(client);
            throw;
        }
        finally { _pending.TryRemove(id, out _); }
    }

    public bool Deliver(string id, Stream stream)
        => _pending.TryGetValue(id, out var tcs) && tcs.TrySetResult(stream);

    public void Fail(string id, string reason)
    {
        if (_pending.TryGetValue(id, out var tcs)) tcs.TrySetException(new ProtocolException(reason));
    }

    internal void ReleaseFor(string client)
    {
        Interlocked.Decrement(ref _active);
        _perClient.AddOrUpdate(client, 0, static (_, v) => v - 1);
    }

    int _entsorgt;

    public void Dispose()
    {
        // Kann von zwei Seiten kommen: aus der eigenen Schleife und aus einem
        // Entzug ueber die Zugriffsliste.
        if (Interlocked.Exchange(ref _entsorgt, 1) != 0) return;
        try { _dead.Cancel(); } catch (ObjectDisposedException) { }
        try { control.Dispose(); } catch (IOException) { }
        _write.Dispose();
        // _dead wird bewusst nicht entsorgt: daran haengen noch verknuepfte
        // Abbruchgeber laufender Sitzungen, die sonst ins Leere greifen.
    }
}

internal sealed class StreamLease(AgentSession session, string client, Stream stream) : IDisposable
{
    public Stream Stream => stream;
    public void Dispose()
    {
        try { stream.Dispose(); } catch (IOException) { }
        session.ReleaseFor(client);
    }
}
