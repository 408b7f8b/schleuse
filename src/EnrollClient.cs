using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Schleuse;

/// <summary>Was zwischen Antrag und Freigabe auf dem Geraet liegen bleibt.</summary>
internal sealed class EnrollState
{
    [JsonPropertyName("relay")] public string Relay { get; set; } = "";
    [JsonPropertyName("ca_pin")] public string CaPin { get; set; } = "";
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("claim")] public string Claim { get; set; } = "";
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; set; } = "";
    /// <summary>Der private Schluessel des Geraets. Verlaesst das Geraet nicht.</summary>
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    [JsonPropertyName("csr")] public string Csr { get; set; } = "";
    [JsonPropertyName("services")] public Dictionary<string, string> Services { get; set; } = new();
}

// ---------------------------------------------------------------------------
// schleuse enroll
//
// Einmalig auf dem Geraet. Erzeugt einen Schluessel, stellt einen Antrag und
// wartet, bis der Betreiber freigibt. Braucht dafuer kein Geheimnis - nur die
// Adresse des Relays und dessen CA-Fingerabdruck, und beides ist fuer alle
// Geraete einer Anlage dasselbe.
//
// Bricht der Vorgang ab oder startet das Geraet neu, wird der begonnene Antrag
// aus enroll-state.json fortgesetzt; es entsteht kein zweiter.
// ---------------------------------------------------------------------------

internal sealed class EnrollClient(string relay, string caPin, string dir, string hostname,
                                   Dictionary<string, string> services, TimeSpan interval)
{
    string StatePath => Path.Combine(dir, "enroll-state.json");
    string CaPath => Path.Combine(dir, "ca.crt");
    string CertPath => Path.Combine(dir, "device.crt");
    string KeyPath => Path.Combine(dir, "device.key");
    string ConfigPath => Path.Combine(dir, "agent.json");

    public async Task<int> RunAsync(CancellationToken ct)
    {
        if (File.Exists(CertPath))
        {
            Log.Err("enroll", $"{CertPath} existiert bereits - dieses Geraet ist schon angemeldet. " +
                              "Zum Neuanmelden die Datei entfernen.");
            return 1;
        }
        Directory.CreateDirectory(dir);

        var state = Store.Load(StatePath, JsonCfg.Default.EnrollState, () => Neu());
        var neu = state.Id.Length == 0;
        if (!neu && (state.Relay != relay || !Fingerprint.Same(state.CaPin, caPin)))
        {
            Log.Err("enroll", "der begonnene Antrag gehoert zu einem anderen Relay - " +
                              $"entweder die alten Angaben verwenden oder {StatePath} entfernen");
            return 1;
        }

        Console.WriteLine($"Relay:         {relay}");
        Console.WriteLine($"CA-Pin:        {caPin}");
        Console.WriteLine();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (state.Id.Length == 0)
                {
                    var a = await SendAsync(new EnrollRequest
                    {
                        Action = Proto.EnrollSubmit,
                        Csr = state.Csr,
                        Hostname = hostname,
                        Services = state.Services,
                    }, ct).ConfigureAwait(false);

                    if (!a.Ok) throw new ProtocolException(a.Error ?? "abgelehnt");
                    state.Id = a.Id ?? "";
                    state.Claim = a.Claim ?? "";
                    state.Fingerprint = a.Fingerprint ?? "";
                    Store.Save(StatePath, state, JsonCfg.Default.EnrollState);

                    Console.WriteLine("Antrag gestellt. Das Geraet wartet auf die Freigabe.");
                    Console.WriteLine();
                    Console.WriteLine($"    Fingerabdruck   {state.Fingerprint}");
                    Console.WriteLine();
                    Console.WriteLine("Diesen Fingerabdruck in der Weboberflaeche des Relays vergleichen,");
                    Console.WriteLine("bevor freigegeben wird. Weichen die Werte ab, hat jemand den Antrag");
                    Console.WriteLine("unterwegs ausgetauscht.");
                    Console.WriteLine();
                    continue;
                }

                var r = await SendAsync(new EnrollRequest
                {
                    Action = Proto.EnrollPoll,
                    Id = state.Id,
                    Claim = state.Claim,
                }, ct).ConfigureAwait(false);

                if (!r.Ok) throw new ProtocolException(r.Error ?? "abgelehnt");

                switch (r.Status)
                {
                    case Proto.StateApproved:
                        Uebernehmen(state, r);
                        return 0;

                    case Proto.StateRejected:
                        Console.WriteLine("Der Antrag wurde abgelehnt.");
                        File.Delete(StatePath);
                        return 1;

                    default:
                        Log.Dbg("enroll", "noch nicht freigegeben");
                        break;
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Log.Warn("enroll", e.Message);
            }

            try { await Task.Delay(interval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        return 1;
    }

    EnrollState Neu()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Der Name im Antrag ist ein Platzhalter - welchen Namen das Geraet
        // bekommt, entscheidet der Betreiber bei der Freigabe.
        var req = new CertificateRequest(new X500DistinguishedName("CN=schleuse-antrag"), key, HashAlgorithmName.SHA256);
        return new EnrollState
        {
            Relay = relay,
            CaPin = caPin,
            Key = key.ExportPkcs8PrivateKeyPem(),
            Csr = req.CreateSigningRequestPem(),
            Services = services,
        };
    }

    /// <summary>
    /// Eine Anfrage, eine Verbindung. Ein wartendes Geraet haelt nichts offen.
    ///
    /// Der erste Schritt auf jeder Verbindung ist die Frage nach der CA des
    /// Relays und deren Abgleich mit dem Fingerabdruck aus der Konfiguration.
    /// Erst danach geht der Zertifikatsantrag hinaus.
    /// </summary>
    async Task<EnrollReply> SendAsync(EnrollRequest req, CancellationToken ct)
    {
        var (host, _) = Net.SplitHostPort(relay);
        var peer = new Tls.PeerName();
        var sock = await Net.ConnectAsync(relay, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        await using var tls = new SslStream(new NetworkStream(sock, ownsSocket: true), leaveInnerStreamOpen: false);

        using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
        to.CancelAfter(TimeSpan.FromSeconds(30));
        await tls.AuthenticateAsClientAsync(Tls.EnrollClientOptions(host, peer), to.Token).ConfigureAwait(false);

        await Wire.WriteAsync(tls, new EnrollRequest { Action = Proto.EnrollCa }, WireJson.Default.EnrollRequest, to.Token)
                  .ConfigureAwait(false);
        var vorstellung = await Wire.ReadAsync(tls, WireJson.Default.EnrollReply, to.Token).ConfigureAwait(false);
        if (!vorstellung.Ok || vorstellung.Ca is not { Length: > 0 } caPem)
            throw new ProtocolException(vorstellung.Error ?? "der Relay nennt seine CA nicht");

        using var leaf = peer.Leaf ?? throw new ProtocolException("kein Zertifikat vom Relay erhalten");
        using var ca = Tls.PruefeRelay(caPem, caPin, host, leaf);

        await Wire.WriteAsync(tls, req, WireJson.Default.EnrollRequest, to.Token).ConfigureAwait(false);
        return await Wire.ReadAsync(tls, WireJson.Default.EnrollReply, to.Token).ConfigureAwait(false);
    }

    void Uebernehmen(EnrollState state, EnrollReply r)
    {
        if (r.Device is not { Length: > 0 } device || r.Cert is not { Length: > 0 } cert
            || r.Chain is not { Length: > 0 } chain || r.Ca is not { Length: > 0 } ca)
            throw new ProtocolException("Freigabe unvollstaendig");

        // Gegenprobe: das ausgestellte Zertifikat muss zu unserem Schluessel und
        // zu dem Fingerabdruck gehoeren, den der Betreiber gesehen hat.
        using var ausgestellt = X509Certificate2.CreateFromPem(cert);
        if (!Fingerprint.Same(state.Fingerprint, Fingerprint.OfPublicKey(ausgestellt.PublicKey)))
            throw new ProtocolException("das ausgestellte Zertifikat gehoert nicht zu diesem Antrag");

        var cn = ausgestellt.GetNameInfo(X509NameType.SimpleName, false) ?? "";
        if (cn != Tls.DevicePrefix + device)
            throw new ProtocolException($"unerwarteter Name im Zertifikat: '{Log.Safe(cn)}'");

        Schreibe(CaPath, ca, oeffentlich: true);
        Schreibe(CertPath, cert.TrimEnd() + "\n" + chain.TrimEnd() + "\n", oeffentlich: true);
        Schreibe(KeyPath, state.Key, oeffentlich: false);

        var dienste = r.Services is { Count: > 0 } ? r.Services : state.Services;
        var cfg = new AgentConfig
        {
            Relay = relay,
            Ca = "ca.crt",
            Cert = "device.crt",
            Key = "device.key",
            Services = dienste,
        };
        Store.Save(ConfigPath, cfg, JsonCfg.Default.AgentConfig);
        File.SetUnixFileMode(ConfigPath, UnixFileMode.UserRead | UnixFileMode.UserWrite
                                       | UnixFileMode.GroupRead);
        File.Delete(StatePath);

        Console.WriteLine($"Freigegeben als '{device}'.");
        Console.WriteLine($"Dienste: {(dienste.Count == 0 ? "(keine)" : string.Join(", ", dienste.Select(kv => $"{kv.Key}={kv.Value}")))}");
        Console.WriteLine();
        Console.WriteLine($"Geschrieben: {CaPath}, {CertPath}, {KeyPath}, {ConfigPath}");
        Console.WriteLine("Jetzt starten:  systemctl enable --now schleuse-agent");
    }

    static void Schreibe(string pfad, string inhalt, bool oeffentlich)
    {
        var mode = oeffentlich
            ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead
            : UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var f = new FileStream(pfad, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = mode,
        });
        f.Write(System.Text.Encoding.UTF8.GetBytes(inhalt));
        f.Flush(flushToDisk: true);
    }
}
