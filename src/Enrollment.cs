using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Selbstanmeldung mit Warteschlange
//
// Ein neues Geraet meldet sich beim Relay an und landet zunaechst in einer
// Warteschlange: kein Zertifikat, kein Tunnel, kein Eintrag in der Geraeteliste.
// Es kann von dort aus nichts erreichen und nichts ausloesen. Der Betreiber
// sieht den Antrag in der Weboberflaeche, vergleicht den Fingerabdruck mit dem,
// den das Geraet angezeigt hat, vergibt einen Namen und die Portfreigaben - und
// gibt frei. Erst dann wird ein Zertifikat ausgestellt, das das Geraet beim
// naechsten Nachfragen abholt.
//
// Damit braucht das Geraet bei der Installation kein Geheimnis. Es genuegt die
// Adresse des Relays und dessen CA-Fingerabdruck; beides ist fuer alle Geraete
// einer Anlage gleich und darf offen im Provisionierungsskript stehen.
// ---------------------------------------------------------------------------

[JsonConverter(typeof(JsonStringEnumConverter<PendingState>))]
internal enum PendingState { Pending, Approved, Rejected }

internal sealed class PendingRequest
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    /// <summary>Fingerabdruck des oeffentlichen Schluessels - der Abgleich mit dem Geraet.</summary>
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; set; } = "";
    /// <summary>SHA-256 des Abholgeheimnisses. Nur wer den Antrag gestellt hat, holt das Zertifikat ab.</summary>
    [JsonPropertyName("claim_hash")] public string ClaimHash { get; set; } = "";
    [JsonPropertyName("csr")] public string Csr { get; set; } = "";
    /// <summary>Selbstauskunft des Geraets. Ungeprueft - nur ein Hinweis fuer den Betreiber.</summary>
    [JsonPropertyName("hostname")] public string? Hostname { get; set; }
    /// <summary>Vom Geraet vorgeschlagene Dienste. Der Betreiber entscheidet, was davon gilt.</summary>
    [JsonPropertyName("proposed")] public Dictionary<string, string> Proposed { get; set; } = new();
    [JsonPropertyName("from")] public string From { get; set; } = "";
    [JsonPropertyName("first_seen")] public DateTimeOffset FirstSeen { get; set; }
    [JsonPropertyName("last_seen")] public DateTimeOffset LastSeen { get; set; }
    [JsonPropertyName("state")] public PendingState State { get; set; } = PendingState.Pending;

    [JsonPropertyName("device")] public string? Device { get; set; }
    [JsonPropertyName("cert")] public string? Cert { get; set; }
    [JsonPropertyName("services")] public Dictionary<string, string>? Services { get; set; }
    [JsonPropertyName("decided_by")] public string? DecidedBy { get; set; }
    [JsonPropertyName("decided_at")] public DateTimeOffset? DecidedAt { get; set; }
}

internal sealed class PendingFile
{
    [JsonPropertyName("requests")] public List<PendingRequest> Requests { get; set; } = [];
}

/// <summary>Die Warteschlange. Alle Zugriffe laufen ueber dasselbe Schloss.</summary>
internal sealed class PendingStore(string path, int maxOffen, TimeSpan lebensdauer)
{
    readonly Lock _gate = new();
    PendingFile _datei = Store.Load(path, JsonCfg.Default.PendingFile, () => new PendingFile());

    public IReadOnlyList<PendingRequest> Alle()
    {
        lock (_gate) { Aufraeumen(); return [.. _datei.Requests]; }
    }

    public PendingRequest? ById(string id)
    {
        lock (_gate) return _datei.Requests.Find(r => r.Id == id);
    }

    /// <summary>
    /// Nimmt einen Antrag entgegen. Meldet sich dasselbe Geraet erneut - etwa
    /// nach einem Neustart, bevor jemand freigegeben hat -, wird der bestehende
    /// Antrag fortgefuehrt statt ein zweiter angelegt. Erkannt wird das am
    /// Fingerabdruck des Schluessels.
    /// </summary>
    public (PendingRequest Eintrag, string? Claim) Aufnehmen(string csr, string fingerprint, string? hostname,
                                                             Dictionary<string, string> vorschlag, string von)
    {
        lock (_gate)
        {
            Aufraeumen();

            var vorhanden = _datei.Requests.Find(r => r.Fingerprint == fingerprint);
            if (vorhanden is not null)
            {
                vorhanden.LastSeen = DateTimeOffset.UtcNow;
                Speichern();
                return (vorhanden, null); // das Geraet kennt sein Abholgeheimnis bereits
            }

            var offen = _datei.Requests.Count(r => r.State == PendingState.Pending);
            if (offen >= maxOffen)
                throw new ProtocolException($"queue is full ({maxOffen} open requests) - please work through them first");

            var claim = RandomNumberGenerator.GetBytes(32);
            var e = new PendingRequest
            {
                Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
                Fingerprint = fingerprint,
                ClaimHash = Convert.ToBase64String(SHA256.HashData(claim)),
                Csr = csr,
                Hostname = hostname,
                Proposed = vorschlag,
                From = von,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
            };
            _datei.Requests.Add(e);
            Speichern();
            return (e, Convert.ToBase64String(claim));
        }
    }

    /// <summary>Nachfrage des Geraets. Nur mit dem richtigen Abholgeheimnis.</summary>
    public PendingRequest? Nachfragen(string id, string claim)
    {
        lock (_gate)
        {
            var e = _datei.Requests.Find(r => r.Id == id);
            if (e is null) return null;

            var erwartet = System.Text.Encoding.ASCII.GetBytes(e.ClaimHash);
            byte[] gezeigt;
            try { gezeigt = System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(claim)))); }
            catch (FormatException) { return null; }
            if (erwartet.Length != gezeigt.Length || !CryptographicOperations.FixedTimeEquals(erwartet, gezeigt))
                return null;

            e.LastSeen = DateTimeOffset.UtcNow;
            Speichern();
            return e;
        }
    }

    /// <summary>Freigabe durch den Betreiber: jetzt entsteht das Zertifikat.</summary>
    public PendingRequest Freigeben(string id, string device, Dictionary<string, string> services,
                                    DeviceIssuer issuer, string durch)
    {
        lock (_gate)
        {
            var e = _datei.Requests.Find(r => r.Id == id)
                    ?? throw new InvalidOperationException("request not found");
            if (e.State != PendingState.Pending)
                throw new InvalidOperationException($"request is already {e.State}");
            if (!Tls.IsSaneName(device))
                throw new InvalidOperationException("unusable device name");

            var antrag = DeviceIssuer.PruefeAntrag(e.Csr);
            // Der Fingerabdruck im Eintrag muss zum Antrag passen - sonst waere
            // zwischen Anzeige und Freigabe etwas ausgetauscht worden.
            if (!Fingerprint.Same(e.Fingerprint, Fingerprint.OfPublicKey(antrag.PublicKey)))
                throw new InvalidOperationException("fingerprint does not match the stored request");

            using var cert = issuer.Issue(device, antrag);
            e.Cert = Pem.Certificate(cert);
            e.Device = device;
            e.Services = services;
            e.State = PendingState.Approved;
            e.DecidedBy = durch;
            e.DecidedAt = DateTimeOffset.UtcNow;
            Speichern();
            return e;
        }
    }

    public void Ablehnen(string id, string durch)
    {
        lock (_gate)
        {
            var e = _datei.Requests.Find(r => r.Id == id) ?? throw new InvalidOperationException("request not found");
            e.State = PendingState.Rejected;
            e.DecidedBy = durch;
            e.DecidedAt = DateTimeOffset.UtcNow;
            e.Csr = "";
            Speichern();
        }
    }

    public bool Loeschen(string id)
    {
        lock (_gate)
        {
            var weg = _datei.Requests.RemoveAll(r => r.Id == id) > 0;
            if (weg) Speichern();
            return weg;
        }
    }

    void Speichern() => Store.Save(path, _datei, JsonCfg.Default.PendingFile);

    /// <summary>
    /// Offene Antraege verfallen; freigegebene bleiben, bis das Geraet sein
    /// Zertifikat abgeholt hat, und danach noch eine Weile zur Nachschau.
    /// </summary>
    void Aufraeumen()
    {
        var jetzt = DateTimeOffset.UtcNow;
        var vorher = _datei.Requests.Count;
        _datei.Requests.RemoveAll(r =>
            r.State == PendingState.Pending ? jetzt - r.LastSeen > lebensdauer
                                            : jetzt - (r.DecidedAt ?? r.LastSeen) > TimeSpan.FromDays(30));
        if (_datei.Requests.Count != vorher) Speichern();
    }
}

/// <summary>Stellt Geraetezertifikate aus. Existiert nur, wenn eine Zwischen-CA eingerichtet ist.</summary>
internal sealed class DeviceIssuer(X509Certificate2 issuer, int certDays)
{
    public X509Certificate2 Ca => issuer;

    public X509Certificate2 Issue(string device, CertificateRequest antrag)
    {
        var subject = new X500DistinguishedName($"CN={Tls.DevicePrefix}{device}");
        var req = new CertificateRequest(subject, antrag.PublicKey, HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(Tls.EkuClientAuthOid)], critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(antrag.PublicKey, critical: false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        // Fuenf Minuten Vorlauf: Geraete im Feld haben oft eine ungenaue Uhr.
        // Aber nie vor die ausstellende CA selbst - eine frisch angelegte
        // Zwischen-CA ist sonst juenger als das erste Zertifikat, das sie
        // ausstellt, und .NET weist das zu Recht zurueck.
        var caVon = new DateTimeOffset(issuer.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var caBis = new DateTimeOffset(issuer.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        var von = DateTimeOffset.UtcNow.AddMinutes(-5);
        if (von < caVon) von = caVon;
        var bis = DateTimeOffset.UtcNow.AddDays(certDays);
        if (bis > caBis) bis = caBis;   // und nie laenger gueltig als die CA
        if (bis <= von) throw new ProtocolException("the intermediate CA has expired");
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;

        return req.Create(issuer, von, bis, serial);
    }

    /// <summary>Prueft den Antrag, bevor daraus ein Zertifikat wird.</summary>
    public static CertificateRequest PruefeAntrag(string csrPem)
    {
        CertificateRequest antrag;
        try
        {
            // Die Vorgabe prueft die Selbstsignatur des Antrags - damit ist
            // belegt, dass der Antragsteller den zugehoerigen Schluessel besitzt.
            antrag = CertificateRequest.LoadSigningRequestPem(
                csrPem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or InvalidOperationException)
        {
            throw new ProtocolException("certificate request unusable: " + e.Message);
        }

        var oid = antrag.PublicKey.Oid.Value;
        switch (oid)
        {
            case "1.2.840.10045.2.1": // ECDSA
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(antrag.PublicKey.ExportSubjectPublicKeyInfo(), out _);
                if (ec.KeySize < 256) throw new ProtocolException($"EC key too short: {ec.KeySize} bit");
                break;
            }
            case "1.2.840.113549.1.1.1": // RSA
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(antrag.PublicKey.ExportSubjectPublicKeyInfo(), out _);
                if (rsa.KeySize < 2048) throw new ProtocolException($"RSA key too short: {rsa.KeySize} bit");
                break;
            }
            default:
                throw new ProtocolException($"key algorithm {oid} not allowed");
        }
        return antrag;
    }
}

internal static class Pem
{
    public static string Certificate(X509Certificate2 cert) =>
        new string(System.Security.Cryptography.PemEncoding.Write("CERTIFICATE", cert.RawData));
}
