using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Identitaet
//
// Es gibt genau eine private CA. Jede Partei hat ein Zertifikat, dessen CN die
// Identitaet traegt:
//
//   device:werk1-hmi     -> Agent auf einem Geraet
//   client:db            -> Bediener
//   relay.example.com    -> Relay (Servername, per SAN geprueft)
//
// Die Geraete-Id kommt damit aus dem Zertifikat, nicht aus der Konfiguration:
// ein Agent kann sich nicht als ein anderes Geraet ausgeben. Beide Seiten
// pruefen die Gegenstelle gegen die CA (mTLS), TLS 1.3, keine Ausnahmen.
// ---------------------------------------------------------------------------

internal static class Tls
{
    public const string DevicePrefix = "device:";
    public const string ClientPrefix = "client:";

    public static X509Certificate2 LoadIdentity(string certPem, string keyPem)
    {
        if (!File.Exists(certPem)) throw new FileNotFoundException($"Zertifikat fehlt: {certPem}");
        if (!File.Exists(keyPem)) throw new FileNotFoundException($"Schluessel fehlt: {keyPem}");
        WarnIfKeyWorldReadable(keyPem);
        return X509Certificate2.CreateFromPemFile(certPem, keyPem);
    }

    /// <summary>
    /// Laedt die Zwischenzertifikate, die hinter dem eigenen in derselben Datei
    /// stehen. Ein per Selbstanmeldung ausgestelltes Geraetezertifikat haengt an
    /// der Zwischen-CA; die Gegenstelle kann die Kette nur pruefen, wenn das
    /// Geraet sie mitschickt.
    /// </summary>
    public static X509Certificate2[] LoadChainRest(string certPem)
    {
        var alle = new X509Certificate2Collection();
        alle.ImportFromPemFile(certPem);
        return alle.Count <= 1 ? [] : [.. alle.Cast<X509Certificate2>().Skip(1)];
    }

    public static X509Certificate2 LoadCa(string caPem)
    {
        if (!File.Exists(caPem)) throw new FileNotFoundException($"CA fehlt: {caPem}");
        return X509CertificateLoader.LoadCertificateFromFile(caPem);
    }

    static void WarnIfKeyWorldReadable(string path)
    {
        try
        {
            var m = File.GetUnixFileMode(path);
            // Nur "andere" sind das Problem. Lesbar fuer die Dienstgruppe ist die
            // uebliche und richtige Auslieferung: root besitzt die Datei, der
            // Dienst liest sie ueber seine Gruppe.
            if ((m & UnixFileMode.OtherRead) != 0)
                Log.Warn("tls", $"privater Schluessel {path} ist fuer alle lesbar; chmod 640 empfohlen");
        }
        catch (Exception e) when (e is IOException or PlatformNotSupportedException) { }
    }

    /// <summary>Prueft die Gegenstelle gegen die eigene CA und liefert deren CN.</summary>
    /// <summary>Erweiterte Schluesselverwendung: Server- bzw. Client-Authentisierung.</summary>
    const string EkuServerAuth = "1.3.6.1.5.5.7.3.1";
    const string EkuClientAuth = "1.3.6.1.5.5.7.3.2";
    public const string EkuClientAuthOid = EkuClientAuth;

    static bool ValidateAgainstCa(X509Certificate2 ca, X509Certificate2[] extra, X509Certificate? peer,
                                  SslPolicyErrors errors, bool requireHostname, string requiredEku,
                                  out string cn, out string issuerThumbprint)
    {
        cn = "";
        issuerThumbprint = "";
        if (peer is null) return false;

        // Chain-Fehler behandeln wir selbst (die CA ist nicht im System-Store).
        // Ein Namensfehler beim Servernamen ist dagegen bindend.
        if (requireHostname && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;

        using var cert = X509CertificateLoader.LoadCertificate(peer.GetRawCertData());
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Sperrung laeuft ueber acl.json
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        // Ohne diese Bindung koennte ein Geraetezertifikat als Relay-Zertifikat
        // auftreten und umgekehrt.
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(requiredEku));
        foreach (var c in extra) chain.ChainPolicy.ExtraStore.Add(c);

        if (!chain.Build(cert)) return false;

        // Wer hat unmittelbar signiert? Daran haengt, welche Rollen ein
        // Zertifikat annehmen darf - siehe IssuedByRoot.
        issuerThumbprint = chain.ChainElements.Count > 1
            ? chain.ChainElements[1].Certificate.Thumbprint
            : cert.Thumbprint;

        cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";
        return cn.Length > 0;
    }

    /// <summary>Serverseite (Relay): verlangt ein Client-Zertifikat, merkt sich dessen CN.</summary>
    public static SslServerAuthenticationOptions ServerOptions(X509Certificate2 ca, X509Certificate2[] extra,
                                                               X509Certificate2 me, PeerName peer)
        => new()
        {
            ServerCertificate = me,
            ClientCertificateRequired = true,
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ApplicationProtocols = [new SslApplicationProtocol(Proto.Alpn)],
            RemoteCertificateValidationCallback = (_, c, _, e) =>
            {
                var ok = ValidateAgainstCa(ca, extra, c, e, requireHostname: false, EkuClientAuth,
                                           out var cn, out var issuer);
                peer.Cn = cn;
                peer.IssuerThumbprint = issuer;
                return ok;
            },
        };

    /// <summary>
    /// Serverseite ohne Client-Zertifikat, ausschliesslich fuer die
    /// Selbstanmeldung. Wird ueber ein eigenes ALPN-Kennzeichen ausgewaehlt,
    /// damit die Tunnelrollen ihre Pflicht zum Client-Zertifikat behalten.
    /// </summary>
    public static SslServerAuthenticationOptions EnrollServerOptions(X509Certificate2 me, X509Certificate2 ca)
        => new()
        {
            // Die Wurzel-CA wird mitgeschickt, obwohl Server das sonst weglassen:
            // das Geraet kennt sie noch nicht und braucht sie, um den
            // Fingerabdruck aus seiner Konfiguration dagegenzuhalten.
            ServerCertificateContext = SslStreamCertificateContext.Create(me, [ca], offline: true),
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ApplicationProtocols = [new SslApplicationProtocol(Proto.AlpnEnroll)],
        };

    /// <summary>Clientseite (Agent/Bediener): prueft Servername und CA, sendet das eigene Zertifikat.</summary>
    public static SslClientAuthenticationOptions ClientOptions(X509Certificate2 ca, X509Certificate2 me,
                                                               X509Certificate2[] chainRest, string host)
        => new()
        {
            TargetHost = host,
            // Die eigene Kette mitschicken, sonst kann der Relay ein per
            // Selbstanmeldung ausgestelltes Zertifikat nicht zurueckverfolgen.
            ClientCertificateContext = SslStreamCertificateContext.Create(me, [.. chainRest], offline: true),
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ApplicationProtocols = [new SslApplicationProtocol(Proto.Alpn)],
            RemoteCertificateValidationCallback = (_, c, _, e) =>
                ValidateAgainstCa(ca, [], c, e, requireHostname: true, EkuServerAuth, out _, out _),
        };

    /// <summary>
    /// Erstanmeldung eines Geraets: es kennt die CA noch nicht und prueft den
    /// Relay am Fingerabdruck aus seiner Konfiguration. Der Relay schickt die
    /// Wurzel-CA im Handshake mit; erkannt wird sie am Abdruck, danach wird die
    /// Kette ganz normal dagegen geprueft - samt Gueltigkeit, Verwendungszweck
    /// und Rechnername. Blind vertraut wird nichts.
    /// </summary>
    public static SslClientAuthenticationOptions EnrollClientOptions(string host, PeerName peer)
        => new()
        {
            // Der Servername waehlt beim Relay die Betriebsart; der Rechnername
            // wird darum spaeter von Hand gegen die wirkliche Adresse geprueft.
            TargetHost = Proto.EnrollSni,
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ApplicationProtocols = [new SslApplicationProtocol(Proto.AlpnEnroll)],
            // Hier kann noch nicht geprueft werden: das Geraet kennt die CA nicht.
            // Das Zertifikat wird nur festgehalten; geprueft wird es unmittelbar
            // nach dem Handshake in PruefeRelay, bevor irgendetwas gesendet wird.
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                if (cert is not null) peer.Leaf = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                return peer.Leaf is not null;
            },
        };

    /// <summary>
    /// Prueft den Relay gegen den Fingerabdruck aus der Konfiguration des
    /// Geraets. Erst wenn das durchgeht, verlaesst der Zertifikatsantrag das
    /// Geraet. Schlaegt es fehl, wird die Verbindung abgebrochen.
    /// </summary>
    public static X509Certificate2 PruefeRelay(string caPemVomRelay, string caPin, string host, X509Certificate2 leaf)
    {
        X509Certificate2 ca;
        try { ca = X509Certificate2.CreateFromPem(caPemVomRelay); }
        catch (CryptographicException e) { throw new ProtocolException("CA des Relays unlesbar: " + e.Message); }

        var gezeigt = Fingerprint.OfCertificate(ca);
        if (!Fingerprint.Same(gezeigt, caPin))
            throw new ProtocolException(
                $"falscher CA-Fingerabdruck. Erwartet {caPin}, bekommen {gezeigt}. " +
                "Entweder ist der Pin falsch oder es antwortet nicht der richtige Relay.");

        if (!leaf.MatchesHostname(host))
            throw new ProtocolException($"das Zertifikat des Relays gilt nicht fuer '{host}'");

        using var pruef = new X509Chain();
        pruef.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        pruef.ChainPolicy.CustomTrustStore.Add(ca);
        pruef.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        pruef.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        pruef.ChainPolicy.ApplicationPolicy.Add(new Oid(EkuServerAuth));
        if (!pruef.Build(leaf))
            throw new ProtocolException("das Zertifikat des Relays passt nicht zu der CA, die es nennt");

        return ca;
    }

    /// <summary>Aufnahmegefaess fuer das, was der Callback ueber die Gegenstelle ermittelt hat.</summary>
    public sealed class PeerName
    {
        public string Cn = "";
        /// <summary>Fingerabdruck des unmittelbaren Ausstellers.</summary>
        public string IssuerThumbprint = "";
        /// <summary>Diese Verbindung ist eine Selbstanmeldung ohne Client-Zertifikat.</summary>
        public bool Enrollment;
        /// <summary>Bei der Selbstanmeldung: das Zertifikat des Relays, noch ungeprueft.</summary>
        public X509Certificate2? Leaf;
    }

    public static bool SplitIdentity(string cn, out string kind, out string name)
    {
        if (cn.StartsWith(DevicePrefix, StringComparison.Ordinal))
        {
            kind = "device"; name = cn[DevicePrefix.Length..];
        }
        else if (cn.StartsWith(ClientPrefix, StringComparison.Ordinal))
        {
            kind = "client"; name = cn[ClientPrefix.Length..];
        }
        else { kind = ""; name = ""; return false; }

        return IsSaneName(name);
    }

    /// <summary>Namen sind bewusst eng gefasst: sie landen in Logzeilen und ACL-Vergleichen.</summary>
    public static bool IsSaneName(string s)
    {
        if (s.Length is 0 or > 64) return false;
        foreach (var c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) return false;
        return true;
    }
}
