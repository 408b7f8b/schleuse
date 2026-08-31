using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Drahtformat
//
// Jede Verbindung (Agent-Control, Agent-Data, Client) laeuft ueber genau einen
// TLS-1.3-Socket zum Relay. Direkt nach dem Handshake sendet der Initiator
// eine Zeile JSON (UTF-8, mit \n abgeschlossen), das Relay antwortet mit einer
// Zeile JSON. Danach ist die Verbindung entweder
//   * ein Control-Kanal  -> weitere JSON-Zeilen in beide Richtungen, oder
//   * ein Datenstrom     -> ab hier rohe Bytes, kein Framing mehr.
//
// Das Format ist bewusst zeilenbasiert und nicht binaer: es laesst sich mit
// `openssl s_client` von Hand mitlesen und debuggen.
// ---------------------------------------------------------------------------

internal static class Proto
{
    public const int Version = 1;

    /// <summary>ALPN-Kennung. Erlaubt es, den Relay hinter einem SNI/ALPN-Router neben einem Webserver zu betreiben.</summary>
    public const string Alpn = "schleuse/1";

    /// <summary>
    /// Eigenes Kennzeichen fuer die Selbstanmeldung. Ein Geraet hat dabei noch
    /// kein Zertifikat; ueber das getrennte ALPN waehlt der Relay dafuer andere
    /// TLS-Bedingungen, ohne die Pflicht zum Client-Zertifikat fuer die
    /// Tunnelrollen aufzuweichen.
    /// </summary>
    public const string AlpnEnroll = "schleuse-enroll/1";

    /// <summary>
    /// Servername, mit dem ein Geraet die Selbstanmeldung anspricht. .NET
    /// entscheidet die Frage nach dem Client-Zertifikat im Handshake, also muss
    /// die Weiche vor den Handshake - der Servername aus dem ClientHello ist
    /// das einzige, was dort schon feststeht. So bleibt es bei einem offenen
    /// Port, ohne die Zertifikatspflicht der Tunnelrollen anzutasten.
    /// </summary>
    public const string EnrollSni = "schleuse-enroll";

    /// <summary>Erste Frage des Geraets: "zeig mir deine CA". Vor allem anderen.</summary>
    public const string EnrollCa = "ca";
    public const string EnrollSubmit = "submit";
    public const string EnrollPoll = "poll";

    public const string StatePending = "pending";
    public const string StateApproved = "approved";
    public const string StateRejected = "rejected";

    public const int MaxLineBytes = 8 * 1024;

    // Rollen
    public const string RoleAgent = "agent";          // Control-Kanal eines Geraets
    public const string RoleAgentData = "agent-data"; // vom Agent geoeffneter Datenstrom
    public const string RoleClient = "client";        // Zugriff durch einen Bediener
    public const string RoleList = "list";            // Bediener fragt nach erreichbaren Geraeten

    // Control-Nachrichten
    public const string CtlOpen = "open";  // Relay -> Agent: bitte Datenstrom oeffnen
    public const string CtlPing = "ping";  // Relay -> Agent
    public const string CtlPong = "pong";  // Agent -> Relay
}

internal sealed class Hello
{
    [JsonPropertyName("v")] public int Version { get; set; } = Proto.Version;
    [JsonPropertyName("role")] public string Role { get; set; } = "";

    /// <summary>Nur Rolle "agent": angebotene Dienstnamen.</summary>
    [JsonPropertyName("services")] public string[]? Services { get; set; }

    /// <summary>Nur Rolle "client": Ziel-Geraet.</summary>
    [JsonPropertyName("device")] public string? Device { get; set; }

    /// <summary>Nur Rolle "client": gewuenschter Dienst.</summary>
    [JsonPropertyName("service")] public string? Service { get; set; }

    /// <summary>Nur Rolle "agent-data": Stream-Id aus der zugehoerigen open-Nachricht.</summary>
    [JsonPropertyName("stream")] public string? Stream { get; set; }

    /// <summary>
    /// Nur Rolle "agent-data": der Agent konnte den lokalen Dienst nicht erreichen.
    /// Der Grund wird bis zum Bediener durchgereicht, statt die Verbindung
    /// wortlos fallenzulassen.
    /// </summary>
    [JsonPropertyName("error")] public string? Error { get; set; }
}

internal sealed class Reply
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }

    public static Reply Good() => new() { Ok = true };
    public static Reply Bad(string e) => new() { Ok = false, Error = e };
}

/// <summary>
/// Antwort auf die Rolle "list". Enthaelt ausschliesslich, was der fragende
/// Bediener laut ACL auch erreichen darf - die Uebersicht ist damit fuer jeden
/// eine andere und verraet keine fremden Geraete.
/// </summary>
internal sealed class Listing
{
    [JsonPropertyName("devices")] public DeviceInfo[] Devices { get; set; } = [];
}

internal sealed class DeviceInfo
{
    [JsonPropertyName("device")] public string Device { get; set; } = "";
    [JsonPropertyName("services")] public string[] Services { get; set; } = [];
    /// <summary>Sekunden seit der Anmeldung dieses Geraets.</summary>
    [JsonPropertyName("online_sec")] public long OnlineSec { get; set; }
    /// <summary>Zurzeit laufende Sitzungen zu diesem Geraet, ueber alle Bediener.</summary>
    [JsonPropertyName("streams")] public int Streams { get; set; }
    /// <summary>Freitext aus der Geraeteliste des Relays.</summary>
    [JsonPropertyName("note")] public string? Note { get; set; }
}

/// <summary>Selbstanmeldung: was das Geraet schickt.</summary>
internal sealed class EnrollRequest
{
    [JsonPropertyName("v")] public int Version { get; set; } = Proto.Version;

    /// <summary>"submit" fuer den ersten Antrag, "poll" fuer jede Nachfrage danach.</summary>
    [JsonPropertyName("action")] public string Action { get; set; } = Proto.EnrollSubmit;

    /// <summary>Zertifikatsantrag im PEM-Format. Der Schluessel dazu bleibt auf dem Geraet.</summary>
    [JsonPropertyName("csr")] public string? Csr { get; set; }

    /// <summary>Selbstauskunft fuer die Anzeige beim Betreiber. Ungeprueft.</summary>
    [JsonPropertyName("hostname")] public string? Hostname { get; set; }

    /// <summary>Vorschlag des Geraets, welche Dienste es anbieten wuerde.</summary>
    [JsonPropertyName("services")] public Dictionary<string, string>? Services { get; set; }

    /// <summary>Nachfrage: Kennung des eigenen Antrags.</summary>
    [JsonPropertyName("id")] public string? Id { get; set; }

    /// <summary>Nachfrage: das Abholgeheimnis aus der Antwort auf "submit".</summary>
    [JsonPropertyName("claim")] public string? Claim { get; set; }
}

/// <summary>Selbstanmeldung: was das Geraet zurueckbekommt.</summary>
internal sealed class EnrollReply
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }

    /// <summary>"pending", "approved" oder "rejected".</summary>
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("id")] public string? Id { get; set; }
    /// <summary>Nur in der Antwort auf den ersten Antrag.</summary>
    [JsonPropertyName("claim")] public string? Claim { get; set; }
    /// <summary>Was der Betreiber in der Oberflaeche sieht - das Geraet zeigt dasselbe an.</summary>
    [JsonPropertyName("fingerprint")] public string? Fingerprint { get; set; }

    [JsonPropertyName("device")] public string? Device { get; set; }
    [JsonPropertyName("cert")] public string? Cert { get; set; }
    /// <summary>Die Zwischen-CA, die ausgestellt hat.</summary>
    [JsonPropertyName("chain")] public string? Chain { get; set; }
    /// <summary>Die Wurzel-CA, gegen die das Geraet kuenftig den Relay prueft.</summary>
    [JsonPropertyName("ca")] public string? Ca { get; set; }
    [JsonPropertyName("services")] public Dictionary<string, string>? Services { get; set; }
}

internal sealed class Ctl
{
    [JsonPropertyName("t")] public string Type { get; set; } = "";
    [JsonPropertyName("stream")] public string? Stream { get; set; }
    [JsonPropertyName("service")] public string? Service { get; set; }
}

// Drahtformat: unbekannte Felder werden ueberlesen, damit eine spaetere
// Fassung optionale Felder ergaenzen kann, ohne aeltere Gegenstellen zu
// zerbrechen.
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(Hello))]
[JsonSerializable(typeof(Reply))]
[JsonSerializable(typeof(Ctl))]
[JsonSerializable(typeof(Listing))]
[JsonSerializable(typeof(EnrollRequest))]
[JsonSerializable(typeof(EnrollReply))]
internal partial class WireJson : JsonSerializerContext;

// Konfiguration: hier gilt das Gegenteil. Ein Tippfehler in "services" oder
// "devices" wuerde sonst stillschweigend zu einer leeren Liste - bei einer
// Zugriffsregel ein Fehler, den man erst im Ernstfall bemerkt.
[JsonSourceGenerationOptions(
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    AllowTrailingCommas = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(RelayConfig))]
[JsonSerializable(typeof(AgentConfig))]
[JsonSerializable(typeof(ClientConfig))]
[JsonSerializable(typeof(Acl))]
[JsonSerializable(typeof(PendingFile))]
[JsonSerializable(typeof(EnrollState))]
[JsonSerializable(typeof(UserFile))]
[JsonSerializable(typeof(ApiFile))]
internal partial class JsonCfg : JsonSerializerContext;

internal static class Wire
{
    /// <summary>
    /// Liest genau eine \n-terminierte Zeile.
    ///
    /// Bewusst byteweise: ein Reader mit eigenem Puffer wuerde Bytes verschlucken,
    /// die bereits zur Nutzlast des Datenstroms gehoeren. SslStream puffert intern
    /// ganze TLS-Records, die Einzelbyte-Reads kosten daher keine Syscalls.
    /// </summary>
    public static async Task<string> ReadLineAsync(Stream s, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent(Proto.MaxLineBytes);
        try
        {
            int n = 0;
            while (true)
            {
                if (n == Proto.MaxLineBytes) throw new ProtocolException("Zeile zu lang");
                int r = await s.ReadAsync(buf.AsMemory(n, 1), ct).ConfigureAwait(false);
                if (r == 0) throw new EndOfStreamException();
                if (buf[n] == (byte)'\n') return Encoding.UTF8.GetString(buf, 0, n);
                n++;
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    public static async Task<T> ReadAsync<T>(Stream s, JsonTypeInfo<T> ti, CancellationToken ct) where T : class
    {
        var line = await ReadLineAsync(s, ct).ConfigureAwait(false);
        T? v;
        try { v = JsonSerializer.Deserialize(line, ti); }
        catch (JsonException e) { throw new ProtocolException("ungueltiges JSON: " + e.Message); }
        return v ?? throw new ProtocolException("leere Nachricht");
    }

    public static async Task WriteAsync<T>(Stream s, T value, JsonTypeInfo<T> ti, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, ti);
        var line = new byte[bytes.Length + 1];
        bytes.CopyTo(line, 0);
        line[^1] = (byte)'\n';
        await s.WriteAsync(line, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }
}

internal sealed class ProtocolException(string message) : Exception(message);
