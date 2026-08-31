using System.Text.Json;
using System.Text.Json.Serialization;

namespace Schleuse;

internal sealed class TlsFiles
{
    [JsonPropertyName("ca")] public string Ca { get; set; } = "";
    [JsonPropertyName("cert")] public string Cert { get; set; } = "";
    [JsonPropertyName("key")] public string Key { get; set; } = "";
}

internal sealed class RelayConfig
{
    [JsonPropertyName("listen")] public string Listen { get; set; } = "0.0.0.0:443";
    [JsonPropertyName("ca")] public string Ca { get; set; } = "";
    [JsonPropertyName("cert")] public string Cert { get; set; } = "";
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    [JsonPropertyName("acl")] public string Acl { get; set; } = "";

    /// <summary>Gleichzeitige Sitzungen zu einem Geraet, ueber alle Bediener zusammen.</summary>
    [JsonPropertyName("max_streams_per_device")] public int MaxStreamsPerDevice { get; set; } = 64;
    /// <summary>
    /// Davon hoechstens so viele fuer einen einzelnen Bediener. Verhindert, dass
    /// einer das Budget eines Geraets auffuellt und die anderen aussperrt.
    /// </summary>
    [JsonPropertyName("max_streams_per_client")] public int MaxStreamsPerClient { get; set; } = 16;
    [JsonPropertyName("stream_open_timeout_sec")] public int StreamOpenTimeoutSec { get; set; } = 15;
    [JsonPropertyName("handshake_timeout_sec")] public int HandshakeTimeoutSec { get; set; } = 10;
    [JsonPropertyName("ping_interval_sec")] public int PingIntervalSec { get; set; } = 30;
    [JsonPropertyName("ping_timeout_sec")] public int PingTimeoutSec { get; set; } = 90;
    /// <summary>
    /// Zwischen-CA fuer die Selbstanmeldung von Geraeten. Fehlt der Abschnitt,
    /// nimmt der Relay keine Selbstanmeldungen an und stellt nichts aus.
    /// </summary>
    [JsonPropertyName("enrollment")] public EnrollmentConfig? Enrollment { get; set; }

    /// <summary>
    /// Laesst Geraete zu, die nicht in der Liste stehen. Die Vorgabe ist nein:
    /// eine fehlende oder leere Geraeteliste erlaubt niemanden, statt jeden.
    ///
    /// Das ist die vorsichtige Auslegung. Wer eine bestehende Anlage ohne Liste
    /// betreibt, setzt den Schalter bewusst - dann steht es auch in der
    /// Konfiguration und nicht nur im Kopf des Betreibers.
    /// </summary>
    [JsonPropertyName("allow_unlisted_devices")] public bool AllowUnlistedDevices { get; set; }

    /// <summary>Weboberflaeche zur Verwaltung. Fehlt der Abschnitt, laeuft keine.</summary>
    [JsonPropertyName("web")] public WebConfig? Web { get; set; }

    /// <summary>Gleichzeitig laufende TLS-Handshakes. Begrenzt nur den Rechenaufwand, nicht die Zahl der Sitzungen.</summary>
    [JsonPropertyName("max_concurrent_handshakes")] public int MaxConcurrentHandshakes { get; set; } = 256;
}

internal sealed class WebConfig
{
    [JsonPropertyName("listen")] public string Listen { get; set; } = "0.0.0.0:8443";

    /// <summary>
    /// Zertifikat der Weboberflaeche - sinnvollerweise ein oeffentlich
    /// vertrauenswuerdiges, damit der Browser nicht warnt. Fehlt es, nimmt der
    /// Relay sein eigenes; dann warnt der Browser bei jedem Aufruf.
    /// </summary>
    [JsonPropertyName("cert")] public string? Cert { get; set; }
    [JsonPropertyName("key")] public string? Key { get; set; }

    [JsonPropertyName("users")] public string Users { get; set; } = "users.json";

    /// <summary>Name, unter dem die Authenticator-App den Eintrag fuehrt.</summary>
    [JsonPropertyName("issuer")] public string Issuer { get; set; } = "schleuse";

    /// <summary>Marken der Schnittstelle und der Schalter fuer die Oberflaeche.</summary>
    [JsonPropertyName("state")] public string State { get; set; } = "api.json";

    /// <summary>
    /// Runden der Passwortableitung. Die Vorgabe folgt der OWASP-Empfehlung und
    /// passt auf gewoehnliche Server. Auf kleinen Rechnern ohne
    /// SHA-Beschleunigung - einem Raspberry Pi 3 etwa - dauert das mehrere
    /// Sekunden je Anmeldung und wird damit selbst zum Hebel fuer eine
    /// Ueberlastung; dort ist ein kleinerer Wert die bessere Wahl.
    ///
    /// Die Rundenzahl steht in jedem gespeicherten Hash mit drin. Ein
    /// geaenderter Wert entwertet bestehende Passwoerter also nicht, er gilt
    /// ab dem naechsten Setzen.
    /// </summary>
    [JsonPropertyName("password_iterations")] public int PasswordIterations { get; set; } = Passwords.Iterations;

    /// <summary>
    /// Vorsatz aller Schnittstellenpfade. Ein selbst gewaehlter, nicht
    /// erratbarer Wert haelt beilaeufiges Absuchen fern - die eigentliche
    /// Absicherung ist und bleibt aber die Marke.
    /// </summary>
    [JsonPropertyName("api_path")] public string ApiPath { get; set; } = "/api";
}

internal sealed class EnrollmentConfig
{
    /// <summary>Zertifikat der Zwischen-CA, mit der Geraete ausgestellt werden.</summary>
    [JsonPropertyName("ca")] public string Ca { get; set; } = "";
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    /// <summary>Gueltigkeitsdauer ausgestellter Geraetezertifikate.</summary>
    [JsonPropertyName("cert_days")] public int CertDays { get; set; } = 825;
    /// <summary>Datei mit der Warteschlange der Antraege.</summary>
    [JsonPropertyName("queue")] public string Queue { get; set; } = "pending.json";
    /// <summary>Hoechstzahl offener Antraege. Verhindert, dass jemand die Warteschlange zumuellt.</summary>
    [JsonPropertyName("max_pending")] public int MaxPending { get; set; } = 32;
    /// <summary>Ein unbearbeiteter Antrag verfaellt nach dieser Zeit ohne Nachfrage.</summary>
    [JsonPropertyName("pending_hours")] public int PendingHours { get; set; } = 72;
}

internal sealed class AgentConfig
{
    /// <summary>host:port des Relays.</summary>
    [JsonPropertyName("relay")] public string Relay { get; set; } = "";
    [JsonPropertyName("ca")] public string Ca { get; set; } = "";
    [JsonPropertyName("cert")] public string Cert { get; set; } = "";
    [JsonPropertyName("key")] public string Key { get; set; } = "";

    /// <summary>
    /// Freigabeliste: Dienstname -> lokales Ziel "host:port".
    /// Das ist die zentrale Sicherheitsgrenze des Agents. Er verbindet sich
    /// ausschliesslich zu Zielen aus dieser Tabelle; das Relay kann kein
    /// beliebiges Ziel anfordern.
    /// </summary>
    [JsonPropertyName("services")] public Dictionary<string, string> Services { get; set; } = new();

    [JsonPropertyName("max_streams")] public int MaxStreams { get; set; } = 32;
    [JsonPropertyName("dial_timeout_sec")] public int DialTimeoutSec { get; set; } = 5;
    [JsonPropertyName("reconnect_min_sec")] public int ReconnectMinSec { get; set; } = 1;
    [JsonPropertyName("reconnect_max_sec")] public int ReconnectMaxSec { get; set; } = 60;
    /// <summary>Ohne Lebenszeichen vom Relay gilt der Control-Kanal als tot. Muss ueber dessen ping_interval_sec liegen.</summary>
    [JsonPropertyName("control_timeout_sec")] public int ControlTimeoutSec { get; set; } = 120;
}

internal sealed class ClientConfig
{
    [JsonPropertyName("relay")] public string Relay { get; set; } = "";
    [JsonPropertyName("ca")] public string Ca { get; set; } = "";
    [JsonPropertyName("cert")] public string Cert { get; set; } = "";
    [JsonPropertyName("key")] public string Key { get; set; } = "";

    /// <summary>
    /// Dauerhaft eingerichtete Weiterleitungen. Ein einziger Prozess bedient
    /// beliebig viele Geraete und Dienste gleichzeitig; jede Weiterleitung hat
    /// ihren eigenen lokalen Port.
    /// </summary>
    [JsonPropertyName("forwards")] public Forward[] Forwards { get; set; } = [];
}

/// <summary>Ein lokaler Port, der auf einen Dienst eines Geraets zeigt.</summary>
internal sealed class Forward
{
    [JsonPropertyName("listen")] public string Listen { get; set; } = "";
    [JsonPropertyName("device")] public string Device { get; set; } = "";
    [JsonPropertyName("service")] public string Service { get; set; } = "";

    public override string ToString() => $"{Listen} -> {Device}/{Service}";

    /// <summary>Zerlegt die Kurzschreibweise "geraet/dienst=127.0.0.1:2201".</summary>
    public static Forward Parse(string spec)
    {
        var eq = spec.IndexOf('=');
        if (eq < 0) throw new FormatException($"'{spec}': erwartet geraet/dienst=adresse:port");
        var ziel = spec[..eq];
        var slash = ziel.IndexOf('/');
        if (slash < 0) throw new FormatException($"'{spec}': erwartet geraet/dienst=adresse:port");
        return new Forward
        {
            Device = ziel[..slash],
            Service = ziel[(slash + 1)..],
            Listen = spec[(eq + 1)..],
        };
    }
}

internal sealed class AclEntry
{
    /// <summary>Glob-Muster fuer Geraete-Ids, z.B. ["werk1-*"].</summary>
    [JsonPropertyName("devices")] public string[] Devices { get; set; } = [];
    /// <summary>Glob-Muster fuer Dienstnamen, z.B. ["ssh","http"].</summary>
    [JsonPropertyName("services")] public string[] Services { get; set; } = [];
}

/// <summary>Ein dem Relay bekanntes Geraet.</summary>
internal sealed class AclDevice
{
    /// <summary>Freitext fuer den Betreiber, erscheint in der Uebersicht. Etwa "Halle 2, IPC hinter Schaltschrank 4".</summary>
    [JsonPropertyName("note")] public string? Note { get; set; }

    /// <summary>
    /// Freigegebene Dienste dieses Geraets.
    ///
    ///   fehlt   alles freigegeben, was das Geraet anbietet
    ///   []      nichts freigegeben
    ///   ["ssh"] nur dieser Dienst, Muster mit * erlaubt
    ///
    /// Welche Adresse hinter einem Dienstnamen steht, entscheidet weiterhin
    /// allein das Geraet - der Relay gibt nur frei oder sperrt. Anders herum
    /// koennte ein uebernommener Relay ein Geraet auf beliebige Adressen im
    /// Anlagennetz zeigen lassen.
    /// </summary>
    [JsonPropertyName("services")] public string[]? Services { get; set; }

    public bool Freigegeben(string dienst) => Services is null || Glob.AnyMatch(Services, dienst);
}

internal sealed class Acl
{
    /// <summary>
    /// Geraeteliste. Ist sie vorhanden und nicht leer, darf sich nur anmelden,
    /// wer hier steht - ein Zertifikat der eigenen CA allein genuegt dann nicht.
    /// Fehlt sie, ist die Anmeldung fuer jedes Zertifikat der CA offen.
    /// </summary>
    [JsonPropertyName("devices")] public Dictionary<string, AclDevice>? Devices { get; set; }

    /// <summary>Client-Name (CN ohne Praefix) -> Berechtigung.</summary>
    [JsonPropertyName("clients")] public Dictionary<string, AclEntry> Clients { get; set; } = new();

    /// <summary>Gesperrte Identitaeten, volle CNs: "device:alt-hmi", "client:ex-monteur".</summary>
    [JsonPropertyName("revoked")] public string[] Revoked { get; set; } = [];

    public bool IsRevoked(string cn) =>
        Array.Exists(Revoked, r => string.Equals(r, cn, StringComparison.Ordinal));

    /// <summary>Steht ueberhaupt eine Geraeteliste bereit?</summary>
    public bool DeviceListActive => Devices is { Count: > 0 };

    /// <summary>
    /// Darf sich dieses Geraet anmelden? Ohne Liste entscheidet der Schalter
    /// aus der Relay-Konfiguration - und der sagt in der Vorgabe nein.
    /// </summary>
    public bool DeviceKnown(string device, bool ohneListeErlaubt) =>
        Devices is { Count: > 0 } liste ? liste.ContainsKey(device) : ohneListeErlaubt;

    /// <summary>Ist dieser Dienst dieses Geraets freigegeben?</summary>
    public bool ServiceReleased(string device, string service) =>
        Devices is null || !Devices.TryGetValue(device, out var d) || d.Freigegeben(service);

    public string? NoteFor(string device) =>
        Devices is not null && Devices.TryGetValue(device, out var d) ? d.Note : null;

    public bool Allows(string client, string device, string service)
    {
        if (!Clients.TryGetValue(client, out var e)) return false;
        return Glob.AnyMatch(e.Devices, device) && Glob.AnyMatch(e.Services, service);
    }
}

internal static class Cfg
{
    public static T Load<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> ti) where T : class
    {
        var text = File.ReadAllText(path);
        var v = JsonSerializer.Deserialize(text, ti)
                ?? throw new InvalidDataException($"{path}: leer");
        return v;
    }

    /// <summary>
    /// Pfade in der Konfiguration aufloesen: '~' wird zum Heimatverzeichnis,
    /// relative Angaben beziehen sich auf das Verzeichnis der Konfigurationsdatei.
    /// </summary>
    public static string Rel(string configPath, string p)
    {
        if (string.IsNullOrEmpty(p)) return p;
        if (p == "~" || p.StartsWith("~/", StringComparison.Ordinal))
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return p.Length <= 2 ? home : Path.Combine(home, p[2..]);
        }
        if (Path.IsPathRooted(p)) return p;
        var dir = Path.GetDirectoryName(Path.GetFullPath(configPath));
        return Path.Combine(dir ?? ".", p);
    }
}

/// <summary>Minimales Glob: nur '*' als Platzhalter fuer beliebige Zeichen.</summary>
internal static class Glob
{
    public static bool AnyMatch(string[] patterns, string value)
    {
        foreach (var p in patterns) if (Match(p, value)) return true;
        return false;
    }

    public static bool Match(string pattern, string value)
    {
        int p = 0, v = 0, star = -1, mark = 0;
        while (v < value.Length)
        {
            if (p < pattern.Length && (pattern[p] == '*'))
            {
                star = p++;
                mark = v;
            }
            else if (p < pattern.Length && pattern[p] == value[v])
            {
                p++; v++;
            }
            else if (star >= 0)
            {
                p = star + 1;
                v = ++mark;
            }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
