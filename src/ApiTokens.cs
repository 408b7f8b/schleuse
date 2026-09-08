using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Zugangsmarken der Schnittstelle
//
// Ein Mensch meldet sich mit Passwort und zweitem Faktor an. Ein Programm kann
// das nicht - es bekommt eine Marke: 256 zufaellige Bit, einmalig angezeigt und
// nur als Pruefsumme gespeichert. Wer die Datei liest, hat damit nichts.
//
// Marken werden ausdruecklich nicht als Keks angenommen und Kekse nicht als
// Marke. Sonst koennte eine fremde Seite den Browser eines angemeldeten
// Verwalters dazu bringen, Aufrufe der Schnittstelle mitzusenden.
// ---------------------------------------------------------------------------

internal sealed class ApiToken
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("role")] public WebRole Role { get; set; } = WebRole.Viewer;
    /// <summary>SHA-256 der Marke. Sie ist zufaellig genug, dass das genuegt.</summary>
    [JsonPropertyName("hash")] public string Hash { get; set; } = "";
    [JsonPropertyName("created")] public DateTimeOffset Created { get; set; }
    [JsonPropertyName("created_by")] public string CreatedBy { get; set; } = "";
    [JsonPropertyName("expires")] public DateTimeOffset? Expires { get; set; }
    [JsonPropertyName("last_used")] public DateTimeOffset? LastUsed { get; set; }
    [JsonPropertyName("last_from")] public string? LastFrom { get; set; }

    public bool Gueltig(DateTimeOffset jetzt) => Expires is null || jetzt < Expires;
}

internal sealed class ApiFile
{
    /// <summary>
    /// Ob die Weboberflaeche bedienbar ist. Laesst sich ueber die Schnittstelle
    /// umlegen - etwa um sie nach der Einrichtung dauerhaft abzuschalten und
    /// nur noch maschinell zu verwalten.
    /// </summary>
    [JsonPropertyName("ui_enabled")] public bool UiEnabled { get; set; } = true;

    [JsonPropertyName("tokens")] public List<ApiToken> Tokens { get; set; } = [];
}

internal sealed class ApiTokenStore(string path)
{
    /// <summary>Vorsatz, an dem eine Marke als solche erkennbar ist.</summary>
    public const string Prefix = "schleuse_";

    readonly Lock _gate = new();
    ApiFile _datei = Store.Load(path, JsonCfg.Default.ApiFile, () => new ApiFile());

    public bool UiEnabled { get { lock (_gate) return _datei.UiEnabled; } }

    /// <summary>Datei neu einlesen - fuer SIGHUP, nachdem jemand sie von aussen geaendert hat.</summary>
    public void NeuLaden()
    {
        lock (_gate) _datei = Store.Load(path, JsonCfg.Default.ApiFile, () => new ApiFile());
    }

    public void SetUiEnabled(bool an)
    {
        lock (_gate) { _datei.UiEnabled = an; Speichern(); }
    }

    public IReadOnlyList<ApiToken> Alle()
    {
        lock (_gate) return [.. _datei.Tokens.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>Legt eine Marke an und liefert sie im Klartext - das einzige Mal.</summary>
    public (ApiToken Eintrag, string Klartext) Anlegen(string name, WebRole rolle, int tage, string durch)
    {
        if (!UserStore.IstBrauchbarerName(name)) throw new InvalidOperationException("unusable name");

        var roh = RandomNumberGenerator.GetBytes(32);
        var klartext = Prefix + Base32.Encode(roh);
        var e = new ApiToken
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
            Name = name,
            Role = rolle,
            Hash = HashOf(klartext),
            Created = DateTimeOffset.UtcNow,
            CreatedBy = durch,
            Expires = tage > 0 ? DateTimeOffset.UtcNow.AddDays(tage) : null,
        };
        lock (_gate)
        {
            if (_datei.Tokens.Count >= 64) throw new InvalidOperationException("too many tokens");
            _datei.Tokens.Add(e);
            Speichern();
        }
        return (e, klartext);
    }

    public bool Loeschen(string id)
    {
        lock (_gate)
        {
            var weg = _datei.Tokens.RemoveAll(t => t.Id == id) > 0;
            if (weg) Speichern();
            return weg;
        }
    }

    /// <summary>
    /// Sucht die Marke zu einem vorgezeigten Wert. Gesucht wird ueber die
    /// Pruefsumme, nicht ueber den Wert selbst - die Laufzeit haengt damit nicht
    /// davon ab, wie weit ein Rateversuch gekommen ist.
    /// </summary>
    public ApiToken? Pruefe(string vorgezeigt, string von)
    {
        if (!vorgezeigt.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var hash = HashOf(vorgezeigt);

        lock (_gate)
        {
            var jetzt = DateTimeOffset.UtcNow;
            var t = _datei.Tokens.Find(x => CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(x.Hash),
                System.Text.Encoding.ASCII.GetBytes(hash)));

            if (t is null || !t.Gueltig(jetzt)) return null;

            // Nutzung nur festhalten, wenn sich etwas Nennenswertes geaendert
            // hat - sonst schriebe jeder Aufruf die Datei neu.
            if (t.LastUsed is null || jetzt - t.LastUsed > TimeSpan.FromMinutes(1) || t.LastFrom != von)
            {
                t.LastUsed = jetzt;
                t.LastFrom = von;
                Speichern();
            }
            return t;
        }
    }

    static string HashOf(string s) =>
        Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s)));

    void Speichern() => Store.Save(path, _datei, JsonCfg.Default.ApiFile);
}
