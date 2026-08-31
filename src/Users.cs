using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Schleuse;

[JsonConverter(typeof(JsonStringEnumConverter<WebRole>))]
internal enum WebRole
{
    /// <summary>Darf alles: freigeben, sperren, Benutzer verwalten.</summary>
    Admin,
    /// <summary>Darf sehen, aber nichts aendern.</summary>
    Viewer,
}

internal sealed class WebUser
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("password")] public string Password { get; set; } = "";
    [JsonPropertyName("role")] public WebRole Role { get; set; } = WebRole.Admin;

    /// <summary>TOTP-Geheimnis in Base32. Bis zur ersten bestaetigten Eingabe vorlaeufig.</summary>
    [JsonPropertyName("totp")] public string? Totp { get; set; }
    [JsonPropertyName("totp_confirmed")] public bool TotpConfirmed { get; set; }
    /// <summary>Zuletzt angenommenes Zeitfenster - verhindert die Wiederverwendung eines Codes.</summary>
    [JsonPropertyName("totp_last")] public long TotpLast { get; set; }

    /// <summary>Wiederherstellungscodes, als SHA-256. Sie sind zufaellig genug, dass das genuegt.</summary>
    [JsonPropertyName("recovery")] public List<string> Recovery { get; set; } = [];

    [JsonPropertyName("created")] public DateTimeOffset Created { get; set; }
    [JsonPropertyName("last_login")] public DateTimeOffset? LastLogin { get; set; }
    [JsonPropertyName("failed")] public int Failed { get; set; }
    [JsonPropertyName("locked_until")] public DateTimeOffset? LockedUntil { get; set; }
    /// <summary>Beim ersten Anmelden muss ein neues Passwort gesetzt werden.</summary>
    [JsonPropertyName("must_change")] public bool MustChange { get; set; }

    public bool Gesperrt(DateTimeOffset jetzt) => LockedUntil is { } bis && jetzt < bis;
    public bool ZweiFaktorFertig => TotpConfirmed && Totp is { Length: > 0 };
}

internal sealed class UserFile
{
    [JsonPropertyName("users")] public Dictionary<string, WebUser> Users { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Benutzerverwaltung der Weboberflaeche. Klein genug, dass alles im Speicher
/// liegt und jede Aenderung sofort auf die Platte geht.
/// </summary>
internal sealed class UserStore(string path)
{
    /// <summary>
    /// Ein Hash, gegen den geprueft wird, wenn es den Benutzer gar nicht gibt.
    /// Wird erst beim ersten Gebrauch gebildet: zum Zeitpunkt des Ladens steht
    /// die Rundenzahl aus der Konfiguration noch nicht fest, und ein Fehlversuch
    /// soll genauso viel kosten wie ein Treffer - nicht mehr.
    /// </summary>
    static readonly Lazy<string> Blindwert = new(() => Passwords.Hash("kein-benutzer"));

    readonly Lock _gate = new();
    UserFile _datei = Store.Load(path, JsonCfg.Default.UserFile, () => new UserFile());

    public bool Leer { get { lock (_gate) return _datei.Users.Count == 0; } }

    public IReadOnlyList<WebUser> Alle()
    {
        lock (_gate) return [.. _datei.Users.Values.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase)];
    }

    public WebUser? Finde(string name)
    {
        lock (_gate) return _datei.Users.GetValueOrDefault(name);
    }

    public int AnzahlAdmins()
    {
        lock (_gate) return _datei.Users.Values.Count(u => u.Role == WebRole.Admin);
    }

    public WebUser Anlegen(string name, string passwort, WebRole rolle, bool mussAendern)
    {
        if (!IstBrauchbarerName(name)) throw new InvalidOperationException("unbrauchbarer Benutzername");
        lock (_gate)
        {
            if (_datei.Users.ContainsKey(name)) throw new InvalidOperationException($"'{name}' gibt es schon");
            var u = new WebUser
            {
                Name = name,
                Password = Passwords.Hash(passwort),
                Role = rolle,
                Created = DateTimeOffset.UtcNow,
                MustChange = mussAendern,
            };
            _datei.Users[name] = u;
            Speichern();
            return u;
        }
    }

    public void Loeschen(string name)
    {
        lock (_gate)
        {
            if (!_datei.Users.TryGetValue(name, out var u)) return;
            if (u.Role == WebRole.Admin && _datei.Users.Values.Count(x => x.Role == WebRole.Admin) <= 1)
                throw new InvalidOperationException("der letzte Verwalter kann nicht geloescht werden");
            _datei.Users.Remove(name);
            Speichern();
        }
    }

    public void Aendern(string name, Action<WebUser> was)
    {
        lock (_gate)
        {
            if (!_datei.Users.TryGetValue(name, out var u)) throw new InvalidOperationException("unbekannter Benutzer");
            was(u);
            Speichern();
        }
    }

    /// <summary>
    /// Prueft das Passwort und fuehrt die Fehlversuche mit. Nach fuenf
    /// Fehlversuchen wird der Zugang zeitweise gesperrt, die Sperrdauer
    /// verdoppelt sich - aus einem Durchprobieren wird so schnell ein Warten.
    /// </summary>
    public (bool Ok, string? Grund) PruefePasswort(string name, string passwort)
    {
        lock (_gate)
        {
            var jetzt = DateTimeOffset.UtcNow;
            if (!_datei.Users.TryGetValue(name, out var u))
            {
                // Gleicher Aufwand wie bei einem echten Benutzer, damit die
                // Antwortzeit nicht verraet, wer existiert. Der Vergleichswert
                // wird einmal beim Start berechnet - ihn jedes Mal neu zu
                // bilden haette die Rechenlast eines Fehlversuchs verdoppelt.
                Passwords.Verify(Blindwert.Value, passwort);
                return (false, null);
            }
            if (u.Gesperrt(jetzt))
                return (false, $"Zugang gesperrt bis {u.LockedUntil:HH:mm} UTC");

            if (!Passwords.Verify(u.Password, passwort))
            {
                u.Failed++;
                if (u.Failed >= 5)
                {
                    var minuten = Math.Min(1440, 15 * (1 << Math.Min(6, u.Failed - 5)));
                    u.LockedUntil = jetzt.AddMinutes(minuten);
                }
                Speichern();
                return (false, null);
            }

            u.Failed = 0;
            u.LockedUntil = null;
            Speichern();
            return (true, null);
        }
    }

    public bool PruefeTotp(string name, string code)
    {
        lock (_gate)
        {
            if (!_datei.Users.TryGetValue(name, out var u) || u.Totp is not { Length: > 0 } b32) return false;
            if (!Base32.TryDecode(b32, out var secret)) return false;

            if (Totp.Verify(secret, code, DateTimeOffset.UtcNow, u.TotpLast, out var counter))
            {
                u.TotpLast = counter;
                u.TotpConfirmed = true;
                u.LastLogin = DateTimeOffset.UtcNow;
                Speichern();
                return true;
            }

            // Kein gueltiger Code - vielleicht ein Wiederherstellungscode.
            var hash = HashCode(code);
            var treffer = u.Recovery.FindIndex(r => CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(r), System.Text.Encoding.ASCII.GetBytes(hash)));
            if (treffer >= 0)
            {
                u.Recovery.RemoveAt(treffer);   // jeder Code gilt genau einmal
                u.LastLogin = DateTimeOffset.UtcNow;
                Speichern();
                Log.Warn("web", $"{name}: Anmeldung mit Wiederherstellungscode, {u.Recovery.Count} verbleiben");
                return true;
            }

            u.Failed++;
            if (u.Failed >= 5) u.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(15);
            Speichern();
            return false;
        }
    }

    /// <summary>Legt ein neues TOTP-Geheimnis an. Gilt erst, wenn es einmal bestaetigt wurde.</summary>
    public string NeuesTotp(string name)
    {
        var b32 = Base32.Encode(Totp.NewSecret());
        Aendern(name, u => { u.Totp = b32; u.TotpConfirmed = false; u.TotpLast = 0; });
        return b32;
    }

    /// <summary>Erzeugt neue Wiederherstellungscodes. Sie werden genau einmal angezeigt.</summary>
    public List<string> NeueWiederherstellung(string name, int anzahl = 8)
    {
        var codes = new List<string>(anzahl);
        for (int i = 0; i < anzahl; i++)
            codes.Add(Base32.Group(Base32.Encode(RandomNumberGenerator.GetBytes(10)), 4));
        Aendern(name, u => u.Recovery = [.. codes.Select(HashCode)]);
        return codes;
    }

    static string HashCode(string code)
    {
        var sauber = new string([.. code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant)]);
        return Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(sauber)));
    }

    public static bool IstBrauchbarerName(string s) =>
        s.Length is > 0 and <= 32 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    void Speichern() => Store.Save(path, _datei, JsonCfg.Default.UserFile);
}
