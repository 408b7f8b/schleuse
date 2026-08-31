using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Schleuse;

/// <summary>
/// Sitzungen der Weboberflaeche. Nur im Speicher: ein Neustart des Relays
/// meldet alle ab, und das ist die richtige Voreinstellung fuer ein
/// Verwaltungspanel.
/// </summary>
internal sealed class WebSession
{
    public required string Id { get; init; }
    public required string User { get; init; }
    public WebRole Role { get; set; }
    /// <summary>Solange falsch, ist erst das Passwort geprueft, nicht der zweite Faktor.</summary>
    public bool TotpDone { get; set; }
    public string Csrf { get; init; } = Neuer();
    public DateTimeOffset Created { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Wird einmalig angezeigt (Anfangspasswort, Wiederherstellungscodes) und dann vergessen.</summary>
    public string? Einmalig { get; set; }

    public static string Neuer() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
}

internal sealed class SessionStore
{
    /// <summary>Nach dieser Zeit ohne Zutun ist Schluss.</summary>
    public static readonly TimeSpan Idle = TimeSpan.FromMinutes(30);
    /// <summary>Und spaetestens dann in jedem Fall.</summary>
    public static readonly TimeSpan Absolut = TimeSpan.FromHours(12);

    readonly ConcurrentDictionary<string, WebSession> _s = new(StringComparer.Ordinal);

    public WebSession Anlegen(string user, WebRole rolle, bool totpFertig)
    {
        Aufraeumen();
        var s = new WebSession { Id = WebSession.Neuer(), User = user, Role = rolle, TotpDone = totpFertig };
        _s[s.Id] = s;
        return s;
    }

    public WebSession? Hole(string? id)
    {
        if (id is null || !_s.TryGetValue(id, out var s)) return null;
        var jetzt = DateTimeOffset.UtcNow;
        if (jetzt - s.LastSeen > Idle || jetzt - s.Created > Absolut) { _s.TryRemove(id, out _); return null; }
        s.LastSeen = jetzt;
        return s;
    }

    /// <summary>
    /// Neue Kennung nach jedem Schritt der Anmeldung. Wer vorher eine Kennung
    /// untergeschoben hat, kann damit nichts anfangen.
    /// </summary>
    public WebSession Erneuern(WebSession alt)
    {
        _s.TryRemove(alt.Id, out _);
        var neu = new WebSession
        {
            Id = WebSession.Neuer(),
            User = alt.User,
            Role = alt.Role,
            TotpDone = alt.TotpDone,
            Einmalig = alt.Einmalig,
        };
        _s[neu.Id] = neu;
        return neu;
    }

    public void Beenden(string id) => _s.TryRemove(id, out _);

    /// <summary>Alle Sitzungen eines Benutzers beenden - etwa nach einem Passwortwechsel.</summary>
    public void BeendeAlle(string user)
    {
        foreach (var (k, v) in _s)
            if (string.Equals(v.User, user, StringComparison.OrdinalIgnoreCase)) _s.TryRemove(k, out _);
    }

    public int Anzahl => _s.Count;

    /// <summary>Alles abmelden - etwa wenn die Oberflaeche abgeschaltet wird.</summary>
    public void AlleBeenden() => _s.Clear();

    void Aufraeumen()
    {
        var jetzt = DateTimeOffset.UtcNow;
        foreach (var (k, v) in _s)
            if (jetzt - v.LastSeen > Idle || jetzt - v.Created > Absolut) _s.TryRemove(k, out _);
    }
}
