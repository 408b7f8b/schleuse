using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Schnittstelle
//
// Alles, was die Weboberflaeche kann, geht auch hierueber. Ausgewiesen wird sich
// mit einer Marke:
//
//     Authorization: Bearer schleuse_XXXXXXXX...
//
// Es gibt bewusst keine Selbstauskunft: kein Verzeichnis der Pfade, keine
// Beschreibung, keine Fehlermeldung, die verraet, ob es einen Pfad gibt. Ohne
// gueltige Marke antwortet jeder Pfad gleich - mit 404 und leerem Rumpf. Der
// Vorsatz aller Pfade ist frei waehlbar; das ist bequem, aber die eigentliche
// Absicherung ist und bleibt die Marke.
//
// Kekse gelten hier nicht. Eine angemeldete Sitzung im Browser darf die
// Schnittstelle nicht mitbenutzen koennen, sonst brauchte eine fremde Seite den
// Verwalter nur auf einen Link zu locken.
// ---------------------------------------------------------------------------

internal sealed partial class WebUi
{
    /// <summary>Fehlversuche je Herkunft, um Absuchen zu bremsen.</summary>
    readonly ConcurrentDictionary<string, (int Anzahl, DateTimeOffset Bis)> _fehlversuche = new();

    string ApiPath => "/" + cfg.ApiPath.Trim('/');

    bool IstApi(string pfad) =>
        pfad.Equals(ApiPath, StringComparison.Ordinal) ||
        pfad.StartsWith(ApiPath + "/", StringComparison.Ordinal);

    // -- Rahmenwerk ----------------------------------------------------------

    /// <summary>Die einzige Antwort auf alles, was nicht ausgewiesen ist.</summary>
    static Task Verbergen(HttpContext c)
    {
        c.Response.StatusCode = 404;
        c.Response.ContentLength = 0;
        return Task.CompletedTask;
    }

    static Task Gib<T>(HttpContext c, T wert, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> ti,
                       int code = 200)
    {
        c.Response.StatusCode = code;
        c.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(c.Response.Body, wert, ti);
    }

    static Task Fehler(HttpContext c, string text, int code = 400) =>
        Gib(c, new ApiError { Message = text }, ApiJson.Default.ApiError, code);

    static Task Erledigt(HttpContext c, string? text = null, string? geheim = null) =>
        Gib(c, new ApiOk { Message = text, Secret = geheim }, ApiJson.Default.ApiOk);

    async Task<ApiRequest?> Rumpf(HttpContext c)
    {
        if (c.Request.ContentType is not { } ct || !ct.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            await Fehler(c, "Content-Type application/json erwartet").ConfigureAwait(false);
            return null;
        }
        try
        {
            var r = await JsonSerializer.DeserializeAsync(c.Request.Body, ApiJson.Default.ApiRequest,
                                                          c.RequestAborted).ConfigureAwait(false);
            if (r is null) { await Fehler(c, "leerer Rumpf").ConfigureAwait(false); return null; }
            return r;
        }
        catch (JsonException e)
        {
            await Fehler(c, "ungültiges JSON: " + e.Message).ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>
    /// Weist die Marke aus. Liefert null, wenn nicht - dann wurde bereits eine
    /// nichtssagende Antwort geschrieben.
    /// </summary>
    async Task<ApiToken?> Ausweis(HttpContext c)
    {
        var von = c.Connection.RemoteIpAddress?.ToString() ?? "?";
        var kopf = c.Request.Headers.Authorization.ToString();
        var wert = kopf.StartsWith("Bearer ", StringComparison.Ordinal) ? kopf[7..].Trim() : "";

        var t = wert.Length == 0 ? null : _marken.Pruefe(wert, von);
        if (t is not null)
        {
            // Eine gueltige Marke kommt immer durch. Die Bremse darf nur den
            // Fehlversuch treffen - sonst sperrte hinter einem NAT ein einziger
            // Stoerer alle anderen mit aus.
            _fehlversuche.TryRemove(von, out _);
            return t;
        }

        await Task.Delay(Bremse(von)).ConfigureAwait(false);
        await Verbergen(c).ConfigureAwait(false);
        return null;
    }

    /// <summary>
    /// Wartezeit fuer einen Fehlversuch: erst ein Viertel, nach zehn Versuchen
    /// aus derselben Richtung bis zu zwei Sekunden. Gegen eine 256-Bit-Marke ist
    /// Durchprobieren ohnehin aussichtslos; das hier haelt vor allem das
    /// Protokoll und die Maschine frei.
    /// </summary>
    /// <param name="nurLesen">
    /// Nur nachsehen, wie hoch die Strafe steht, ohne sie zu erhoehen. So laesst
    /// sich vor einer teuren Pruefung entscheiden, ob sie ueberhaupt lohnt.
    /// </param>
    internal TimeSpan Bremse(string von, bool nurLesen = false)
    {
        if (nurLesen)
            return _fehlversuche.TryGetValue(von, out var stand) && DateTimeOffset.UtcNow < stand.Bis
                   ? TimeSpan.FromMilliseconds(stand.Anzahl < 10 ? 250 : 2000)
                   : TimeSpan.Zero;

        // Sonst wuechse die Tabelle beim Absuchen mit jeder neuen Herkunft.
        if (_fehlversuche.Count > 4096)
        {
            var jetzt0 = DateTimeOffset.UtcNow;
            foreach (var (k, v) in _fehlversuche)
                if (jetzt0 > v.Bis) _fehlversuche.TryRemove(k, out _);
        }

        var e = _fehlversuche.AddOrUpdate(von,
            _ => (1, DateTimeOffset.UtcNow.AddMinutes(5)),
            (_, alt) => DateTimeOffset.UtcNow > alt.Bis
                        ? (1, DateTimeOffset.UtcNow.AddMinutes(5))
                        : (alt.Anzahl + 1, alt.Bis));

        // Nur an der Schwelle protokollieren, damit ein Absuchen das Log nicht flutet.
        if (e.Anzahl == 10) Log.Warn("api", $"{von}: zehn Fehlversuche an der Schnittstelle");

        return TimeSpan.FromMilliseconds(e.Anzahl < 10 ? 250 : 2000);
    }

    // -- Verteilung ----------------------------------------------------------

    async Task ApiVerteile(HttpContext c)
    {
        var t = await Ausweis(c).ConfigureAwait(false);
        if (t is null) return;

        var pfad = (c.Request.Path.Value ?? "")[ApiPath.Length..];
        if (pfad.Length == 0) pfad = "/";
        var post = HttpMethods.IsPost(c.Request.Method);
        var schreiben = t.Role == WebRole.Admin;

        // Lesende Pfade
        if (!post)
        {
            switch (pfad)
            {
                case "/status":  await ApiStatusAusgeben(c); return;
                case "/devices": await ApiGeraete(c); return;
                case "/pending": await ApiWarteschlange(c); return;
                case "/clients": await ApiZugaenge(c); return;
                case "/users":   await ApiBenutzer(c); return;
                case "/tokens":  await ApiMarken(c); return;
                default: await Verbergen(c).ConfigureAwait(false); return;
            }
        }

        // Aendernde Pfade - nur mit Verwalterrolle. Existiert der Pfad nicht,
        // gibt es dieselbe nichtssagende Antwort wie sonst auch.
        if (!Bekannt(pfad)) { await Verbergen(c).ConfigureAwait(false); return; }
        if (!schreiben)
        {
            await Fehler(c, "diese Marke darf nur lesen", 403).ConfigureAwait(false);
            return;
        }

        var r = await Rumpf(c).ConfigureAwait(false);
        if (r is null) return;

        try
        {
            switch (pfad)
            {
                case "/pending/approve": await ApiFreigeben(c, r, t); return;
                case "/pending/reject":  await ApiAntragEntscheiden(c, r, t, ablehnen: true); return;
                case "/pending/delete":  await ApiAntragEntscheiden(c, r, t, ablehnen: false); return;
                case "/devices/save":    await ApiGeraetSpeichern(c, r, t); return;
                case "/devices/delete":  await ApiGeraetLoeschen(c, r, t); return;
                case "/clients/save":    await ApiZugangSpeichern(c, r, t); return;
                case "/clients/delete":  await ApiZugangLoeschen(c, r, t); return;
                case "/users/add":       await ApiBenutzerAnlegen(c, r, t); return;
                case "/users/delete":    await ApiBenutzerLoeschen(c, r, t); return;
                case "/users/reset":     await ApiBenutzerZuruecksetzen(c, r, t); return;
                case "/tokens/create":   await ApiMarkeAnlegen(c, r, t); return;
                case "/tokens/delete":   await ApiMarkeLoeschen(c, r, t); return;
                case "/ui":              await ApiUiSchalten(c, r, t); return;
            }
        }
        catch (InvalidOperationException e)
        {
            await Fehler(c, e.Message).ConfigureAwait(false);
        }
        catch (ProtocolException e)
        {
            await Fehler(c, e.Message).ConfigureAwait(false);
        }
    }

    static bool Bekannt(string pfad) => pfad is
        "/pending/approve" or "/pending/reject" or "/pending/delete" or
        "/devices/save" or "/devices/delete" or
        "/clients/save" or "/clients/delete" or
        "/users/add" or "/users/delete" or "/users/reset" or
        "/tokens/create" or "/tokens/delete" or "/ui";

    // -- Lesen ---------------------------------------------------------------

    Task ApiStatusAusgeben(HttpContext c) => Gib(c, new ApiStatus
    {
        UiEnabled = _marken.UiEnabled,
        Enrollment = relay.Issuer is not null,
        DeviceListActive = relay.CurrentAcl.DeviceListActive || !relay.AllowUnlistedDevices,
        CaPin = Fingerprint.OfCertificate(relay.RootCa),
        RelayListen = relay.ListenAddress,
        DevicesOnline = relay.Online().Count,
        Pending = relay.Pending?.Alle().Count(x => x.State == PendingState.Pending) ?? 0,
        Tunnels = [.. relay.Tunnels().Select(x => new ApiTunnel
        {
            Client = x.Client, Device = x.Device, Service = x.Service,
        })],
    }, ApiJson.Default.ApiStatus);

    Task ApiGeraete(HttpContext c)
    {
        var acl = relay.CurrentAcl;
        var online = relay.Online().ToDictionary(d => d.Device, d => d, StringComparer.Ordinal);
        var namen = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var k in (IEnumerable<string>?)acl.Devices?.Keys ?? []) namen.Add(k);
        foreach (var k in online.Keys) namen.Add(k);

        return Gib(c, new ApiDevices
        {
            Devices = [.. namen.Select(n =>
            {
                var d = acl.Devices?.GetValueOrDefault(n);
                var an = online.GetValueOrDefault(n);
                return new ApiDevice
                {
                    Device = n,
                    Note = d?.Note,
                    Released = d?.Services,
                    Offered = an?.Services ?? [],
                    Online = an is not null,
                    OnlineSec = an?.OnlineSec ?? 0,
                    Streams = an?.Streams ?? 0,
                    Revoked = acl.IsRevoked(Tls.DevicePrefix + n),
                };
            })],
        }, ApiJson.Default.ApiDevices);
    }

    Task ApiWarteschlange(HttpContext c)
    {
        var alle = relay.Pending?.Alle() ?? [];
        return Gib(c, new ApiPending
        {
            Requests = [.. alle.Select(r => new ApiPendingEntry
            {
                Id = r.Id,
                Fingerprint = r.Fingerprint,
                Hostname = r.Hostname,
                From = r.From,
                FirstSeen = r.FirstSeen,
                LastSeen = r.LastSeen,
                State = r.State.ToString().ToLowerInvariant(),
                Proposed = r.Proposed,
                Device = r.Device,
                DecidedBy = r.DecidedBy,
                DecidedAt = r.DecidedAt,
            })],
        }, ApiJson.Default.ApiPending);
    }

    Task ApiZugaenge(HttpContext c)
    {
        var acl = relay.CurrentAcl;
        return Gib(c, new ApiClients
        {
            Clients = [.. acl.Clients.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => new ApiClient
            {
                Client = kv.Key,
                Devices = kv.Value.Devices,
                Services = kv.Value.Services,
                Revoked = acl.IsRevoked(Tls.ClientPrefix + kv.Key),
            })],
        }, ApiJson.Default.ApiClients);
    }

    Task ApiBenutzer(HttpContext c) => Gib(c, new ApiUsers
    {
        Users = [.. _users.Alle().Select(u => new ApiUser
        {
            User = u.Name,
            Role = u.Role.ToString().ToLowerInvariant(),
            Totp = u.ZweiFaktorFertig,
            RecoveryLeft = u.Recovery.Count,
            LastLogin = u.LastLogin,
            LockedUntil = u.LockedUntil,
            MustChange = u.MustChange,
        })],
    }, ApiJson.Default.ApiUsers);

    Task ApiMarken(HttpContext c) => Gib(c, new ApiTokens
    {
        Tokens = [.. _marken.Alle().Select(t => new ApiTokenInfo
        {
            Id = t.Id,
            Name = t.Name,
            Role = t.Role.ToString().ToLowerInvariant(),
            Created = t.Created,
            CreatedBy = t.CreatedBy,
            Expires = t.Expires,
            LastUsed = t.LastUsed,
            LastFrom = t.LastFrom,
        })],
    }, ApiJson.Default.ApiTokens);

    // -- Aendern -------------------------------------------------------------

    static string Pflicht(string? wert, string name) =>
        wert is { Length: > 0 } ? wert : throw new InvalidOperationException($"'{name}' fehlt");

    /// <summary>
    /// Freitext aus der Schnittstelle: gekuerzt und von Steuerzeichen befreit.
    /// Er landet in einer Datei, in Logzeilen und auf einer Webseite - an jeder
    /// dieser Stellen waere unbegrenzter Fremdtext eine Zumutung.
    /// </summary>
    static string? Text(string? s, int max)
    {
        if (s is null) return null;
        // Erst kuerzen, dann saeubern - nicht umgekehrt: sonst liefe die
        // Saeuberung ueber die volle Laenge der Anfrage.
        return Log.Clean(s.Length > max ? s[..max] : s);
    }

    /// <summary>Musterliste: begrenzte Anzahl, nur die Zeichen, die ein Muster braucht.</summary>
    static string[] Muster(string[]? a, int hoechstens = 64) =>
        a is null ? [] :
        [.. a.Take(hoechstens)
             .Where(x => x.Length is > 0 and <= 64
                      && x.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '.' or '*'))];

    async Task ApiFreigeben(HttpContext c, ApiRequest r, ApiToken t)
    {
        if (relay.Pending is null || relay.Issuer is null)
            throw new InvalidOperationException("die Selbstanmeldung ist nicht eingerichtet");

        var id = Pflicht(r.Id, "id");
        var device = Pflicht(r.Device, "device");
        var antrag = relay.Pending.ById(id) ?? throw new InvalidOperationException("Antrag nicht gefunden");

        // Fehlt die Angabe, gilt alles, was das Geraet vorgeschlagen hat.
        var gewuenscht = r.Services ?? [.. antrag.Proposed.Keys];
        var erlaubt = gewuenscht.Where(antrag.Proposed.ContainsKey)
                                .ToDictionary(x => x, x => antrag.Proposed[x], StringComparer.Ordinal);

        var e = relay.Pending.Freigeben(id, device, erlaubt, relay.Issuer, "token:" + t.Name);

        relay.UpdateAcl(acl =>
            {
            acl.Devices ??= new Dictionary<string, AclDevice>(StringComparer.Ordinal);
            acl.Devices[device] = new AclDevice
            {
            Note = string.IsNullOrWhiteSpace(r.Note) ? null : Text(r.Note, 200),
            Services = erlaubt.Count == 0 ? [] : [.. erlaubt.Keys],
            };
            acl.Revoked = [.. acl.Revoked.Where(x => x != Tls.DevicePrefix + device)];
        });

        Log.Info("api", $"{t.Name}: Gerät '{device}' freigegeben (Fingerabdruck {e.Fingerprint})");
        await Erledigt(c, $"'{device}' freigegeben").ConfigureAwait(false);
    }

    async Task ApiAntragEntscheiden(HttpContext c, ApiRequest r, ApiToken t, bool ablehnen)
    {
        if (relay.Pending is null) throw new InvalidOperationException("die Selbstanmeldung ist nicht eingerichtet");
        var id = Pflicht(r.Id, "id");
        if (ablehnen)
        {
            relay.Pending.Ablehnen(id, "token:" + t.Name);
            Log.Warn("api", $"{t.Name}: Antrag {id} abgelehnt");
            await Erledigt(c, "abgelehnt").ConfigureAwait(false);
        }
        else
        {
            if (!relay.Pending.Loeschen(id)) throw new InvalidOperationException("Antrag nicht gefunden");
            await Erledigt(c, "entfernt").ConfigureAwait(false);
        }
    }

    async Task ApiGeraetSpeichern(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.Device, "device");
        if (!Tls.IsSaneName(name)) throw new InvalidOperationException("unbrauchbarer Gerätename");

        var note = Text(r.Note, 200);
        var dienste = r.Services is null ? null : Muster(r.Services).Where(Tls.IsSaneName).ToArray();

        relay.UpdateAcl(acl =>
            {
            acl.Devices ??= new Dictionary<string, AclDevice>(StringComparer.Ordinal);
            if (!acl.Devices.TryGetValue(name, out var d)) acl.Devices[name] = d = new AclDevice();
            if (note is not null) d.Note = note.Length == 0 ? null : note;
            if (dienste is not null) d.Services = dienste;
            if (r.Revoked is { } gesperrt)
                acl.Revoked = Sperrliste(acl.Revoked, Tls.DevicePrefix + name, gesperrt);
        });
        Log.Info("api", $"{t.Name}: Gerät '{name}' geändert");
        await Erledigt(c, $"'{name}' gespeichert").ConfigureAwait(false);
    }

    async Task ApiGeraetLoeschen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.Device, "device");
        relay.UpdateAcl(acl =>
            {
            if (acl.Devices?.Remove(name) != true) throw new InvalidOperationException("Gerät nicht in der Liste");
        });
        Log.Warn("api", $"{t.Name}: Gerät '{name}' entfernt");
        await Erledigt(c, $"'{name}' entfernt").ConfigureAwait(false);
    }

    async Task ApiZugangSpeichern(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.Client, "client");
        if (!Tls.IsSaneName(name)) throw new InvalidOperationException("unbrauchbarer Name");

        var geraete = r.Devices is null ? null : Muster(r.Devices);
        var dienste = r.Services is null ? null : Muster(r.Services);

        relay.UpdateAcl(acl =>
            {
            var alt = acl.Clients.GetValueOrDefault(name);
            acl.Clients[name] = new AclEntry
            {
                Devices = geraete ?? alt?.Devices ?? [],
                Services = dienste ?? alt?.Services ?? [],
            };
            if (r.Revoked is { } gesperrt)
                acl.Revoked = Sperrliste(acl.Revoked, Tls.ClientPrefix + name, gesperrt);
        });
        Log.Info("api", $"{t.Name}: Zugang '{name}' gespeichert");
        await Erledigt(c, $"'{name}' gespeichert").ConfigureAwait(false);
    }

    async Task ApiZugangLoeschen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.Client, "client");
        relay.UpdateAcl(acl =>
            {
            if (!acl.Clients.Remove(name)) throw new InvalidOperationException("Zugang nicht gefunden");
        });
        Log.Warn("api", $"{t.Name}: Zugang '{name}' entfernt");
        await Erledigt(c, $"'{name}' entfernt").ConfigureAwait(false);
    }

    static WebRole Rolle(string? s) =>
        string.Equals(s, "viewer", StringComparison.OrdinalIgnoreCase) ? WebRole.Viewer : WebRole.Admin;

    async Task ApiBenutzerAnlegen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.User, "user");
        var pw = Passwords.Suggest();
        _users.Anlegen(name, pw, Rolle(r.Role), mussAendern: true);
        Log.Info("api", $"{t.Name}: Benutzer '{name}' angelegt");
        await Erledigt(c, $"'{name}' angelegt - der zweite Faktor wird beim ersten Anmelden eingerichtet",
                       geheim: pw).ConfigureAwait(false);
    }

    async Task ApiBenutzerLoeschen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.User, "user");
        _users.Loeschen(name);
        _sitzungen.BeendeAlle(name);
        Log.Warn("api", $"{t.Name}: Benutzer '{name}' gelöscht");
        await Erledigt(c, $"'{name}' gelöscht").ConfigureAwait(false);
    }

    async Task ApiBenutzerZuruecksetzen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.User, "user");
        if (_users.Finde(name) is null) throw new InvalidOperationException("unbekannter Benutzer");

        if (string.Equals(r.What, "2fa", StringComparison.OrdinalIgnoreCase))
        {
            _users.Aendern(name, u => { u.Totp = null; u.TotpConfirmed = false; u.TotpLast = 0; u.Recovery.Clear(); });
            _sitzungen.BeendeAlle(name);
            Log.Warn("api", $"{t.Name}: zweiter Faktor von '{name}' zurückgesetzt");
            await Erledigt(c, "zweiter Faktor zurückgesetzt").ConfigureAwait(false);
            return;
        }

        var pw = Passwords.Suggest();
        _users.Aendern(name, u => { u.Password = Passwords.Hash(pw); u.MustChange = true; u.Failed = 0; u.LockedUntil = null; });
        _sitzungen.BeendeAlle(name);
        Log.Warn("api", $"{t.Name}: Passwort von '{name}' zurückgesetzt");
        await Erledigt(c, "Passwort zurückgesetzt", geheim: pw).ConfigureAwait(false);
    }

    async Task ApiMarkeAnlegen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var name = Pflicht(r.Name, "name");
        (ApiToken e, string klartext) = _marken.Anlegen(name, Rolle(r.Role), Math.Clamp(r.Days ?? 0, 0, 3650), "token:" + t.Name);
        Log.Info("api", $"{t.Name}: Marke '{name}' angelegt ({e.Role}, id {e.Id})");
        await Erledigt(c, $"Marke '{name}' angelegt - sie wird nur dieses eine Mal angezeigt",
                       geheim: klartext).ConfigureAwait(false);
    }

    async Task ApiMarkeLoeschen(HttpContext c, ApiRequest r, ApiToken t)
    {
        var id = Pflicht(r.Id, "id");
        if (!_marken.Loeschen(id)) throw new InvalidOperationException("Marke nicht gefunden");
        Log.Warn("api", $"{t.Name}: Marke {id} zurückgezogen");
        await Erledigt(c, "zurückgezogen").ConfigureAwait(false);
    }

    async Task ApiUiSchalten(HttpContext c, ApiRequest r, ApiToken t)
    {
        var an = r.Enabled ?? throw new InvalidOperationException("'enabled' fehlt");
        _marken.SetUiEnabled(an);
        if (!an) _sitzungen.AlleBeenden();
        Log.Warn("api", $"{t.Name}: Weboberfläche {(an ? "eingeschaltet" : "abgeschaltet")}");
        await Erledigt(c, an
            ? "die Weboberfläche ist wieder bedienbar"
            : "die Weboberfläche ist abgeschaltet; sie lässt sich hierüber oder mit " +
              "'schleuse ui -c <relay.json> -on' wieder einschalten").ConfigureAwait(false);
    }
}
