using Microsoft.AspNetCore.Http;

namespace Schleuse;

// Die Seiten der Weboberflaeche. Jede baut ihre Zeichenkette selbst; alles, was
// von aussen kommt, geht durch Html.E.
internal sealed partial class WebUi
{
    static string Csrf(WebSession s) => $"""<input type="hidden" name="csrf" value="{Html.E(s.Csrf)}">""";
    static string Zeit(DateTimeOffset t) => t.ToLocalTime().ToString("dd.MM.yyyy HH:mm");

    // -- Warteschlange -------------------------------------------------------

    async Task Warteschlange(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        if (relay.Pending is null)
        {
            await Sende(c, Html.Seite("Warteschlange", s, """
                <h1>Warteschlange</h1>
                <p class="lead">Die Selbstanmeldung ist nicht eingerichtet.</p>
                <div class="karte">
                <p>Damit sich Geräte selbst anmelden können, braucht der Relay eine
                   Zwischen-CA. Sie wird einmalig auf einem sicheren Rechner erzeugt:</p>
                <pre>./schleuse-pki.sh device-ca</pre>
                <p>Danach <code>device-ca.crt</code> und <code>device-ca.key</code> auf den
                   Relay legen und in <code>relay.json</code> eintragen:</p>
                <pre>"enrollment": { "ca": "device-ca.crt", "key": "device-ca.key" }</pre>
                <p class="schwach">Der Schlüssel der Wurzel-CA bleibt dabei offline. Die
                   Zwischen-CA kann nur Geräte ausstellen, keine Zugänge.</p>
                </div>
                """, hinweis, fehler)).ConfigureAwait(false);
            return;
        }

        var alle = relay.Pending.Alle();
        var offen = alle.Where(r => r.State == PendingState.Pending)
                        .OrderBy(r => r.FirstSeen).ToList();
        var erledigt = alle.Where(r => r.State != PendingState.Pending)
                           .OrderByDescending(r => r.DecidedAt ?? r.LastSeen).Take(20).ToList();

        var inhalt = new System.Text.StringBuilder();
        inhalt.Append($"""
            <h1>Warteschlange</h1>
            <p class="lead">Neu angemeldete Geräte warten hier. Solange sie warten, haben
               sie kein Zertifikat und erreichen nichts.</p>
            """);

        if (offen.Count == 0)
            inhalt.Append("""<p class="schwach">Zurzeit wartet nichts.</p>""");

        foreach (var r in offen)
        {
            var vorschlag = Vorschlag(r.Hostname);
            var dienste = r.Proposed.Count == 0
                ? """
                  <p class="schwach">Das Gerät hat keine Dienste vorgeschlagen. Es kann dann
                     nichts anbieten, bis seine Konfiguration ergänzt wird.</p>
                  """
                : string.Concat(r.Proposed.Select(kv => $"""
                    <label style="display:inline-block;margin-right:1.2rem">
                      <input type="checkbox" name="svc" value="{Html.E(kv.Key)}" checked>
                      <code>{Html.E(kv.Key)}</code>
                      <span class="schwach">&rarr; {Html.E(kv.Value)}</span>
                    </label>
                    """));

            inhalt.Append($"""
                <div class="karte">
                  <p class="schwach">Fingerabdruck des Schlüssels &mdash; muss mit dem übereinstimmen,
                     den das Gerät beim Anmelden angezeigt hat</p>
                  <p class="fp">{Html.E(r.Fingerprint)}</p>
                  <table>
                    <tr><th>Selbstauskunft</th><td>{Html.E(r.Hostname ?? "(keine)")}</td></tr>
                    <tr><th>Herkunft</th><td class="mono">{Html.E(r.From)}</td></tr>
                    <tr><th>Seit</th><td>{Zeit(r.FirstSeen)}</td></tr>
                  </table>
                  <form method="post" action="/pending/approve">
                    {Csrf(s)}
                    <input type="hidden" name="id" value="{Html.E(r.Id)}">
                    <label>Name des Geräts</label>
                    <input type="text" name="device" class="klein" value="{Html.E(vorschlag)}"
                           maxlength="64" pattern="[A-Za-z0-9._-]+" required>
                    <label>Notiz</label>
                    <input type="text" name="note" placeholder="Halle 2, Schaltschrank 4">
                    <label>Freigegebene Dienste</label>
                    {dienste}
                    <p>
                      <button>Freigeben</button>
                    </p>
                  </form>
                  <form method="post" action="/pending/reject" class="inline">
                    {Csrf(s)}<input type="hidden" name="id" value="{Html.E(r.Id)}">
                    <button class="gefahr">Ablehnen</button>
                  </form>
                </div>
                """);
        }

        if (erledigt.Count > 0)
        {
            inhalt.Append("""
                <h2>Zuletzt entschieden</h2>
                <table><tr><th>Fingerabdruck</th><th>Gerät</th><th>Ergebnis</th>
                           <th>Durch</th><th>Wann</th><th></th></tr>
                """);
            foreach (var r in erledigt)
                inhalt.Append($"""
                    <tr><td class="mono">{Html.E(r.Fingerprint)}</td>
                        <td class="mono">{Html.E(r.Device ?? "-")}</td>
                        <td>{(r.State == PendingState.Approved ? "<span class=\"an\">freigegeben</span>" : "<span class=\"aus\">abgelehnt</span>")}</td>
                        <td>{Html.E(r.DecidedBy)}</td>
                        <td>{(r.DecidedAt is { } t ? Zeit(t) : "")}</td>
                        <td><form method="post" action="/pending/delete" class="inline">
                            {Csrf(s)}<input type="hidden" name="id" value="{Html.E(r.Id)}">
                            <button class="link">entfernen</button></form></td></tr>
                    """);
            inhalt.Append("</table>");
        }

        await Sende(c, Html.Seite("Warteschlange", s, inhalt.ToString(), hinweis, fehler)).ConfigureAwait(false);
    }

    /// <summary>Aus der Selbstauskunft einen brauchbaren Namen vorschlagen.</summary>
    static string Vorschlag(string? hostname)
    {
        if (hostname is null) return "";
        var kurz = hostname.Split('.')[0];
        var sauber = new string([.. kurz.Where(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_')]);
        return sauber.Length is > 0 and <= 64 ? sauber.ToLowerInvariant() : "";
    }

    async Task Freigeben(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;
        if (relay.Pending is null || relay.Issuer is null) { await Weiter(c, "/pending").ConfigureAwait(false); return; }

        var id = Feld(f, "id", 32);
        var device = Feld(f, "device", 64);
        var note = Feld(f, "note", 200);
        var dienste = f["svc"].Where(x => x is not null).Select(x => x!).ToArray();

        try
        {
            var antrag = relay.Pending.ById(id) ?? throw new InvalidOperationException("Antrag nicht gefunden");
            var erlaubt = dienste.Where(d => antrag.Proposed.ContainsKey(d))
                                 .ToDictionary(d => d, d => antrag.Proposed[d], StringComparer.Ordinal);

            var e = relay.Pending.Freigeben(id, device, erlaubt, relay.Issuer, s.User);

            // Und in die Geraeteliste eintragen, sonst wuerde die Anmeldung
            // gleich wieder abgewiesen.
            relay.UpdateAcl(acl =>
            {
            acl.Devices ??= new Dictionary<string, AclDevice>(StringComparer.Ordinal);
            acl.Devices[device] = new AclDevice
            {
                Note = note.Length == 0 ? null : note,
                Services = erlaubt.Count == 0 ? [] : [.. erlaubt.Keys],
            };
            acl.Revoked = [.. acl.Revoked.Where(x => x != Tls.DevicePrefix + device)];
            });

            Log.Info("web", $"{s.User}: Gerät '{device}' freigegeben (Fingerabdruck {e.Fingerprint})");
            await Warteschlange(c, $"'{device}' ist freigegeben. Das Gerät holt sein Zertifikat " +
                                   "bei der nächsten Nachfrage ab.", null).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ProtocolException)
        {
            await Warteschlange(c, null, ex.Message).ConfigureAwait(false);
        }
    }

    async Task Entscheiden(HttpContext c, bool ablehnen)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;
        if (relay.Pending is null) { await Weiter(c, "/pending").ConfigureAwait(false); return; }

        var id = Feld(f, "id", 32);
        try
        {
            if (ablehnen) { relay.Pending.Ablehnen(id, s.User); Log.Warn("web", $"{s.User}: Antrag {id} abgelehnt"); }
            else relay.Pending.Loeschen(id);
            await Warteschlange(c, ablehnen ? "Antrag abgelehnt." : "Eintrag entfernt.", null).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            await Warteschlange(c, null, ex.Message).ConfigureAwait(false);
        }
    }

    // -- Geraete -------------------------------------------------------------

    async Task Geraete(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        var acl = relay.CurrentAcl;
        var online = relay.Online().ToDictionary(d => d.Device, d => d, StringComparer.Ordinal);
        var pin = Fingerprint.OfCertificate(relay.RootCa);
        var liste = acl.Devices ?? new Dictionary<string, AclDevice>(StringComparer.Ordinal);

        var zeilen = new System.Text.StringBuilder();
        foreach (var (name, d) in liste.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var an = online.GetValueOrDefault(name);
            var gesperrt = acl.IsRevoked(Tls.DevicePrefix + name);
            var angeboten = an?.Services ?? [];

            var kaesten = angeboten.Length == 0
                ? """<span class="schwach">nicht verbunden &ndash; Dienste unbekannt</span>"""
                : string.Concat(angeboten.Select(x => $"""
                    <label style="display:inline-block;margin-right:1rem">
                      <input type="checkbox" name="svc" value="{Html.E(x)}"{(d.Freigegeben(x) ? " checked" : "")}>
                      <code>{Html.E(x)}</code></label>
                    """));

            zeilen.Append($"""
                <div class="karte">
                  <p><strong class="mono">{Html.E(name)}</strong>
                     {(an is not null ? $"<span class=\"an\">· verbunden seit {Dauer(an.OnlineSec)}</span>"
                                      : "<span class=\"aus\">· offline</span>")}
                     {(gesperrt ? "<span class=\"aus\">· gesperrt</span>" : "")}</p>
                  <form method="post" action="/devices/save">
                    {Csrf(s)}<input type="hidden" name="device" value="{Html.E(name)}">
                    <label>Notiz</label>
                    <input type="text" name="note" value="{Html.E(d.Note)}">
                    <label>Freigegebene Dienste</label>
                    {kaesten}
                    <p><label style="display:inline">
                       <input type="checkbox" name="revoked"{(gesperrt ? " checked" : "")}> gesperrt
                       </label>
                       <span class="schwach">– trennt sofort auch laufende Sitzungen</span></p>
                    <p><button>Speichern</button></p>
                  </form>
                  <form method="post" action="/devices/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="device" value="{Html.E(name)}">
                    <button class="gefahr">Gerät entfernen</button>
                  </form>
                </div>
                """);
        }

        var fremde = online.Keys.Where(k => !liste.ContainsKey(k)).ToList();
        var hinweisFremd = fremde.Count == 0 ? "" : $"""
            <p class="fehler">Verbunden, aber nicht in der Liste: {Html.E(string.Join(", ", fremde))}.
               Das kann nur vorkommen, wenn <code>allow_unlisted_devices</code> gesetzt ist &ndash;
               dann darf sich jedes Zertifikat dieser CA anmelden.</p>
            """;

        await Sende(c, Html.Seite("Geräte", s, $"""
            <h1>Geräte</h1>
            <p class="lead">Nur wer hier steht, darf sich anmelden. Welche Adresse hinter einem
               Dienstnamen steht, entscheidet das Gerät selbst &ndash; hier wird nur freigegeben
               oder gesperrt.</p>
            {hinweisFremd}
            <div class="karte">
              <p class="schwach">So meldet sich ein neues Gerät an. Dieselbe Zeile für alle Geräte,
                 sie enthält kein Geheimnis:</p>
              <pre>schleuse enroll -relay {Html.E(OeffentlicheAdresse())} -ca-pin {Html.E(pin)} \
                 -service ssh=127.0.0.1:22 -service http=127.0.0.1:80</pre>
              <p class="schwach">Das Gerät landet danach in der <a href="/pending">Warteschlange</a>.</p>
            </div>
            {(liste.Count == 0 ? "<p class=\"schwach\">Die Geräteliste ist leer.</p>" : zeilen.ToString())}
            """, hinweis, fehler)).ConfigureAwait(false);
    }

    string OeffentlicheAdresse()
    {
        var (host, port) = Net.SplitHostPort(relay.ListenAddress);
        if (host is "0.0.0.0" or "::" or "") host = "<relay>";
        return $"{host}:{port}";
    }

    async Task GeraetSpeichern(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "device", 64);
        var note = Feld(f, "note", 200);
        var dienste = f["svc"].Where(x => x is not null).Select(x => x!).Where(Tls.IsSaneName).ToArray();
        var gesperrt = f["revoked"].Count > 0;

        var gefunden = false;
        relay.UpdateAcl(acl =>
            {
            if (acl.Devices is null || !acl.Devices.TryGetValue(name, out var d)) return;
            gefunden = true;
            d.Note = note.Length == 0 ? null : note;
            d.Services = dienste;
            acl.Revoked = Sperrliste(acl.Revoked, Tls.DevicePrefix + name, gesperrt);
        });

        if (!gefunden)
        {
            await Geraete(c, null, $"'{name}' steht nicht in der Liste.").ConfigureAwait(false);
            return;
        }
        Log.Info("web", $"{s.User}: Gerät '{name}' geändert (gesperrt={gesperrt}, " +
                        $"Dienste={string.Join(",", dienste)})");
        await Geraete(c, $"'{name}' gespeichert.", null).ConfigureAwait(false);
    }

    /// <summary>Nimmt einen Eintrag in die Sperrliste auf oder heraus, ohne Dubletten.</summary>
    internal static string[] Sperrliste(string[] bisher, string eintrag, bool sperren) =>
        sperren ? [.. bisher.Where(x => x != eintrag).Append(eintrag)]
                : [.. bisher.Where(x => x != eintrag)];

    async Task GeraetLoeschen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "device", 64);
        relay.UpdateAcl(acl =>
            {
            acl.Devices?.Remove(name);
        });
        Log.Warn("web", $"{s.User}: Gerät '{name}' aus der Liste entfernt");
        await Geraete(c, $"'{name}' entfernt. Eine laufende Anmeldung wurde beendet.", null).ConfigureAwait(false);
    }

    // -- Zugaenge ------------------------------------------------------------

    async Task Zugaenge(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        var acl = relay.CurrentAcl;
        var zeilen = string.Concat(acl.Clients.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv =>
        {
            var gesperrt = acl.IsRevoked(Tls.ClientPrefix + kv.Key);
            return $"""
                <div class="karte">
                  <p><strong class="mono">{Html.E(kv.Key)}</strong>
                     {(gesperrt ? "<span class=\"aus\">· gesperrt</span>" : "")}</p>
                  <form method="post" action="/clients/save">
                    {Csrf(s)}<input type="hidden" name="client" value="{Html.E(kv.Key)}">
                    <label>Geräte (Muster, durch Komma getrennt, <code>*</code> erlaubt)</label>
                    <input type="text" name="devices" value="{Html.E(string.Join(", ", kv.Value.Devices))}">
                    <label>Dienste</label>
                    <input type="text" name="services" value="{Html.E(string.Join(", ", kv.Value.Services))}">
                    <p><label style="display:inline">
                       <input type="checkbox" name="revoked"{(gesperrt ? " checked" : "")}> gesperrt</label>
                       <span class="schwach">– beendet auch laufende Sitzungen</span></p>
                    <p><button>Speichern</button></p>
                  </form>
                  <form method="post" action="/clients/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="client" value="{Html.E(kv.Key)}">
                    <button class="gefahr">Zugang entfernen</button>
                  </form>
                </div>
                """;
        }));

        await Sende(c, Html.Seite("Zugänge", s, $"""
            <h1>Zugänge</h1>
            <p class="lead">Wer auf welche Geräte und Dienste darf. Die Zertifikate dazu werden
               nicht hier ausgestellt.</p>
            <div class="karte">
              <p class="schwach">Ein Bediener-Zertifikat entsteht auf dem Rechner, auf dem der
                 Schlüssel der Wurzel-CA liegt &ndash; nicht auf dem Relay:</p>
              <pre>./schleuse-pki.sh client &lt;name&gt;</pre>
              <p class="schwach">Der Relay nimmt Bediener-Zertifikate nur an, wenn die Wurzel-CA sie
                 unmittelbar signiert hat. Die Zwischen-CA auf dem Relay kann das nicht &ndash; wer
                 den Relay übernimmt, kann sich damit keinen Zugang schaffen.</p>
            </div>
            {zeilen}
            <h2>Neuen Zugang eintragen</h2>
            <div class="karte">
              <form method="post" action="/clients/save">
                {Csrf(s)}
                <label>Name (der Teil hinter <code>client:</code> im Zertifikat)</label>
                <input type="text" name="client" class="klein" maxlength="64" pattern="[A-Za-z0-9._-]+" required>
                <label>Geräte</label>
                <input type="text" name="devices" value="*">
                <label>Dienste</label>
                <input type="text" name="services" value="*">
                <p><button>Anlegen</button></p>
              </form>
            </div>
            """, hinweis, fehler)).ConfigureAwait(false);
    }

    static string[] Muster(string s) =>
        [.. s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
             .Where(x => x.Length <= 64 && x.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '.' or '*'))];

    async Task ZugangSpeichern(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "client", 64);
        if (!Tls.IsSaneName(name)) { await Zugaenge(c, null, "Unbrauchbarer Name.").ConfigureAwait(false); return; }

        relay.UpdateAcl(acl =>
            {
            acl.Clients[name] = new AclEntry
            {
            Devices = Muster(Feld(f, "devices", 500)),
            Services = Muster(Feld(f, "services", 500)),
            };
            var eintrag = Tls.ClientPrefix + name;
            acl.Revoked = f["revoked"].Count > 0
            ? [.. acl.Revoked.Where(x => x != eintrag).Append(eintrag)]
            : [.. acl.Revoked.Where(x => x != eintrag)];
        });
        Log.Info("web", $"{s.User}: Zugang '{name}' gespeichert");
        await Zugaenge(c, $"'{name}' gespeichert.", null).ConfigureAwait(false);
    }

    async Task ZugangLoeschen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "client", 64);
        relay.UpdateAcl(acl =>
            {
            acl.Clients.Remove(name);
        });
        Log.Warn("web", $"{s.User}: Zugang '{name}' entfernt");
        await Zugaenge(c, $"'{name}' entfernt.", null).ConfigureAwait(false);
    }

    // -- Benutzer ------------------------------------------------------------

    async Task Benutzer(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        var jetzt = DateTimeOffset.UtcNow;
        var zeilen = string.Concat(_users.Alle().Select(u => $"""
            <tr>
              <td class="mono">{Html.E(u.Name)}</td>
              <td>{(u.Role == WebRole.Admin ? "Verwalter" : "nur lesen")}</td>
              <td>{(u.ZweiFaktorFertig ? "<span class=\"an\">eingerichtet</span>"
                                       : "<span class=\"aus\">fehlt noch</span>")}</td>
              <td>{(u.Recovery.Count)}</td>
              <td>{(u.LastLogin is { } t ? Zeit(t) : "-")}</td>
              <td>{(u.Gesperrt(jetzt) ? $"<span class=\"aus\">bis {Html.E(u.LockedUntil!.Value.ToLocalTime().ToString("HH:mm"))}</span>" : "")}</td>
              <td>
                <form method="post" action="/users/reset" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link" name="was" value="password">Passwort</button>
                </form> ·
                <form method="post" action="/users/reset" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link" name="was" value="2fa">2FA</button>
                </form> ·
                <form method="post" action="/users/delete" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link">löschen</button>
                </form>
              </td>
            </tr>
            """));

        await Sende(c, Html.Seite("Benutzer", s, $"""
            <h1>Benutzer</h1>
            <p class="lead">Zugänge zu dieser Oberfläche. Jeder braucht Passwort und zweiten Faktor.</p>
            <table>
              <tr><th>Name</th><th>Rolle</th><th>2FA</th><th>Codes</th><th>Zuletzt</th><th>Gesperrt</th><th></th></tr>
              {zeilen}
            </table>
            <h2>Neuen Benutzer anlegen</h2>
            <div class="karte">
              <form method="post" action="/users/add">
                {Csrf(s)}
                <label>Name</label>
                <input type="text" name="user" class="klein" maxlength="32" pattern="[A-Za-z0-9._-]+" required>
                <label>Rolle</label>
                <select name="role">
                  <option value="Admin">Verwalter – darf alles ändern</option>
                  <option value="Viewer">nur lesen</option>
                </select>
                <p><button>Anlegen</button></p>
                <p class="schwach">Das Anfangspasswort wird einmalig angezeigt. Der zweite Faktor
                   wird beim ersten Anmelden eingerichtet.</p>
              </form>
            </div>
            """, hinweis, fehler)).ConfigureAwait(false);
    }

    async Task BenutzerAnlegen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "user", 32);
        var rolle = Feld(f, "role", 16) == "Viewer" ? WebRole.Viewer : WebRole.Admin;
        try
        {
            var pw = Passwords.Suggest();
            _users.Anlegen(name, pw, rolle, mussAendern: true);
            Log.Info("web", $"{s.User}: Benutzer '{name}' angelegt ({rolle})");
            await Benutzer(c, $"'{name}' angelegt. Anfangspasswort: {pw} – jetzt notieren, " +
                              "es wird nicht wieder angezeigt.", null).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            await Benutzer(c, null, ex.Message).ConfigureAwait(false);
        }
    }

    async Task BenutzerLoeschen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "user", 32);
        try
        {
            _users.Loeschen(name);
            _sitzungen.BeendeAlle(name);
            Log.Warn("web", $"{s.User}: Benutzer '{name}' gelöscht");
            await Benutzer(c, $"'{name}' gelöscht.", null).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            await Benutzer(c, null, ex.Message).ConfigureAwait(false);
        }
    }

    async Task BenutzerZuruecksetzen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var name = Feld(f, "user", 32);
        var was = Feld(f, "was", 16);
        if (_users.Finde(name) is null) { await Benutzer(c, null, "Unbekannter Benutzer.").ConfigureAwait(false); return; }

        if (was == "2fa")
        {
            _users.Aendern(name, u => { u.Totp = null; u.TotpConfirmed = false; u.TotpLast = 0; u.Recovery.Clear(); });
            _sitzungen.BeendeAlle(name);
            Log.Warn("web", $"{s.User}: zweiter Faktor von '{name}' zurückgesetzt");
            await Benutzer(c, $"Der zweite Faktor von '{name}' ist zurückgesetzt und wird beim " +
                              "nächsten Anmelden neu eingerichtet.", null).ConfigureAwait(false);
            return;
        }

        var pw = Passwords.Suggest();
        _users.Aendern(name, u => { u.Password = Passwords.Hash(pw); u.MustChange = true; u.Failed = 0; u.LockedUntil = null; });
        _sitzungen.BeendeAlle(name);
        Log.Warn("web", $"{s.User}: Passwort von '{name}' zurückgesetzt");
        await Benutzer(c, $"Neues Passwort für '{name}': {pw} – jetzt notieren.", null).ConfigureAwait(false);
    }

    // -- Eigenes Konto -------------------------------------------------------

    async Task Konto(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }
        var u = _users.Finde(s.User);
        if (u is null) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        // Wiederherstellungscodes werden genau einmal gezeigt.
        var einmalig = "";
        if (s.Einmalig is { Length: > 0 } codes)
        {
            s.Einmalig = null;
            einmalig = $"""
                <div class="karte">
                  <h2 style="margin-top:0">Wiederherstellungscodes</h2>
                  <p>Jeder Code gilt einmal und ersetzt den zweiten Faktor, wenn das Telefon
                     verloren geht. Jetzt ausdrucken oder notieren &ndash; sie werden nicht
                     wieder angezeigt.</p>
                  <ul class="codes">{string.Concat(codes.Split('\n').Select(x => $"<li>{Html.E(x)}</li>"))}</ul>
                </div>
                """;
        }

        var warnung = u.MustChange
            ? """
              <p class="fehler">Dieses Passwort wurde von einem Verwalter vergeben.
                 Bitte jetzt ein eigenes setzen.</p>
              """
            : "";

        await Sende(c, Html.Seite("Konto", s, $"""
            <h1>Konto</h1>
            <p class="lead">{Html.E(s.User)} · {(s.Role == WebRole.Admin ? "Verwalter" : "nur lesen")}</p>
            {einmalig}{warnung}
            <h2>Passwort ändern</h2>
            <div class="karte">
              <form method="post" action="/account/password">
                {Csrf(s)}
                <label>Bisheriges Passwort</label>
                <input type="password" name="alt" autocomplete="current-password" required>
                <label>Neues Passwort (mindestens 12 Zeichen)</label>
                <input type="password" name="neu" autocomplete="new-password" required>
                <label>Wiederholen</label>
                <input type="password" name="neu2" autocomplete="new-password" required>
                <p><button>Ändern</button></p>
              </form>
            </div>
            <h2>Zweiter Faktor</h2>
            <div class="karte">
              <p>{(u.ZweiFaktorFertig ? "Eingerichtet." : "Noch nicht eingerichtet.")}
                 Verbleibende Wiederherstellungscodes: {u.Recovery.Count}</p>
              <form method="post" action="/account/2fa">
                {Csrf(s)}
                <p><button class="zweit" name="was" value="codes">Neue Wiederherstellungscodes</button>
                   <button class="gefahr" name="was" value="neu">Zweiten Faktor neu einrichten</button></p>
              </form>
            </div>
            """, hinweis, fehler)).ConfigureAwait(false);
    }

    async Task PasswortAendern(HttpContext c)
    {
        var p = await Post(c, nurVerwalter: false).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        var u = _users.Finde(s.User);
        if (u is null || !Passwords.Verify(u.Password, f["alt"].ToString()))
        {
            await Konto(c, null, "Das bisherige Passwort stimmt nicht.").ConfigureAwait(false);
            return;
        }
        var neu = f["neu"].ToString();
        if (neu.Length < 12) { await Konto(c, null, "Das neue Passwort ist zu kurz.").ConfigureAwait(false); return; }
        if (neu != f["neu2"].ToString()) { await Konto(c, null, "Die Eingaben stimmen nicht überein.").ConfigureAwait(false); return; }

        _users.Aendern(s.User, x => { x.Password = Passwords.Hash(neu); x.MustChange = false; });
        Log.Info("web", $"{s.User}: Passwort geändert");
        await Konto(c, "Passwort geändert.", null).ConfigureAwait(false);
    }

    async Task ZweiterFaktorNeu(HttpContext c)
    {
        var p = await Post(c, nurVerwalter: false).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;

        if (Feld(f, "was", 16) == "codes")
        {
            s.Einmalig = string.Join("\n", _users.NeueWiederherstellung(s.User));
            Log.Info("web", $"{s.User}: neue Wiederherstellungscodes");
            await Konto(c, "Neue Codes erzeugt. Die alten gelten nicht mehr.", null).ConfigureAwait(false);
            return;
        }

        _users.Aendern(s.User, u => { u.Totp = null; u.TotpConfirmed = false; u.TotpLast = 0; });
        s.TotpDone = false;
        Log.Warn("web", $"{s.User}: zweiter Faktor wird neu eingerichtet");
        await Weiter(c, "/login/2fa-neu").ConfigureAwait(false);
    }
}

// Verwaltung der Marken in der Oberflaeche - dieselben Aufrufe wie ueber die
// Schnittstelle, damit beide Wege dasselbe koennen.
internal sealed partial class WebUi
{
    async Task Marken(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        var zeilen = string.Concat(_marken.Alle().Select(t => $"""
            <tr>
              <td>{Html.E(t.Name)}</td>
              <td>{(t.Role == WebRole.Admin ? "Verwalter" : "nur lesen")}</td>
              <td>{Zeit(t.Created)}<br><span class="schwach">{Html.E(t.CreatedBy)}</span></td>
              <td>{(t.Expires is { } e ? Zeit(e) : "unbegrenzt")}</td>
              <td>{(t.LastUsed is { } l ? Zeit(l) : "nie")}<br>
                  <span class="schwach mono">{Html.E(t.LastFrom)}</span></td>
              <td><form method="post" action="/tokens/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="id" value="{Html.E(t.Id)}">
                    <button class="link">zurückziehen</button></form></td>
            </tr>
            """));

        var ui = _marken.UiEnabled;
        await Sende(c, Html.Seite("Schnittstelle", s, $"""
            <h1>Schnittstelle</h1>
            <p class="lead">Alles, was hier bedienbar ist, geht auch maschinell. Ausgewiesen
               wird sich mit einer Marke im Kopf <code>Authorization: Bearer …</code>.</p>

            <div class="karte">
              <p>Vorsatz der Pfade: <code>{Html.E(ApiPath)}</code></p>
              <pre>curl -H "Authorization: Bearer schleuse_…" https://&lt;relay&gt;:8443{Html.E(ApiPath)}/status</pre>
              <p class="schwach">Ohne gültige Marke antwortet jeder Pfad gleich – mit 404 und leerem
                 Rumpf. Es gibt kein Verzeichnis der Pfade und keine Selbstauskunft.</p>
              <p class="schwach">Die Weboberfläche ist zurzeit
                 <strong>{(ui ? "eingeschaltet" : "abgeschaltet")}</strong>. Umlegen lässt sich das
                 nur über die Schnittstelle (<code>POST {Html.E(ApiPath)}/ui</code>) oder auf dem
                 Relay mit <code>schleuse ui -c &lt;relay.json&gt; -on</code> – damit man sich hier
                 nicht selbst aussperrt.</p>
            </div>

            <table>
              <tr><th>Name</th><th>Rolle</th><th>Angelegt</th><th>Gültig bis</th><th>Zuletzt benutzt</th><th></th></tr>
              {zeilen}
            </table>

            <h2>Neue Marke</h2>
            <div class="karte">
              <form method="post" action="/tokens/create">
                {Csrf(s)}
                <label>Name</label>
                <input type="text" name="name" class="klein" maxlength="32" pattern="[A-Za-z0-9._-]+" required>
                <label>Rolle</label>
                <select name="role">
                  <option value="Viewer">nur lesen</option>
                  <option value="Admin">Verwalter – darf alles ändern</option>
                </select>
                <label>Gültig für … Tage (0 = unbegrenzt)</label>
                <input type="text" name="days" class="klein" value="0">
                <p><button>Anlegen</button></p>
                <p class="schwach">Die Marke wird einmalig angezeigt und danach nur noch als
                   Prüfsumme gespeichert.</p>
              </form>
            </div>
            """, hinweis, fehler)).ConfigureAwait(false);
    }

    async Task MarkeAnlegen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;
        try
        {
            var tage = int.TryParse(Feld(f, "days", 8), out var d) ? Math.Clamp(d, 0, 3650) : 0;
            var rolle = Feld(f, "role", 16) == "Admin" ? WebRole.Admin : WebRole.Viewer;
            var (e, klartext) = _marken.Anlegen(Feld(f, "name", 32), rolle, tage, s.User);
            Log.Info("web", $"{s.User}: Marke '{e.Name}' angelegt ({e.Role})");
            await Marken(c, $"Marke angelegt: {klartext} – jetzt notieren, sie wird nicht wieder angezeigt.",
                         null).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            await Marken(c, null, ex.Message).ConfigureAwait(false);
        }
    }

    async Task MarkeLoeschen(HttpContext c)
    {
        var p = await Post(c).ConfigureAwait(false);
        if (p is null) return;
        var (s, f) = p.Value;
        var id = Feld(f, "id", 32);
        _marken.Loeschen(id);
        Log.Warn("web", $"{s.User}: Marke {id} zurückgezogen");
        await Marken(c, "Marke zurückgezogen.", null).ConfigureAwait(false);
    }
}
