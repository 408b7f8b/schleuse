using Microsoft.AspNetCore.Http;

namespace Schleuse;

// Die Seiten der Weboberflaeche. Jede baut ihre Zeichenkette selbst; alles, was
// von aussen kommt, geht durch Html.E.
internal sealed partial class WebUi
{
    static string Csrf(WebSession s) => $"""<input type="hidden" name="csrf" value="{Html.E(s.Csrf)}">""";
    static string Zeit(DateTimeOffset t) => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

    // -- Warteschlange -------------------------------------------------------

    async Task Warteschlange(HttpContext c, string? hinweis, string? fehler)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return; }

        if (relay.Pending is null)
        {
            await Sende(c, Html.Seite("Queue", s, """
                <h1>Queue</h1>
                <p class="lead">Self enrollment is not set up.</p>
                <div class="karte">
                <p>For devices to enrol themselves, the relay needs an intermediate
                   CA. It is created once on a secure machine:</p>
                <pre>./schleuse-pki.sh device-ca</pre>
                <p>Then put <code>device-ca.crt</code> and <code>device-ca.key</code> on the
                   relay and name them in <code>relay.json</code>:</p>
                <pre>"enrollment": { "ca": "device-ca.crt", "key": "device-ca.key" }</pre>
                <p class="schwach">The root CA key stays offline while doing this. The
                   intermediate CA can only issue devices, never access accounts.</p>
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
            <h1>Queue</h1>
            <p class="lead">Newly enrolled devices wait here. While they wait they hold
               no certificate and reach nothing.</p>
            """);

        if (offen.Count == 0)
            inhalt.Append("""<p class="schwach">Nothing is waiting right now.</p>""");

        foreach (var r in offen)
        {
            var vorschlag = Vorschlag(r.Hostname);
            var dienste = r.Proposed.Count == 0
                ? """
                  <p class="schwach">The device proposed no services. It can offer
                     nothing until its configuration is extended.</p>
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
                  <p class="schwach">Fingerprint of the key &mdash; must match the one the
                     device showed while enrolling</p>
                  <p class="fp">{Html.E(r.Fingerprint)}</p>
                  <table>
                    <tr><th>Self report</th><td>{Html.E(r.Hostname ?? "(none)")}</td></tr>
                    <tr><th>Origin</th><td class="mono">{Html.E(r.From)}</td></tr>
                    <tr><th>Since</th><td>{Zeit(r.FirstSeen)}</td></tr>
                  </table>
                  <form method="post" action="/pending/approve">
                    {Csrf(s)}
                    <input type="hidden" name="id" value="{Html.E(r.Id)}">
                    <label>Device name</label>
                    <input type="text" name="device" class="klein" value="{Html.E(vorschlag)}"
                           maxlength="64" pattern="[A-Za-z0-9._-]+" required>
                    <label>Note</label>
                    <input type="text" name="note" placeholder="Hall 2, cabinet 4">
                    <label>Released services</label>
                    {dienste}
                    <p>
                      <button>Approve</button>
                    </p>
                  </form>
                  <form method="post" action="/pending/reject" class="inline">
                    {Csrf(s)}<input type="hidden" name="id" value="{Html.E(r.Id)}">
                    <button class="gefahr">Reject</button>
                  </form>
                </div>
                """);
        }

        if (erledigt.Count > 0)
        {
            inhalt.Append("""
                <h2>Recently decided</h2>
                <table><tr><th>Fingerprint</th><th>Device</th><th>Result</th>
                           <th>By</th><th>When</th><th></th></tr>
                """);
            foreach (var r in erledigt)
                inhalt.Append($"""
                    <tr><td class="mono">{Html.E(r.Fingerprint)}</td>
                        <td class="mono">{Html.E(r.Device ?? "-")}</td>
                        <td>{(r.State == PendingState.Approved ? "<span class=\"an\">approved</span>" : "<span class=\"aus\">rejected</span>")}</td>
                        <td>{Html.E(r.DecidedBy)}</td>
                        <td>{(r.DecidedAt is { } t ? Zeit(t) : "")}</td>
                        <td><form method="post" action="/pending/delete" class="inline">
                            {Csrf(s)}<input type="hidden" name="id" value="{Html.E(r.Id)}">
                            <button class="link">remove</button></form></td></tr>
                    """);
            inhalt.Append("</table>");
        }

await Sende(c, Html.Seite("Queue", s, inhalt.ToString(), hinweis, fehler)).ConfigureAwait(false);
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
            var antrag = relay.Pending.ById(id) ?? throw new InvalidOperationException("request not found");
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
            await Warteschlange(c, $"'{device}' is approved. The device picks up its certificate " +
                                   "on its next poll.", null).ConfigureAwait(false);
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
            await Warteschlange(c, ablehnen ? "Request rejected." : "Entry removed.", null).ConfigureAwait(false);
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
                ? """<span class="schwach">not connected &ndash; services unknown</span>"""
                : string.Concat(angeboten.Select(x => $"""
                    <label style="display:inline-block;margin-right:1rem">
                      <input type="checkbox" name="svc" value="{Html.E(x)}"{(d.Freigegeben(x) ? " checked" : "")}>
                      <code>{Html.E(x)}</code></label>
                    """));

            zeilen.Append($"""
                <div class="karte">
                  <p><strong class="mono">{Html.E(name)}</strong>
                     {(an is not null ? $"<span class=\"an\">· connected for {Dauer(an.OnlineSec)}</span>"
                                      : "<span class=\"aus\">· offline</span>")}
                     {(gesperrt ? "<span class=\"aus\">· revoked</span>" : "")}</p>
                  <form method="post" action="/devices/save">
                    {Csrf(s)}<input type="hidden" name="device" value="{Html.E(name)}">
                    <label>Note</label>
                    <input type="text" name="note" value="{Html.E(d.Note)}">
                    <label>Released services</label>
                    {kaesten}
                    <p><label style="display:inline">
                       <input type="checkbox" name="revoked"{(gesperrt ? " checked" : "")}> revoked
                       </label>
                       <span class="schwach">– cuts running sessions immediately too</span></p>
                    <p><button>Save</button></p>
                  </form>
                  <form method="post" action="/devices/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="device" value="{Html.E(name)}">
                    <button class="gefahr">Remove device</button>
                  </form>
                </div>
                """);
        }

        var fremde = online.Keys.Where(k => !liste.ContainsKey(k)).ToList();
        var hinweisFremd = fremde.Count == 0 ? "" : $"""
            <p class="fehler">Connected but not on the list: {Html.E(string.Join(", ", fremde))}.
               This can only happen when <code>allow_unlisted_devices</code> is set &ndash;
               then every certificate of this CA may enrol.</p>
            """;

        await Sende(c, Html.Seite("Devices", s, $"""
            <h1>Devices</h1>
            <p class="lead">Only what is listed here may enrol. Which address sits behind a
               service name is the device's own decision &ndash; here it is only released
               or revoked.</p>
            {hinweisFremd}
            <div class="karte">
              <p class="schwach">This is how a new device enrols. The same line for every device,
                 it contains no secret:</p>
              <pre>schleuse enroll -relay {Html.E(OeffentlicheAdresse())} -ca-pin {Html.E(pin)} \
                 -service ssh=127.0.0.1:22 -service http=127.0.0.1:80</pre>
              <p class="schwach">The device then lands in the <a href="/pending">queue</a>.</p>
            </div>
            {(liste.Count == 0 ? "<p class=\"schwach\">The device list is empty.</p>" : zeilen.ToString())}
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
            await Geraete(c, null, $"'{name}' is not on the list.").ConfigureAwait(false);
            return;
        }
        Log.Info("web", $"{s.User}: Gerät '{name}' geändert (gesperrt={gesperrt}, " +
                        $"Dienste={string.Join(",", dienste)})");
        await Geraete(c, $"'{name}' saved.", null).ConfigureAwait(false);
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
        await Geraete(c, $"'{name}' removed. A running enrollment was cut.", null).ConfigureAwait(false);
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
                     {(gesperrt ? "<span class=\"aus\">· revoked</span>" : "")}</p>
                  <form method="post" action="/clients/save">
                    {Csrf(s)}<input type="hidden" name="client" value="{Html.E(kv.Key)}">
                    <label>Devices (patterns, comma separated, <code>*</code> allowed)</label>
                    <input type="text" name="devices" value="{Html.E(string.Join(", ", kv.Value.Devices))}">
                    <label>Services</label>
                    <input type="text" name="services" value="{Html.E(string.Join(", ", kv.Value.Services))}">
                    <p><label style="display:inline">
                       <input type="checkbox" name="revoked"{(gesperrt ? " checked" : "")}> revoked</label>
                       <span class="schwach">– cuts running sessions too</span></p>
                    <p><button>Save</button></p>
                  </form>
                  <form method="post" action="/clients/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="client" value="{Html.E(kv.Key)}">
                    <button class="gefahr">Remove account</button>
                  </form>
                </div>
                """;
        }));

        await Sende(c, Html.Seite("Access", s, $"""
            <h1>Access</h1>
            <p class="lead">Who may reach which devices and services. The matching certificates
               are not issued here.</p>
            <div class="karte">
              <p class="schwach">An operator certificate is created on the machine that holds the
                 root CA key &ndash; not on the relay:</p>
              <pre>./schleuse-pki.sh client &lt;name&gt;</pre>
              <p class="schwach">The relay accepts operator certificates only if the root CA signed
                 them directly. The intermediate CA on the relay cannot do that &ndash; whoever
                 takes over the relay cannot grant themselves access with it.</p>
            </div>
            {zeilen}
            <h2>Add a new account</h2>
            <div class="karte">
              <form method="post" action="/clients/save">
                {Csrf(s)}
                <label>Name (the part after <code>client:</code> in the certificate)</label>
                <input type="text" name="client" class="klein" maxlength="64" pattern="[A-Za-z0-9._-]+" required>
                <label>Devices</label>
                <input type="text" name="devices" value="*">
                <label>Services</label>
                <input type="text" name="services" value="*">
                <p><button>Create</button></p>
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
        if (!Tls.IsSaneName(name)) { await Zugaenge(c, null, "Unusable name.").ConfigureAwait(false); return; }

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
        await Zugaenge(c, $"'{name}' saved.", null).ConfigureAwait(false);
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
        await Zugaenge(c, $"'{name}' removed.", null).ConfigureAwait(false);
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
              <td>{(u.Role == WebRole.Admin ? "Administrator" : "read only")}</td>
              <td>{(u.ZweiFaktorFertig ? "<span class=\"an\">set up</span>"
                                       : "<span class=\"aus\">still missing</span>")}</td>
              <td>{(u.Recovery.Count)}</td>
              <td>{(u.LastLogin is { } t ? Zeit(t) : "-")}</td>
              <td>{(u.Gesperrt(jetzt) ? $"<span class=\"aus\">until {Html.E(u.LockedUntil!.Value.ToLocalTime().ToString("HH:mm"))}</span>" : "")}</td>
              <td>
                <form method="post" action="/users/reset" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link" name="was" value="password">Password</button>
                </form> ·
                <form method="post" action="/users/reset" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link" name="was" value="2fa">2FA</button>
                </form> ·
                <form method="post" action="/users/delete" class="inline">
                  {Csrf(s)}<input type="hidden" name="user" value="{Html.E(u.Name)}">
                  <button class="link">delete</button>
                </form>
              </td>
            </tr>
            """));

        await Sende(c, Html.Seite("Users", s, $"""
            <h1>Users</h1>
            <p class="lead">Accounts for this interface. Every one needs a password and a second factor.</p>
            <table>
              <tr><th>Name</th><th>Role</th><th>2FA</th><th>Codes</th><th>Last seen</th><th>Locked</th><th></th></tr>
              {zeilen}
            </table>
            <h2>Add a new user</h2>
            <div class="karte">
              <form method="post" action="/users/add">
                {Csrf(s)}
                <label>Name</label>
                <input type="text" name="user" class="klein" maxlength="32" pattern="[A-Za-z0-9._-]+" required>
                <label>Role</label>
                <select name="role">
                  <option value="Admin">Administrator – may change everything</option>
                  <option value="Viewer">read only</option>
                </select>
                <p><button>Create</button></p>
                <p class="schwach">The initial password is shown once. The second factor
                   is set up at the first sign in.</p>
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
            await Benutzer(c, $"'{name}' created. Initial password: {pw} – write it down now, " +
                              "it is not shown again.", null).ConfigureAwait(false);
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
            await Benutzer(c, $"'{name}' deleted.", null).ConfigureAwait(false);
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
        if (_users.Finde(name) is null) { await Benutzer(c, null, "Unknown user.").ConfigureAwait(false); return; }

        if (was == "2fa")
        {
            _users.Aendern(name, u => { u.Totp = null; u.TotpConfirmed = false; u.TotpLast = 0; u.Recovery.Clear(); });
            _sitzungen.BeendeAlle(name);
            Log.Warn("web", $"{s.User}: zweiter Faktor von '{name}' zurückgesetzt");
            await Benutzer(c, $"The second factor of '{name}' is reset and will be set up " +
                              "again at the next sign in.", null).ConfigureAwait(false);
            return;
        }

        var pw = Passwords.Suggest();
        _users.Aendern(name, u => { u.Password = Passwords.Hash(pw); u.MustChange = true; u.Failed = 0; u.LockedUntil = null; });
        _sitzungen.BeendeAlle(name);
        Log.Warn("web", $"{s.User}: Passwort von '{name}' zurückgesetzt");
        await Benutzer(c, $"New password for '{name}': {pw} – write it down now.", null).ConfigureAwait(false);
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
                  <h2 style="margin-top:0">Recovery codes</h2>
                  <p>Each code works once and replaces the second factor if the phone is
                     lost. Print or write them down now &ndash; they are not shown
                     again.</p>
                  <ul class="codes">{string.Concat(codes.Split('\n').Select(x => $"<li>{Html.E(x)}</li>"))}</ul>
                </div>
                """;
        }

        var warnung = u.MustChange
            ? """
              <p class="fehler">This password was set by an administrator.
                 Please choose your own now.</p>
              """
            : "";

        await Sende(c, Html.Seite("Account", s, $"""
            <h1>Account</h1>
            <p class="lead">{Html.E(s.User)} · {(s.Role == WebRole.Admin ? "Administrator" : "read only")}</p>
            {einmalig}{warnung}
            <h2>Change password</h2>
            <div class="karte">
              <form method="post" action="/account/password">
                {Csrf(s)}
                <label>Current password</label>
                <input type="password" name="alt" autocomplete="current-password" required>
                <label>New password (at least 12 characters)</label>
                <input type="password" name="neu" autocomplete="new-password" required>
                <label>Repeat</label>
                <input type="password" name="neu2" autocomplete="new-password" required>
                <p><button>Change</button></p>
              </form>
            </div>
            <h2>Second factor</h2>
            <div class="karte">
              <p>{(u.ZweiFaktorFertig ? "Set up." : "Not set up yet.")}
                 Remaining recovery codes: {u.Recovery.Count}</p>
              <form method="post" action="/account/2fa">
                {Csrf(s)}
                <p><button class="zweit" name="was" value="codes">New recovery codes</button>
                   <button class="gefahr" name="was" value="neu">Set up second factor again</button></p>
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
            await Konto(c, null, "The current password is not correct.").ConfigureAwait(false);
            return;
        }
        var neu = f["neu"].ToString();
        if (neu.Length < 12) { await Konto(c, null, "The new password is too short.").ConfigureAwait(false); return; }
        if (neu != f["neu2"].ToString()) { await Konto(c, null, "The entries do not match.").ConfigureAwait(false); return; }

        _users.Aendern(s.User, x => { x.Password = Passwords.Hash(neu); x.MustChange = false; });
        Log.Info("web", $"{s.User}: Passwort geändert");
        await Konto(c, "Password changed.", null).ConfigureAwait(false);
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
            await Konto(c, "New codes created. The old ones no longer work.", null).ConfigureAwait(false);
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
              <td>{(t.Role == WebRole.Admin ? "Administrator" : "read only")}</td>
              <td>{Zeit(t.Created)}<br><span class="schwach">{Html.E(t.CreatedBy)}</span></td>
              <td>{(t.Expires is { } e ? Zeit(e) : "no limit")}</td>
              <td>{(t.LastUsed is { } l ? Zeit(l) : "never")}<br>
                  <span class="schwach mono">{Html.E(t.LastFrom)}</span></td>
              <td><form method="post" action="/tokens/delete" class="inline">
                    {Csrf(s)}<input type="hidden" name="id" value="{Html.E(t.Id)}">
                    <button class="link">withdraw</button></form></td>
            </tr>
            """));

        var ui = _marken.UiEnabled;
        await Sende(c, Html.Seite("API", s, $"""
            <h1>API</h1>
            <p class="lead">Everything that can be done here also works programmatically.
               Authentication uses a token in the <code>Authorization: Bearer …</code> header.</p>

            <div class="karte">
              <p>Prefix of all paths: <code>{Html.E(ApiPath)}</code></p>
              <pre>curl -H "Authorization: Bearer schleuse_…" https://&lt;relay&gt;:8443{Html.E(ApiPath)}/status</pre>
              <p class="schwach">Without a valid token every path answers the same – 404 with an
                 empty body. There is no path listing and no self description.</p>
              <p class="schwach">The web interface is currently
                 <strong>{(ui ? "switched on" : "switched off")}</strong>. This can only be changed
                 through the API (<code>POST {Html.E(ApiPath)}/ui</code>) or on the
                 relay with <code>schleuse ui -c &lt;relay.json&gt; -on</code> – so that nobody
                 locks themselves out here.</p>
            </div>

            <table>
              <tr><th>Name</th><th>Role</th><th>Created</th><th>Valid until</th><th>Last used</th><th></th></tr>
              {zeilen}
            </table>

            <h2>New token</h2>
            <div class="karte">
              <form method="post" action="/tokens/create">
                {Csrf(s)}
                <label>Name</label>
                <input type="text" name="name" class="klein" maxlength="32" pattern="[A-Za-z0-9._-]+" required>
                <label>Role</label>
                <select name="role">
                  <option value="Viewer">read only</option>
                  <option value="Admin">Administrator – may change everything</option>
                </select>
                <label>Valid for … days (0 = no limit)</label>
                <input type="text" name="days" class="klein" value="0">
                <p><button>Create</button></p>
                <p class="schwach">The token is shown once and afterwards stored only as a
                   checksum.</p>
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
            await Marken(c, $"Token created: {klartext} – write it down now, it is not shown again.",
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
        await Marken(c, "Token withdrawn.", null).ConfigureAwait(false);
    }
}
