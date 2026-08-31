using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Weboberflaeche
//
// Laeuft im selben Prozess wie der Relay, aber auf einem eigenen Port mit einem
// eigenen Zertifikat. Der Tunnelport behaelt dadurch seine Eigenschaft, dass
// ohne gueltiges Client-Zertifikat schon der Handshake scheitert.
//
// Angemeldet wird mit Benutzername, Passwort und einem zweiten Faktor. Es gibt
// kein JavaScript: jede Seite ist ein Formular, jede Aenderung ein POST mit
// einem Merkmal gegen fremde Formulare.
// ---------------------------------------------------------------------------

internal sealed partial class WebUi(Relay relay, WebConfig cfg, string cfgPath)
{
    readonly UserStore _users = new(Cfg.Rel(cfgPath, cfg.Users));
    readonly SessionStore _sitzungen = new();
    readonly ApiTokenStore _marken = new(Cfg.Rel(cfgPath, cfg.State));
    string? _setupToken;

    const string CookieName = "schleuse_sitzung";

    X509Certificate2? _zertifikat;
    DateTime _zertStand;
    DateTimeOffset _zertGeprueft = DateTimeOffset.MinValue;
    readonly Lock _zertGate = new();

    public async Task RunAsync(CancellationToken ct)
    {
        var (host, port) = Net.SplitHostPort(cfg.Listen);
        _ = AktuellesZertifikat();  // frueh scheitern, wenn etwas fehlt

        Passwords.Runden = Math.Clamp(cfg.PasswordIterations, 50_000, 5_000_000);
        var dauer = Passwords.Messen();
        if (dauer > TimeSpan.FromSeconds(1))
            Log.Warn("web", $"eine Passwortpruefung dauert hier {dauer.TotalSeconds:0.0} s " +
                            $"({Passwords.Runden} Runden). Das bremst jede Anmeldung und macht sie zum " +
                            "Hebel fuer eine Ueberlastung - password_iterations kleiner setzen.");
        else
            Log.Info("web", $"Passwortpruefung: {dauer.TotalMilliseconds:0} ms bei {Passwords.Runden} Runden");

        if (_users.Leer)
        {
            _setupToken = Base32.Group(Base32.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(15)), 5);
            Log.Warn("web", "noch kein Benutzer eingerichtet. Zum Anlegen des ersten Verwalters:");
            Log.Warn("web", $"    https://{host}:{port}/setup   Kennwort: {_setupToken}");
        }

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 64 * 1024;
            k.Listen(System.Net.IPAddress.Parse(host == "0.0.0.0" ? "0.0.0.0" : host), port,
                     o => o.UseHttps(new HttpsConnectionAdapterOptions
                     {
                         // Nicht ein festes Zertifikat, sondern bei jeder
                         // Verbindung das gerade gueltige: ein per certbot
                         // erneuertes Zertifikat wuerde sonst erst beim naechsten
                         // Neustart wirksam - und das faellt spaetestens auf,
                         // wenn das alte nach neunzig Tagen ablaeuft.
                         ServerCertificateSelector = (_, _) => AktuellesZertifikat(),
                         SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                      | System.Security.Authentication.SslProtocols.Tls13,
                     }));
        });

        // Wie beim Relay laesst sich der Zustand ohne Neustart neu einlesen -
        // etwa nachdem 'schleuse ui' die Oberflaeche wieder eingeschaltet hat.
        using var hup = System.Runtime.InteropServices.PosixSignalRegistration.Create(
            System.Runtime.InteropServices.PosixSignal.SIGHUP, sig =>
            {
                sig.Cancel = true;
                _marken.NeuLaden();
                Log.Info("web", $"Zustand neu eingelesen, Oberfläche {( _marken.UiEnabled ? "an" : "aus")}");
            });

        var app = builder.Build();
        app.Use(Kopfzeilen);
        app.Run(Verteile);

        if (!_marken.UiEnabled)
            Log.Warn("web", "die Weboberflaeche ist abgeschaltet - nur die Schnittstelle antwortet. " +
                            $"Einschalten: schleuse ui -c <relay.json> -on   (oder POST {ApiPath}/ui)");
        Log.Info("web", $"Weboberflaeche auf https://{host}:{port}{ApiPath} (Schnittstelle) " +
                        $"und https://{host}:{port}/ (Oberfläche)");
        await app.RunAsync($"https://{host}:{port}").WaitAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Liefert das Zertifikat der Oberflaeche und laedt es neu, wenn sich die
    /// Datei geaendert hat. Geprueft wird hoechstens einmal je Minute, damit
    /// nicht jede Verbindung die Platte anfasst.
    /// </summary>
    X509Certificate2 AktuellesZertifikat()
    {
        if (cfg.Cert is not { Length: > 0 } c || cfg.Key is not { Length: > 0 } k)
        {
            if (_zertifikat is null)
                Log.Warn("web", "kein eigenes Zertifikat eingerichtet - es wird das des Relays verwendet. " +
                                "Der Browser wird warnen, weil es von der eigenen CA stammt.");
            return _zertifikat = relay.OwnCertificate;
        }

        var pfad = Cfg.Rel(cfgPath, c);
        lock (_zertGate)
        {
            var jetzt = DateTimeOffset.UtcNow;
            if (_zertifikat is not null && jetzt - _zertGeprueft < TimeSpan.FromMinutes(1)) return _zertifikat;
            _zertGeprueft = jetzt;

            var stand = File.GetLastWriteTimeUtc(pfad);
            if (_zertifikat is not null && stand == _zertStand) return _zertifikat;

            try
            {
                var neu = Tls.LoadIdentity(pfad, Cfg.Rel(cfgPath, k));
                if (_zertifikat is not null)
                    Log.Info("web", $"Zertifikat erneuert, gültig bis {neu.NotAfter:yyyy-MM-dd}");
                _zertStand = stand;
                return _zertifikat = neu;
            }
            catch (Exception e) when (e is IOException or System.Security.Cryptography.CryptographicException
                                        or FileNotFoundException)
            {
                // Waehrend certbot schreibt, kann die Datei kurz unbrauchbar
                // sein. Dann lieber mit dem alten weitermachen als aussetzen.
                if (_zertifikat is not null)
                {
                    Log.Warn("web", $"Zertifikat nicht lesbar ({e.Message}) - das bisherige bleibt in Gebrauch");
                    return _zertifikat;
                }
                throw;
            }
        }
    }

    /// <summary>
    /// Kopfzeilen, die jede Antwort bekommt. Die Inhaltsregel verbietet alles
    /// ausser den eigenen Stilangaben - die Oberflaeche laedt nichts nach und
    /// fuehrt kein Skript aus, also darf sie das auch nicht duerfen.
    /// </summary>
    static async Task Kopfzeilen(HttpContext c, Func<Task> weiter)
    {
        var h = c.Response.Headers;
        h["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; " +
                                       "frame-ancestors 'none'; base-uri 'none'";
        h["X-Content-Type-Options"] = "nosniff";
        h["Referrer-Policy"] = "no-referrer";
        h["Cache-Control"] = "no-store";
        h["Strict-Transport-Security"] = "max-age=31536000";
        await weiter().ConfigureAwait(false);
    }

    // -- Rahmenwerk ----------------------------------------------------------

    static Task Sende(HttpContext c, string s)
    {
        c.Response.ContentType = "text/html; charset=utf-8";
        return c.Response.WriteAsync(s);
    }

    static Task Weiter(HttpContext c, string pfad)
    {
        c.Response.Redirect(pfad, permanent: false);
        return Task.CompletedTask;
    }

    static Task Status(HttpContext c, int code)
    {
        c.Response.StatusCode = code;
        return Task.CompletedTask;
    }

    WebSession? Sitzung(HttpContext c) => _sitzungen.Hole(c.Request.Cookies[CookieName]);

    void SetzeCookie(HttpContext c, WebSession s) =>
        c.Response.Cookies.Append(CookieName, s.Id, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });

    /// <summary>
    /// Prueft Anmeldung, Merkmal gegen fremde Formulare und - bei Aenderungen -
    /// die Rolle. Liefert null, wenn schon eine Antwort geschrieben wurde.
    /// </summary>
    async Task<(WebSession S, IFormCollection F)?> Post(HttpContext c, bool nurVerwalter = true)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) { await Weiter(c, "/login").ConfigureAwait(false); return null; }

        if (!c.Request.HasFormContentType) { await Status(c, 400).ConfigureAwait(false); return null; }
        var f = await c.Request.ReadFormAsync().ConfigureAwait(false);

        if (!MerkmalStimmt(f["csrf"].ToString(), s.Csrf))
        {
            Log.Warn("web", $"{s.User}: Formular ohne gueltiges Merkmal abgewiesen");
            await Status(c, 400).ConfigureAwait(false);
            return null;
        }

        if (nurVerwalter && s.Role != WebRole.Admin)
        {
            await Sende(c, Html.Seite("Nicht erlaubt", s,
                "<h1>Nicht erlaubt</h1><p class=\"lead\">Dieser Zugang darf nur lesen.</p>")).ConfigureAwait(false);
            return null;
        }

        return (s, f);
    }

    static bool MerkmalStimmt(string gezeigt, string erwartet) =>
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(gezeigt.PadRight(64)[..64]),
            System.Text.Encoding.ASCII.GetBytes(erwartet.PadRight(64)[..64]));

    static string Feld(IFormCollection f, string name, int max = 200)
    {
        var v = f[name].ToString().Trim();
        return v.Length > max ? v[..max] : v;
    }

    // -- Routen --------------------------------------------------------------

    /// <summary>
    /// Eine Tabelle statt eines Routengenerators: was es gibt, steht an einer
    /// Stelle und laesst sich lesen wie ein Inhaltsverzeichnis.
    /// </summary>
    async Task Verteile(HttpContext c)
    {
        var pfad = c.Request.Path.Value ?? "/";
        var post = HttpMethods.IsPost(c.Request.Method);
        if (!post && !HttpMethods.IsGet(c.Request.Method) && !HttpMethods.IsHead(c.Request.Method))
        {
            await Verbergen(c).ConfigureAwait(false);
            return;
        }

        try
        {
            if (IstApi(pfad)) { await ApiVerteile(c).ConfigureAwait(false); return; }

            // Ist die Oberflaeche abgeschaltet, verhaelt sich der Port so, als
            // gaebe es sie nicht. Die Schnittstelle bleibt erreichbar und kann
            // sie wieder einschalten.
            if (!_marken.UiEnabled) { await Verbergen(c).ConfigureAwait(false); return; }

            switch (pfad)
            {
                case "/setup":         await (post ? SetupAnlegen(c) : SetupSeite(c, null)); return;
                case "/login":         await (post ? LoginPasswort(c) : LoginSeite(c, null)); return;
                case "/login/2fa":     await (post ? ZweiterFaktorPruefen(c) : ZweiterFaktorSeite(c, null)); return;
                case "/login/2fa-neu": await (post ? ZweiterFaktorBestaetigen(c) : ZweiterFaktorEinrichten(c, null)); return;
                case "/logout" when post: await Abmelden(c); return;

                case "/":                 if (!post) { await Uebersicht(c); return; } break;
                case "/pending":          if (!post) { await Warteschlange(c, null, null); return; } break;
                case "/pending/approve":  if (post) { await Freigeben(c); return; } break;
                case "/pending/reject":   if (post) { await Entscheiden(c, ablehnen: true); return; } break;
                case "/pending/delete":   if (post) { await Entscheiden(c, ablehnen: false); return; } break;

                case "/devices":          if (!post) { await Geraete(c, null, null); return; } break;
                case "/devices/save":     if (post) { await GeraetSpeichern(c); return; } break;
                case "/devices/delete":   if (post) { await GeraetLoeschen(c); return; } break;

                case "/clients":          if (!post) { await Zugaenge(c, null, null); return; } break;
                case "/clients/save":     if (post) { await ZugangSpeichern(c); return; } break;
                case "/clients/delete":   if (post) { await ZugangLoeschen(c); return; } break;

                case "/users":            if (!post) { await Benutzer(c, null, null); return; } break;
                case "/users/add":        if (post) { await BenutzerAnlegen(c); return; } break;
                case "/users/delete":     if (post) { await BenutzerLoeschen(c); return; } break;
                case "/users/reset":      if (post) { await BenutzerZuruecksetzen(c); return; } break;

                case "/tokens":           if (!post) { await Marken(c, null, null); return; } break;
                case "/tokens/create":    if (post) { await MarkeAnlegen(c); return; } break;
                case "/tokens/delete":    if (post) { await MarkeLoeschen(c); return; } break;

                case "/account":          if (!post) { await Konto(c, null, null); return; } break;
                case "/account/password": if (post) { await PasswortAendern(c); return; } break;
                case "/account/2fa":      if (post) { await ZweiterFaktorNeu(c); return; } break;
            }

            await Weiter(c, Sitzung(c) is { TotpDone: true } ? "/" : "/login").ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // Nie den inneren Fehler an den Browser geben - er koennte Pfade
            // oder Namen enthalten, die niemanden dort etwas angehen.
            Log.Err("web", $"{pfad}: {e}");
            await Status(c, 500).ConfigureAwait(false);
        }
    }

    // -- Ersteinrichtung -----------------------------------------------------

    Task SetupSeite(HttpContext c, string? fehler)
    {
        if (!_users.Leer) return Weiter(c, "/login");
        return Sende(c, Html.Seite("Ersteinrichtung", null, $"""
            <div class="anmelden">
            <h1>Ersteinrichtung</h1>
            <p class="lead">Das Kennwort steht im Protokoll des Relays.</p>
            <form method="post" action="/setup">
              <label>Kennwort aus dem Protokoll</label>
              <input type="text" name="token" autocomplete="off" autofocus required>
              <label>Benutzername</label>
              <input type="text" name="user" autocomplete="username" required>
              <label>Passwort (mindestens 12 Zeichen)</label>
              <input type="password" name="pw" autocomplete="new-password" required>
              <label>Passwort wiederholen</label>
              <input type="password" name="pw2" autocomplete="new-password" required>
              <p><button>Anlegen</button></p>
            </form>
            </div>
            """, fehler: fehler));
    }

    async Task SetupAnlegen(HttpContext c)
    {
        if (!_users.Leer || _setupToken is null) { await Weiter(c, "/login").ConfigureAwait(false); return; }
        var f = await c.Request.ReadFormAsync().ConfigureAwait(false);

        if (!Fingerprint.Same(Feld(f, "token"), _setupToken))
        {
            Log.Warn("web", $"Ersteinrichtung mit falschem Kennwort von {c.Connection.RemoteIpAddress}");
            { await SetupSeite(c, "Das Kennwort stimmt nicht.").ConfigureAwait(false); return; }
        }
        var name = Feld(f, "user", 32);
        var pw = f["pw"].ToString();
        if (!UserStore.IstBrauchbarerName(name)) { await SetupSeite(c, "Unbrauchbarer Benutzername.").ConfigureAwait(false); return; }
        if (pw.Length < 12) { await SetupSeite(c, "Das Passwort ist zu kurz.").ConfigureAwait(false); return; }
        if (pw != f["pw2"].ToString()) { await SetupSeite(c, "Die Passwörter stimmen nicht überein.").ConfigureAwait(false); return; }

        var u = _users.Anlegen(name, pw, WebRole.Admin, mussAendern: false);
        _setupToken = null;
        Log.Info("web", $"erster Verwalter '{name}' angelegt");

        var s = _sitzungen.Anlegen(u.Name, u.Role, totpFertig: false);
        SetzeCookie(c, s);
        await Weiter(c, "/login/2fa-neu").ConfigureAwait(false);
    }

    // -- Anmeldung -----------------------------------------------------------

    Task LoginSeite(HttpContext c, string? fehler)
    {
        if (_users.Leer) return Weiter(c, "/setup");
        if (Sitzung(c) is { TotpDone: true }) return Weiter(c, "/");
        return Sende(c, Html.Seite("Anmelden", null, """
            <div class="anmelden">
            <h1>Anmelden</h1>
            <form method="post" action="/login">
              <label>Benutzername</label>
              <input type="text" name="user" autocomplete="username" autofocus required>
              <label>Passwort</label>
              <input type="password" name="pw" autocomplete="current-password" required>
              <p><button>Weiter</button></p>
            </form>
            </div>
            """, fehler: fehler));
    }

    async Task LoginPasswort(HttpContext c)
    {
        var f = await c.Request.ReadFormAsync().ConfigureAwait(false);
        var name = Feld(f, "user", 32);
        var von = c.Connection.RemoteIpAddress;

        // Erst bremsen, dann rechnen. Eine Passwortableitung kostet absichtlich
        // Rechenzeit - auf kleinen Maschinen ueber eine Sekunde. Wer sie ohne
        // Vorbedingung ausloesen kann, legt damit die Maschine lahm.
        var warte = Bremse("login:" + von, nurLesen: true);
        if (warte > TimeSpan.FromMilliseconds(300))
        {
            await Task.Delay(warte).ConfigureAwait(false);
            { await LoginSeite(c, "Zu viele Fehlversuche. Bitte etwas warten.").ConfigureAwait(false); return; }
        }

        var (ok, grund) = _users.PruefePasswort(name, f["pw"].ToString());

        if (!ok)
        {
            Log.Warn("web", $"Anmeldung fehlgeschlagen: '{Log.Safe(name)}' von {von}{(grund is null ? "" : " - " + grund)}");
            // Dieselbe Bremse wie an der Schnittstelle: waechst mit der Zahl der
            // Fehlversuche aus derselben Richtung. Eine Passwortpruefung kostet
            // absichtlich Rechenzeit, also darf sie nicht beliebig oft angestossen
            // werden koennen.
            await Task.Delay(Bremse("login:" + von)).ConfigureAwait(false);
            { await LoginSeite(c, grund ?? "Benutzername oder Passwort stimmt nicht.").ConfigureAwait(false); return; }
        }

        var u = _users.Finde(name)!;
        var s = _sitzungen.Anlegen(u.Name, u.Role, totpFertig: false);
        SetzeCookie(c, s);
        { await Weiter(c, u.ZweiFaktorFertig ? "/login/2fa" : "/login/2fa-neu").ConfigureAwait(false); return; }
    }

    Task ZweiterFaktorSeite(HttpContext c, string? fehler)
    {
        var s = Sitzung(c);
        if (s is null) return Weiter(c, "/login");
        if (s.TotpDone) return Weiter(c, "/");
        return Sende(c, Html.Seite("Zweiter Faktor", null, $"""
            <div class="anmelden">
            <h1>Zweiter Faktor</h1>
            <p class="lead">Der sechsstellige Code aus der Authenticator-App.
               Ein Wiederherstellungscode geht auch.</p>
            <form method="post" action="/login/2fa">
              <input type="hidden" name="csrf" value="{Html.E(s.Csrf)}">
              <label>Code</label>
              <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
              <p><button>Anmelden</button></p>
            </form>
            </div>
            """, fehler: fehler));
    }

    async Task ZweiterFaktorPruefen(HttpContext c)
    {
        var s = Sitzung(c);
        if (s is null) { await Weiter(c, "/login").ConfigureAwait(false); return; }
        var f = await c.Request.ReadFormAsync().ConfigureAwait(false);
        if (f["csrf"].ToString() != s.Csrf) { await Status(c, 400).ConfigureAwait(false); return; }

        if (!_users.PruefeTotp(s.User, Feld(f, "code", 64)))
        {
            Log.Warn("web", $"{s.User}: zweiter Faktor falsch, von {c.Connection.RemoteIpAddress}");
            await Task.Delay(500).ConfigureAwait(false);
            { await ZweiterFaktorSeite(c, "Der Code stimmt nicht.").ConfigureAwait(false); return; }
        }

        s.TotpDone = true;
        var neu = _sitzungen.Erneuern(s);   // neue Kennung nach der Anmeldung
        SetzeCookie(c, neu);
        Log.Info("web", $"{neu.User} angemeldet von {c.Connection.RemoteIpAddress}");
        { await Weiter(c, "/").ConfigureAwait(false); return; }
    }

    Task ZweiterFaktorEinrichten(HttpContext c, string? fehler)
    {
        var s = Sitzung(c);
        if (s is null) return Weiter(c, "/login");
        var u = _users.Finde(s.User);
        if (u is null) return Weiter(c, "/login");
        if (u.Totp is not { Length: > 0 }) _users.NeuesTotp(s.User);
        u = _users.Finde(s.User)!;

        var uri = Totp.OtpAuthUri(u.Name, cfg.Issuer, Base32.TryDecode(u.Totp!, out var g) ? g : []);

        // Der QR-Code steht als SVG im Dokument, nicht als nachgeladenes Bild:
        // die Inhaltsregel bleibt damit bei default-src 'none'. Kodiert wird
        // hier im Haus - die Zeile enthaelt das Geheimnis des zweiten Faktors,
        // sie an einen Dienst im Netz zu schicken hoebe die ganze Uebung auf.
        var qr = QrCode.Svg(QrCode.Encode(uri), "QR-Code mit der Einrichtungszeile");

        return Sende(c, Html.Seite("Zweiten Faktor einrichten", null, $"""
            <div class="anmelden" style="max-width:34rem">
            <h1>Zweiten Faktor einrichten</h1>
            <p class="lead">In der Authenticator-App scannen und dann einen Code
               eingeben.</p>
            <div class="karte">
              <p class="qr">{qr}</p>
              <p class="schwach">Geht das Scannen nicht, von Hand hinzufügen:</p>
              <p class="schwach">Geheimnis</p>
              <p class="fp">{Html.E(Base32.Group(u.Totp!))}</p>
              <p class="schwach">Verfahren: TOTP, SHA-1, 6 Stellen, 30 Sekunden</p>
              <p class="schwach">Vollständige Zeile für Apps, die sie annehmen:</p>
              <pre>{Html.E(uri)}</pre>
            </div>
            <form method="post" action="/login/2fa-neu">
              <input type="hidden" name="csrf" value="{Html.E(s.Csrf)}">
              <label>Code aus der App</label>
              <input type="text" name="code" inputmode="numeric" class="klein" autofocus required>
              <p><button>Bestätigen</button></p>
            </form>
            </div>
            """, fehler: fehler));
    }

    async Task ZweiterFaktorBestaetigen(HttpContext c)
    {
        var s = Sitzung(c);
        if (s is null) { await Weiter(c, "/login").ConfigureAwait(false); return; }
        var f = await c.Request.ReadFormAsync().ConfigureAwait(false);
        if (f["csrf"].ToString() != s.Csrf) { await Status(c, 400).ConfigureAwait(false); return; }

        if (!_users.PruefeTotp(s.User, Feld(f, "code", 16)))
            { await ZweiterFaktorEinrichten(c, "Der Code stimmt nicht. Stimmt die Uhrzeit des Geräts?").ConfigureAwait(false); return; }

        var codes = _users.NeueWiederherstellung(s.User);
        s.TotpDone = true;
        s.Einmalig = string.Join("\n", codes);
        var neu = _sitzungen.Erneuern(s);
        SetzeCookie(c, neu);
        Log.Info("web", $"{neu.User}: zweiter Faktor eingerichtet");
        { await Weiter(c, "/account").ConfigureAwait(false); return; }
    }

    async Task Abmelden(HttpContext c)
    {
        var s = Sitzung(c);
        if (s is not null)
        {
            var f = await c.Request.ReadFormAsync().ConfigureAwait(false);
            if (f["csrf"].ToString() == s.Csrf) _sitzungen.Beenden(s.Id);
        }
        c.Response.Cookies.Delete(CookieName);
        { await Weiter(c, "/login").ConfigureAwait(false); return; }
    }

    // -- Uebersicht ----------------------------------------------------------

    Task Uebersicht(HttpContext c)
    {
        var s = Sitzung(c);
        if (s is not { TotpDone: true }) return Weiter(c, "/login");

        var online = relay.Online();
        var tunnel = relay.Tunnels();
        var offen = relay.Pending?.Alle().Count(r => r.State == PendingState.Pending) ?? 0;
        var acl = relay.CurrentAcl;

        var warte = offen == 0 ? "" : $"""
            <p class="hinweis">{offen} Anmeldung{(offen == 1 ? "" : "en")} wartet auf Freigabe -
               <a href="/pending">ansehen</a></p>
            """;

        var geraete = online.Count == 0
            ? "<p class=\"schwach\">Zurzeit ist kein Gerät verbunden.</p>"
            : $"""
               <table><tr><th>Gerät</th><th>Dienste</th><th>Online</th><th>Sitzungen</th><th>Notiz</th></tr>
               {string.Concat(online.Select(d => $"""
                 <tr><td class="mono">{Html.E(d.Device)}</td>
                     <td>{string.Concat(d.Services.Select(x =>
                          acl.ServiceReleased(d.Device, x)
                            ? $"<span class=\"an\">{Html.E(x)}</span> "
                            : $"<span class=\"aus\"><s>{Html.E(x)}</s></span> "))}</td>
                     <td>{Dauer(d.OnlineSec)}</td><td>{d.Streams}</td>
                     <td class="schwach">{Html.E(d.Note)}</td></tr>
                 """))}
               </table>
               <p class="schwach">Durchgestrichene Dienste bietet das Gerät an, sie sind aber nicht freigegeben.</p>
               """;

        var sitzungen = tunnel.Count == 0
            ? "<p class=\"schwach\">Zurzeit läuft keine Sitzung.</p>"
            : $"""
               <table><tr><th>Zugang</th><th>Gerät</th><th>Dienst</th></tr>
               {string.Concat(tunnel.Select(t => $"""
                 <tr><td class="mono">{Html.E(t.Client)}</td><td class="mono">{Html.E(t.Device)}</td>
                     <td class="mono">{Html.E(t.Service)}</td></tr>
                 """))}
               </table>
               """;

        return Sende(c, Html.Seite("Übersicht", s, $"""
            <h1>Übersicht</h1>
            <p class="lead">{online.Count} Gerät{(online.Count == 1 ? "" : "e")} verbunden,
               {tunnel.Count} laufende Sitzung{(tunnel.Count == 1 ? "" : "en")}.</p>
            {warte}
            <h2>Verbundene Geräte</h2>
            {geraete}
            <h2>Laufende Sitzungen</h2>
            {sitzungen}
            """));
    }

    static string Dauer(long sek) => sek switch
    {
        < 60 => $"{sek} s",
        < 3600 => $"{sek / 60} min",
        < 86400 => $"{sek / 3600} h",
        _ => $"{sek / 86400} T",
    };
}
