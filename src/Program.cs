using System.Runtime.InteropServices;

// schleuse ist ein Linux-Dienst; das erspart Plattform-Fallunterscheidungen bei
// Dateirechten und Signalen.
[assembly: System.Runtime.Versioning.SupportedOSPlatform("linux")]

namespace Schleuse;

internal static class Program
{
    const string Version = "1.0.0";

    static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; cts.Cancel(); });

        try
        {
            return await DispatchAsync(args, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception e)
        {
            Log.Err("schleuse", e.Message);
            if (Log.Debug) Console.Error.WriteLine(e);
            return 1;
        }
    }

    static async Task<int> DispatchAsync(string[] args, CancellationToken ct)
    {
        if (args.Length == 0) { Usage(); return 2; }

        var opt = new Options(args[1..]);
        Log.Debug = opt.Flag("v") || opt.Flag("debug");

        switch (args[0])
        {
            case "relay":
            {
                var path = opt.Value("c") ?? "/etc/schleuse/relay.json";
                var cfg = Cfg.Load(path, JsonCfg.Default.RelayConfig);
                opt.Reject();

                var relay = new Relay(cfg, path);
                relay.Initialize();

                // Vermittlung und Weboberflaeche laufen nebeneinander im selben
                // Prozess, aber auf getrennten Ports. Faellt eine der beiden aus,
                // endet der Dienst - systemd startet ihn neu.
                var laeuft = new List<Task> { relay.RunAsync(ct) };
                if (cfg.Web is { } web) laeuft.Add(new WebUi(relay, web, path).RunAsync(ct));

                var fertig = await Task.WhenAny(laeuft).ConfigureAwait(false);
                await fertig.ConfigureAwait(false);
                return 0;
            }

            case "agent":
            {
                var path = opt.Value("c") ?? "/etc/schleuse/agent.json";
                var cfg = Cfg.Load(path, JsonCfg.Default.AgentConfig);
                opt.Reject();
                return await new Agent(cfg, path).RunAsync(ct).ConfigureAwait(false);
            }

            case "client":
            {
                var path = opt.Value("c") ?? DefaultClientConfig();
                var cfg = Cfg.Load(path, JsonCfg.Default.ClientConfig);
                if (opt.Value("relay") is { } r) cfg.Relay = r;

                var device = opt.Value("device");
                var service = opt.Value("service");
                var listen = opt.Value("listen");
                var stdio = opt.Flag("stdio");
                var list = opt.Flag("list");
                var forwards = opt.Values("forward").Select(Forward.Parse).ToList();
                opt.Reject();

                var c = new TunnelClient(cfg, path);

                if (list)
                {
                    if (stdio || listen is not null || forwards.Count > 0)
                        throw new ArgumentException("-list vertraegt sich nicht mit -stdio, -listen oder -forward");
                    return await c.RunListAsync(ct).ConfigureAwait(false);
                }

                if (stdio)
                {
                    if (listen is not null || forwards.Count > 0)
                        throw new ArgumentException("-stdio vertraegt sich nicht mit -listen oder -forward");
                    Log.AllToStderr = true;
                    return await c.RunStdioAsync(
                        device ?? throw new ArgumentException("-device fehlt"),
                        service ?? "ssh", ct).ConfigureAwait(false);
                }

                // Kurzform fuer eine einzelne Weiterleitung.
                if (listen is not null)
                    forwards.Add(new Forward
                    {
                        Listen = listen,
                        Device = device ?? throw new ArgumentException("-device fehlt"),
                        Service = service ?? "ssh",
                    });
                else if (device is not null)
                    throw new ArgumentException("-device braucht -listen, -stdio oder -forward");

                // Ohne Angabe auf der Kommandozeile gilt, was in der Konfiguration steht.
                if (forwards.Count == 0) forwards.AddRange(cfg.Forwards);
                if (forwards.Count == 0)
                    throw new ArgumentException($"keine Weiterleitung angegeben und keine in {path} hinterlegt");

                return await c.RunForwardsAsync(forwards, ct).ConfigureAwait(false);
            }

            case "enroll":
            {
                var relay = opt.Value("relay") ?? throw new ArgumentException("-relay <host:port> fehlt");
                var pin = opt.Value("ca-pin") ?? throw new ArgumentException("-ca-pin <fingerabdruck> fehlt");
                var dir = opt.Value("dir") ?? "/etc/schleuse";
                var name = opt.Value("name") ?? Environment.MachineName;
                var interval = int.TryParse(opt.Value("interval"), out var iv) ? Math.Clamp(iv, 1, 3600) : 5;
                var dienste = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var spec in opt.Values("service"))
                {
                    var eq = spec.IndexOf('=');
                    if (eq < 0) throw new ArgumentException($"'{spec}': erwartet name=host:port");
                    dienste[spec[..eq]] = spec[(eq + 1)..];
                }
                opt.Reject();

                Net.SplitHostPort(relay);
                foreach (var (dn, ziel) in dienste)
                {
                    if (!Tls.IsSaneName(dn)) throw new ArgumentException($"unbrauchbarer Dienstname '{dn}'");
                    Net.SplitHostPort(ziel);
                }

                return await new EnrollClient(relay, pin, dir, name, dienste,
                                              TimeSpan.FromSeconds(interval)).RunAsync(ct).ConfigureAwait(false);
            }

            case "ui":
            {
                var path = opt.Value("c") ?? "/etc/schleuse/relay.json";
                var cfg = Cfg.Load(path, JsonCfg.Default.RelayConfig);
                var an = opt.Flag("on");
                var aus = opt.Flag("off");
                opt.Reject();
                if (an && aus) throw new ArgumentException("-on und -off gleichzeitig ergibt nichts");
                if (cfg.Web is not { } web) throw new InvalidDataException($"{path}: kein Abschnitt \"web\"");

                // Notausgang, falls die Oberflaeche ueber die Schnittstelle
                // abgeschaltet wurde und die Marke verlorenging.
                var store = new ApiTokenStore(Cfg.Rel(path, web.State));
                if (an || aus) store.SetUiEnabled(an);
                Console.WriteLine($"Weboberfläche: {(store.UiEnabled ? "eingeschaltet" : "abgeschaltet")}");
                if (an || aus) Console.WriteLine("Wirksam nach: systemctl reload schleuse-relay");
                return 0;
            }

            case "verify-crypto":
            {
                // -qr ist ein Pruefwerkzeug: es gibt die Modulraster zu den
                // Zeilen der Standardeingabe aus, damit scripts/qr-gegenpruefen.py
                // den Kodierer gegen eine unabhaengige Umsetzung stellen kann.
                var qr = opt.Flag("qr");
                opt.Reject();
                return qr ? VerifyCrypto.DumpQr() : VerifyCrypto.Run();
            }

            case "version" or "-version" or "--version":
                Console.WriteLine($"schleuse {Version} ({RuntimeInformation.RuntimeIdentifier})");
                return 0;

            case "help" or "-h" or "--help":
                Usage();
                return 0;

            default:
                Log.Err("schleuse", $"unbekannter Befehl '{args[0]}'");
                Usage();
                return 2;
        }
    }

    static string DefaultClientConfig()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        var baseDir = string.IsNullOrEmpty(xdg) ? Path.Combine(home, ".config") : xdg;
        return Path.Combine(baseDir, "schleuse", "client.json");
    }

    static void Usage() => Console.WriteLine("""
        schleuse - Reverse-Tunnel fuer Linux-Geraete hinter NAT/Firewall

          schleuse relay  [-c /etc/schleuse/relay.json]
              Vermittlungsdienst im Internet. Einziger offener Port.

          schleuse agent  [-c /etc/schleuse/agent.json]
              Dienst auf dem Geraet. Baut nur ausgehende Verbindungen auf.

          schleuse client [-c ~/.config/schleuse/client.json] [-relay host:port]
              -forward <geraet>/<dienst>=<adresse:port> ...   mehrfach moeglich
              -device <id> [-service ssh] -listen <adresse:port>   Kurzform
              -device <id> [-service ssh] -stdio                   fuer ProxyCommand
              -list                                                Uebersicht
              Ohne Angabe gilt, was unter "forwards" in der Konfiguration steht.

          schleuse enroll -relay <host:port> -ca-pin <fingerabdruck>
                      [-dir /etc/schleuse] [-name <bezeichnung>]
                      [-service ssh=127.0.0.1:22] ...
              Einmalige Selbstanmeldung eines neuen Geraets. Erzeugt den
              Schluessel auf dem Geraet und wartet auf die Freigabe durch den
              Betreiber. Enthaelt kein Geheimnis - dieselbe Zeile passt fuer
              jedes Geraet einer Anlage.

          schleuse ui [-c /etc/schleuse/relay.json] [-on | -off]
              Zeigt oder setzt, ob die Weboberfläche bedienbar ist. Notausgang,
              wenn sie über die Schnittstelle abgeschaltet wurde.

          schleuse verify-crypto
              Rechnet die eingebauten Verfahren gegen die Testvektoren ihrer
              Spezifikationen nach (TOTP, Base32, PBKDF2).

          schleuse version

        Beispiele:
          schleuse client -list
          GERAET                   DIENSTE                             ONLINE  SITZUNGEN

          Mehrere Geraete und Protokolle in einem Prozess:
            schleuse client -forward werk1/ssh=127.0.0.1:2201 \
                        -forward werk1/http=127.0.0.1:8001 \
                        -forward werk2/ssh=127.0.0.1:2202 \
                        -forward werk2/modbus=127.0.0.1:5021
            ssh -p 2201 root@127.0.0.1
            curl http://127.0.0.1:8001/

          Einzelne Weiterleitung:
            schleuse client -device werk1 -service ssh -listen 127.0.0.1:2222
            scp -P 2222 datei.bin root@127.0.0.1:/tmp/

          Ohne offenen Port, als ProxyCommand:
            ssh -o ProxyCommand='schleuse client -device werk1 -service ssh -stdio' root@werk1

        Optionen:
          -v, -debug   ausfuehrliche Protokollierung
        """);
}

/// <summary>Winziger Argumentparser: -flag und -name wert. Nicht mehr, als hier gebraucht wird.</summary>
internal sealed class Options
{
    readonly Dictionary<string, List<string?>> _opts = new(StringComparer.Ordinal);
    readonly HashSet<string> _used = new(StringComparer.Ordinal);

    public Options(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (!a.StartsWith('-')) throw new ArgumentException($"unerwartetes Argument '{a}'");
            var name = a.TrimStart('-');
            if (name.Length == 0) throw new ArgumentException("leere Option");

            string? wert;
            var eq = name.IndexOf('=');
            if (eq >= 0) { wert = name[(eq + 1)..]; name = name[..eq]; }
            else if (i + 1 < args.Length && !args[i + 1].StartsWith('-')) wert = args[++i];
            else wert = null;

            if (!_opts.TryGetValue(name, out var liste)) _opts[name] = liste = [];
            liste.Add(wert);
        }
    }

    public string? Value(string name)
    {
        _used.Add(name);
        if (!_opts.TryGetValue(name, out var v)) return null;
        if (v.Count > 1) throw new ArgumentException($"-{name} mehrfach angegeben");
        return v[0];
    }

    /// <summary>Wiederholbare Option, etwa mehrere -forward.</summary>
    public IEnumerable<string> Values(string name)
    {
        _used.Add(name);
        if (!_opts.TryGetValue(name, out var v)) return [];
        return v.Select(x => x ?? throw new ArgumentException($"-{name} braucht einen Wert"));
    }

    public bool Flag(string name)
    {
        _used.Add(name);
        return _opts.ContainsKey(name);
    }

    /// <summary>Meldet Optionen, die niemand abgeholt hat - schuetzt vor stillen Tippfehlern.</summary>
    public void Reject()
    {
        foreach (var k in _opts.Keys)
            if (!_used.Contains(k)) throw new ArgumentException($"unbekannte Option '-{k}'");
    }
}
