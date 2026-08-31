namespace Schleuse;

/// <summary>
/// Eine Zeile pro Ereignis nach stdout, damit journald/logfmt-Tools sie lesen koennen.
/// Kein Logging-Framework: das waere die groesste Abhaengigkeit im ganzen Programm.
/// </summary>
internal static class Log
{
    public static bool Debug;

    /// <summary>Im ProxyCommand-Modus ist stdout der Tunnel - dann darf dort nichts anderes landen.</summary>
    public static bool AllToStderr;

    static readonly Lock Gate = new();

    public static void Dbg(string comp, string msg) { if (Debug) Write("debug", comp, msg); }
    public static void Info(string comp, string msg) => Write("info", comp, msg);
    public static void Warn(string comp, string msg) => Write("warn", comp, msg);
    public static void Err(string comp, string msg) => Write("error", comp, msg);

    /// <summary>
    /// Entschaerft Text aus fremder Hand (Zertifikatsnamen, Protokollfelder)
    /// fuer die Ausgabe: Steuerzeichen koennten sonst gefaelschte Logzeilen
    /// einschmuggeln.
    /// </summary>
    public static string Safe(string s) => Clean(s.Length > 128 ? s[..128] + "..." : s);

    /// <summary>
    /// Nur die Steuerzeichen ersetzen, ohne zu kuerzen. Fuer Text, der irgendwo
    /// gespeichert wird und eine eigene Laengengrenze hat - die Kuerzung fuers
    /// Logbuch waere dort die falsche.
    /// </summary>
    public static string Clean(string s)
    {
        // Nicht auf dem Stapel anlegen: der Text kommt aus einer Anfrage und
        // darf bis zur Rumpfgrenze lang sein. Ein stackalloc dieser Groesse
        // waere ein Ueberlauf mit Ansage.
        var i = s.AsSpan().IndexOfAnyInRange('\0', '\u001f');
        if (i < 0 && s.AsSpan().IndexOf('\u007f') < 0) return s;   // der Normalfall: nichts zu tun

        return string.Create(s.Length, s, static (ziel, quelle) =>
        {
            for (int k = 0; k < quelle.Length; k++)
                ziel[k] = char.IsControl(quelle[k]) ? '?' : quelle[k];
        });
    }

    static void Write(string level, string comp, string msg)
    {
        var line = $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} {level,-5} {comp,-6} {msg}";
        lock (Gate)
        {
            var w = AllToStderr || level is "error" or "warn" ? Console.Error : Console.Out;
            w.WriteLine(line);
            w.Flush();
        }
    }
}
