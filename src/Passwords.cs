using System.Security.Cryptography;

namespace Schleuse;

/// <summary>
/// Passwortablage: PBKDF2-HMAC-SHA256 aus der Standardbibliothek. Argon2 waere
/// die bessere Wahl, braeuchte aber eine Fremdbibliothek - und die einzige
/// Abhaengigkeit dieses Programms sollte nicht ausgerechnet an der Stelle
/// stehen, an der Passwoerter liegen.
///
/// Format:  pbkdf2-sha256$&lt;runden&gt;$&lt;salz base64&gt;$&lt;hash base64&gt;
/// Die Rundenzahl steht mit in der Zeile, damit sie sich spaeter anheben laesst,
/// ohne bestehende Eintraege zu entwerten.
/// </summary>
internal static class Passwords
{
    public const int Iterations = 600_000;   // Empfehlung des OWASP fuer SHA-256
    const int SaltBytes = 16;
    const int HashBytes = 32;
    const string Prefix = "pbkdf2-sha256";

    /// <summary>Wird beim Start aus der Konfiguration gesetzt.</summary>
    public static int Runden { get; set; } = Iterations;

    /// <summary>Misst, wie lange eine Ableitung mit der eingestellten Rundenzahl dauert.</summary>
    public static TimeSpan Messen()
    {
        var uhr = System.Diagnostics.Stopwatch.StartNew();
        Rfc2898DeriveBytes.Pbkdf2("messung", new byte[SaltBytes], Runden, HashAlgorithmName.SHA256, HashBytes);
        return uhr.Elapsed;
    }

    public static string Hash(string passwort, int runden = 0)
    {
        if (runden <= 0) runden = Runden;
        var salz = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(passwort, salz, runden, HashAlgorithmName.SHA256, HashBytes);
        return $"{Prefix}${runden}${Convert.ToBase64String(salz)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string gespeichert, string passwort)
    {
        var teile = gespeichert.Split('$');
        if (teile.Length != 4 || teile[0] != Prefix) return false;
        if (!int.TryParse(teile[1], out var runden) || runden is < 1000 or > 10_000_000) return false;

        byte[] salz, erwartet;
        try { salz = Convert.FromBase64String(teile[2]); erwartet = Convert.FromBase64String(teile[3]); }
        catch (FormatException) { return false; }

        var ist = Rfc2898DeriveBytes.Pbkdf2(passwort, salz, runden, HashAlgorithmName.SHA256, erwartet.Length);
        return CryptographicOperations.FixedTimeEquals(ist, erwartet);
    }

    /// <summary>Ein zufaelliges Anfangspasswort, das sich vorlesen laesst.</summary>
    public static string Suggest() => Base32.Group(Base32.Encode(RandomNumberGenerator.GetBytes(10)), 5);
}
