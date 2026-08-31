namespace Schleuse;

/// <summary>
/// Base32 nach RFC 4648 ohne Fuellzeichen. Gebraucht fuer Anmelde-Token und
/// fuer TOTP-Geheimnisse: beides muss ein Mensch abtippen oder vorlesen
/// koennen, ohne ueber Gross- und Kleinschreibung zu stolpern.
/// </summary>
internal static class Base32
{
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new System.Text.StringBuilder((data.Length * 8 + 4) / 5);
        int puffer = 0, bits = 0;
        foreach (var b in data)
        {
            puffer = (puffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(puffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(puffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static bool TryDecode(string text, out byte[] data)
    {
        data = [];
        var roh = new List<byte>(text.Length * 5 / 8 + 1);
        int puffer = 0, bits = 0;
        foreach (var zeichen in text)
        {
            if (zeichen is '-' or ' ' or '=' or '\t') continue; // Gruppierung und Fuellzeichen
            var c = char.ToUpperInvariant(zeichen);
            var i = Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (i < 0) return false;
            puffer = (puffer << 5) | i;
            bits += 5;
            if (bits >= 8)
            {
                roh.Add((byte)((puffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        data = [.. roh];
        return true;
    }

    /// <summary>Vierergruppen mit Bindestrich - so laesst sich ein Token vorlesen und abtippen.</summary>
    public static string Group(string s, int je = 4)
    {
        var sb = new System.Text.StringBuilder(s.Length + s.Length / je);
        for (int i = 0; i < s.Length; i++)
        {
            if (i > 0 && i % je == 0) sb.Append('-');
            sb.Append(s[i]);
        }
        return sb.ToString();
    }
}
