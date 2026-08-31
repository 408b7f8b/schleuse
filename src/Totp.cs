using System.Security.Cryptography;

namespace Schleuse;

/// <summary>
/// Zeitbasierte Einmalkennwoerter nach RFC 6238 - das, was Authenticator-Apps
/// erzeugen. HMAC-SHA1, sechs Stellen, dreissig Sekunden; das ist nicht
/// modern, aber es ist das, was jede App kann.
///
/// Die Umsetzung wird gegen die Testvektoren aus Anhang B der Spezifikation
/// geprueft (scripts/webtest.sh), damit sie nicht bloss ploausibel aussieht.
/// </summary>
internal static class Totp
{
    public const int Digits = 6;
    public const int PeriodSeconds = 30;

    /// <summary>Ein Zeitfenster Toleranz nach vorn und hinten - fuer ungenaue Uhren.</summary>
    public const int Skew = 1;

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static string Code(byte[] secret, long counter, int digits = Digits, HashAlgorithmName? alg = null)
    {
        Span<byte> ctr = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(ctr, counter);

        Span<byte> mac = stackalloc byte[64];
        int len = (alg?.Name) switch
        {
            "SHA256" => HMACSHA256.HashData(secret, ctr, mac),
            "SHA512" => HMACSHA512.HashData(secret, ctr, mac),
            _ => HMACSHA1.HashData(secret, ctr, mac),
        };

        int offset = mac[len - 1] & 0x0F;
        int bin = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16)
                | (mac[offset + 2] << 8) | mac[offset + 3];

        var mod = (int)Math.Pow(10, digits);
        return (bin % mod).ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    public static long CounterFor(DateTimeOffset zeit) => zeit.ToUnixTimeSeconds() / PeriodSeconds;

    /// <summary>
    /// Prueft eine Eingabe. Liefert den verwendeten Zaehler zurueck, damit der
    /// Aufrufer denselben Code kein zweites Mal gelten laesst - sonst koennte
    /// ihn jemand innerhalb des Zeitfensters wiederverwenden.
    /// </summary>
    public static bool Verify(byte[] secret, string eingabe, DateTimeOffset jetzt, long zuletzt, out long counter)
    {
        counter = 0;
        var ziffern = new string([.. eingabe.Where(char.IsAsciiDigit)]);
        if (ziffern.Length != Digits) return false;

        var mitte = CounterFor(jetzt);
        for (long c = mitte - Skew; c <= mitte + Skew; c++)
        {
            if (c <= zuletzt) continue; // schon einmal benutzt
            var erwartet = Code(secret, c);
            if (CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(erwartet),
                    System.Text.Encoding.ASCII.GetBytes(ziffern)))
            {
                counter = c;
                return true;
            }
        }
        return false;
    }

    /// <summary>Die Zeile, die eine Authenticator-App erwartet.</summary>
    public static string OtpAuthUri(string benutzer, string ausgeber, byte[] secret) =>
        $"otpauth://totp/{System.Uri.EscapeDataString(ausgeber)}:{System.Uri.EscapeDataString(benutzer)}" +
        $"?secret={Base32.Encode(secret)}&issuer={System.Uri.EscapeDataString(ausgeber)}" +
        $"&algorithm=SHA1&digits={Digits}&period={PeriodSeconds}";
}
