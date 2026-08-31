using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Schleuse;

/// <summary>
/// Kurze, vorlesbare Fingerabdruecke. Zwei Stellen brauchen sie:
///
///   CA-Pin        Damit ein Geraet bei seiner allerersten Verbindung weiss, mit
///                 wem es spricht. Kein Geheimnis - er darf im Handbuch stehen
///                 und ist fuer alle Geraete einer Anlage derselbe.
///
///   Schluessel    Beim Freigeben eines Antrags. Das Geraet zeigt ihn beim
///                 Anmelden an, die Oberflaeche zeigt ihn dem Betreiber. Stimmen
///                 beide ueberein, hat niemand den Antrag unterwegs ausgetauscht.
///
/// 10 Byte aus SHA-256, Base32 in Vierergruppen: 16 Zeichen, 80 Bit.
/// </summary>
internal static class Fingerprint
{
    public const int Bytes = 10;

    public static string OfCertificate(X509Certificate2 cert) => Format(SHA256.HashData(cert.RawData));

    public static string OfPublicKey(PublicKey key) => Format(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    static string Format(byte[] hash) => Base32.Group(Base32.Encode(hash.AsSpan(0, Bytes)));

    /// <summary>Vergleicht zwei Fingerabdruecke, unabhaengig von Gruppierung und Schreibweise.</summary>
    public static bool Same(string a, string b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.Ordinal);

    static string Normalize(string s) =>
        new([.. s.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant)]);
}
