using System.Security.Cryptography;
using System.Text;

namespace Schleuse;

/// <summary>
/// Prueft die selbst umgesetzten Verfahren gegen die Testvektoren ihrer
/// Spezifikationen. Selbstgeschriebene Krypto-Bausteine, die nur plausibel
/// aussehen, sind die haeufigste Ursache stiller Sicherheitsluecken - hier
/// laesst sich jederzeit nachrechnen, dass sie stimmen.
/// </summary>
internal static class VerifyCrypto
{
    public static int Run()
    {
        int fehler = 0;

        // --- RFC 6238, Anhang B: TOTP mit HMAC-SHA1, acht Stellen ----------
        var geheim = Encoding.ASCII.GetBytes("12345678901234567890");
        (long Zeit, string Code)[] vektoren =
        [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        foreach (var (zeit, erwartet) in vektoren)
        {
            var ist = Totp.Code(geheim, zeit / Totp.PeriodSeconds, digits: 8);
            fehler += Pruefe($"RFC 6238 TOTP t={zeit}", ist, erwartet);
        }

        // --- RFC 4648, Anhang: Base32 --------------------------------------
        (string Klar, string Kodiert)[] b32 =
        [
            ("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI"),
        ];
        foreach (var (klar, kodiert) in b32)
        {
            fehler += Pruefe($"Base32 '{klar}'", Base32.Encode(Encoding.ASCII.GetBytes(klar)), kodiert);
            if (!Base32.TryDecode(kodiert, out var zurueck)) { Console.WriteLine($"FEHL Base32 decode '{kodiert}'"); fehler++; }
            else fehler += Pruefe($"Base32 zurueck '{kodiert}'", Encoding.ASCII.GetString(zurueck), klar);
        }

        // --- RFC 6070: PBKDF2-HMAC-SHA1, zur Absicherung der Parameterlage --
        var dk = Rfc2898DeriveBytes.Pbkdf2(Encoding.ASCII.GetBytes("password"),
                                           Encoding.ASCII.GetBytes("salt"), 4096, HashAlgorithmName.SHA1, 20);
        fehler += Pruefe("RFC 6070 PBKDF2", Convert.ToHexString(dk).ToLowerInvariant(),
                         "4b007901b765489abead49d926f721d065a429c1");

        // --- Eigene Zusagen -------------------------------------------------
        var pw = Passwords.Hash("hunter2");
        fehler += Pruefe("Passwort stimmt", Passwords.Verify(pw, "hunter2").ToString(), "True");
        fehler += Pruefe("falsches Passwort", Passwords.Verify(pw, "hunter3").ToString(), "False");
        fehler += Pruefe("zwei Hashes verschieden", (Passwords.Hash("x") != Passwords.Hash("x")).ToString(), "True");

        var s = Totp.NewSecret();
        var jetzt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var code = Totp.Code(s, Totp.CounterFor(jetzt));
        fehler += Pruefe("TOTP angenommen", Totp.Verify(s, code, jetzt, 0, out var c).ToString(), "True");
        fehler += Pruefe("TOTP nicht zweimal", Totp.Verify(s, code, jetzt, c, out _).ToString(), "False");

        // --- ISO/IEC 18004: QR-Code, Byte-Modus, Stufe M --------------------
        // Ein QR-Kodierer ist Bitschieberei, in der ein Fehler sich versteckt,
        // ohne aufzufallen: das Bild sieht richtig aus, eine App liest es
        // sogar, und erst ein bestimmter Inhalt kippt es. Darum stehen hier
        // keine Beispiele, sondern Pruefsummen ganzer Raster - Modul fuer
        // Modul festgenagelt gegen eine unabhaengige Umsetzung. Die Vektoren
        // decken den ganzen Bereich ab: Fassung 1 bis 40, jede Breite des
        // Laengenfeldes, alle acht Masken. Erzeugt und nachgestellt mit
        // scripts/qr-gegenpruefen.py.
        foreach (var (laenge, sollFassung, sollHash) in QrVektoren)
        {
            var raster = QrCode.Encode(QrProbe(laenge));
            var fassung = (raster.Length - 17) / 4;
            fehler += Pruefe($"QR Fassung bei {laenge} Bytes", fassung.ToString(System.Globalization.CultureInfo.InvariantCulture), sollFassung.ToString(System.Globalization.CultureInfo.InvariantCulture));
            fehler += Pruefe($"QR Raster bei {laenge} Bytes", QrFingerabdruck(raster), sollHash);
        }

        Console.WriteLine(fehler == 0 ? "alle Testvektoren stimmen" : $"{fehler} Abweichungen");
        return fehler == 0 ? 0 : 1;
    }

    /// <summary>
    /// Gibt fuer jede Zeile auf der Standardeingabe das Modulraster aus:
    /// erst die Kantenlaenge, dann die Zeilen als Nullen und Einsen. Damit
    /// stellt scripts/qr-gegenpruefen.py den Kodierer gegen eine unabhaengige
    /// Umsetzung - fuer ein paar hundert Eingaben statt fuer ein Beispiel.
    /// </summary>
    public static int DumpQr()
    {
        while (Console.ReadLine() is { } zeile)
        {
            var raster = QrCode.Encode(zeile);
            Console.WriteLine(raster.Length);
            foreach (var r in raster)
                Console.WriteLine(new string([.. r.Select(m => m ? '1' : '0')]));
        }
        return 0;
    }

    /// <summary>
    /// Eine Probe fester Laenge, damit die Vektoren kurz bleiben. Das Muster
    /// haelt sich absichtlich vom Namen des Programms fern: die Pruefsummen
    /// haengen daran, und eine Umbenennung darf die Testvektoren nicht kippen.
    /// Wer es doch aendert, erzeugt sie mit scripts/qr-gegenpruefen.py neu.
    /// </summary>
    static string QrProbe(int laenge)
    {
        const string Muster = "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=X&algorithm=SHA1&digits=6&period=30&x=0123456789";
        var sb = new StringBuilder(laenge);
        for (int i = 0; i < laenge; i++) sb.Append(Muster[i % Muster.Length]);
        return sb.ToString();
    }

    static string QrFingerabdruck(bool[][] raster)
    {
        var sb = new StringBuilder(raster.Length * (raster.Length + 1));
        foreach (var zeile in raster)
        {
            foreach (var m in zeile) sb.Append(m ? '1' : '0');
            sb.Append('\n');
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    /// <summary>
    /// Fuer jede der vierzig Fassungen die beiden Randlaengen: die kleinste,
    /// die sie noetig macht, und die groesste, die sie noch fasst. Dort sitzen
    /// die Fehler - beim Fassungswechsel, beim Wechsel der Laengenfeldbreite
    /// und dort, wo der Abschluss nicht mehr ganz hineinpasst.
    /// </summary>
    static (int Laenge, int Fassung, string Hash)[] QrVektoren =>
    [
        (1, 1, "0db507863e33ebc9a5fef92418d2af2faae5f54aa138b4ec40afa8d2d644a5fe"),
        (14, 1, "46e4d9ddea56e4f52530f93f7e4d987b8074e4e9d7ec841206f149720ce1f9cc"),
        (15, 2, "5247907560e53a794cee87f08d6eddd2727a4305f877024409b692b40de1d5d3"),
        (26, 2, "af32a5dc4766b8a5a62ebffb09de81acec5528700f521d0478e9484c22e66a47"),
        (27, 3, "9e6780db648ec23281b2bfdbbe96f5c66dce223c7a1aee15054e57673ebfd815"),
        (42, 3, "cf2d45b0c9b6c1c3645580fa9d8a59058a25abc10eb0967fab8aa164aeffc704"),
        (43, 4, "545a9f881138d4248853049595612a9edfbbccb9337786fcb983ec6a061fb619"),
        (62, 4, "06fdc6dd68ed6c29c15968c7eefc73862a52d98f9e2773b21b442d8ff9852773"),
        (63, 5, "f32ef0fbce994e923c7267ca6eab09ce5aacbde1417b1ab3e0c009defb7f9e91"),
        (84, 5, "ad79978dc8b943912f6c604d8d48606558320a3570def058bf31794c62a2bd06"),
        (85, 6, "20915284fb5e148faa795ba108ac22abbe002a32da4907542248b9ad133714a6"),
        (106, 6, "39d7ea92f64e8dc364e9415a8baf0d68465f53583406630bfc6fd7fdb1c3e5b8"),
        (107, 7, "6929a6e4a0fa4b54eaf9a428633d9a36c7c0659d6a74cdc4fc844619b2531737"),
        (122, 7, "4747a87a48cae0b5d7f5d68b506c54c3f322fd1ed9d61983e8ee0175c658a99f"),
        (123, 8, "a0001d4e8726759c371fd298e62bbc33686771cf7db20194eed201a45e0720e8"),
        (152, 8, "25d79b12d5e0967ece21136b59a48b267a8321ee6f8e9c12fe0c50fc686382f4"),
        (153, 9, "58ab61958e7925edc79b37647a59b16531b49613476920b9099958f6df46e5ad"),
        (180, 9, "cde129c455bfcbb51e0c2f32eb92039fa1ee48749973de731b6e4ffe25a4ee8c"),
        (181, 10, "177012258edb6a3f56ea7103373cbea51074aa31ac8d93662827e5660d75e7cf"),
        (213, 10, "16a5a9e6c972940a90c552025b3b367047dd4d0c239f26b55d1e588aa20b3bf8"),
        (214, 11, "3069877ac3f3db2f3906e1810fd854815efc3681d22b70ac5ce6028a87a15cac"),
        (251, 11, "c23cd3c48c276cd5dfe837be73da56b3b3407d6179fc7a39202bd0a0af6042b9"),
        (252, 12, "2970164d2b1593eddfe36c56f74cb314b32b23ad7d10c314c710821da92f3940"),
        (287, 12, "54604eae9e01ab361c26583625cddbddcf6252685977be24b40587ee01ebab8d"),
        (288, 13, "cf38df483abada85a89aaac99e8f6e7f4a09936a2f7d8d8dada4cc5c18ade027"),
        (331, 13, "330f65d7b0d059de71b27e82e9690c692baf27ddca530cb45bb5062799c27eb4"),
        (332, 14, "d3c5cf555e2ec716057d672f60141b1c00f79b0bdbd9453e0389116c6701bc2f"),
        (362, 14, "85cbbd7bcf3cfd420c288619f891814ccce6519187d3befaa536d1784fcbf764"),
        (363, 15, "2ca1b93ee6423306e4bcaeb4c5239901550dd46e7b12d44116307a3dfb09b018"),
        (412, 15, "287cae534d1f817f75aa9743bd4bfa129d9475eeb8cc1ef2aa7225b06be1f258"),
        (413, 16, "3d59b135bce083aef4f03145391c458245195acb6d45cab382f6d686fd40923a"),
        (450, 16, "7c5bebaeed15942280352e59b1d0762514b4d3c764b01d5d65d287afcc6f34d1"),
        (451, 17, "46b589fe65e15979c2ec2fa62e505154c79f45192fbde7db02bf0106d88dd271"),
        (504, 17, "019f1ce6514714dd25407be9930ca10eb98cc76ca09d608b8bc9ca48fd92f671"),
        (505, 18, "7ec1f9e2b9343cab48ee306b088bc6d40714e63f4f927ea56fafecde99ced25f"),
        (560, 18, "461f56d706a349c459140ddc4042140e19d03fd6c0b712c123d2f085488d3a1a"),
        (561, 19, "8c443baea178fcb479a272f7a2ba13d8d39fa722e52e864d830bbaa04394fc06"),
        (624, 19, "8774c2b3a78f13a7ff0c03b973f01e35d59d98d0c98432ca3eec5aa4b6279b26"),
        (625, 20, "a365a2d85ebc7aae8e6bbbf0197918ca128c5d0ccf714efa61f7ba52327e4c7e"),
        (666, 20, "e22a8f9f542c5080700d49ecd4706c6784be83606d773ff7a2a43458770bc272"),
        (667, 21, "9afc9ffe0198ce20792f5c0c2d9ae7ecaf92863f226e8ac4b13150e497dc6c51"),
        (711, 21, "2e7f922dbcd4f55265bd0986f07e46ca97de3418f733ad6692e38b98a0332e5a"),
        (712, 22, "5edc68f2f9534e11c6f49453d01fc630e0aff579053777951ffb109966f7700f"),
        (779, 22, "23395059d39fb1cb04b62ac35d0be7e4fe31861037b7795cd47b4e9c0f0b64a3"),
        (780, 23, "7e04364a838126a476c0ac7942708de09e8900bdafd44a2780d002b4960485b9"),
        (857, 23, "dacddf41ab0e3dc66a8f3b7032933b5758de109f82d82258c79e45d1bb498b32"),
        (858, 24, "68319108510af2aabb5dfee875e2b5b57e49ed4062eb6893411134f3d7269f60"),
        (911, 24, "90576639c99933915468fe2d684b6b147d0adfb6c079d3ab07b2fff1e875ae50"),
        (912, 25, "eaac13c2c371e305745bdebadb55def11b3d20c8ebcd04300a9b1bc75a27a6ba"),
        (997, 25, "af864759ff58b3a0f5f3316eb38d9b591f2c577a0cad581a93ff8f1bd90eb361"),
        (998, 26, "ba096fcebf033f8d5e04fe293aac313c8cacc77e2d22efc5a7502150402dc63c"),
        (1059, 26, "e680eae10c73e48a3372ac4158353cf3257bba994889e059c68540112b3bd63f"),
        (1060, 27, "9cd347ee1f98edcf0d0726f815749ee02c8a3d89367a5b84edbd8e895d1e5e10"),
        (1125, 27, "6d75e54e2a437ef60d1272295f730182352819d1efab30730b09d514a1ddbbcd"),
        (1126, 28, "f222787260b378e911268602a25784999b3a76a59ad16393b1e8ed665dca19e9"),
        (1190, 28, "da799115a4bf0dc31d639d27fa585999d222ae1ffc8e769874f42ed04834880f"),
        (1191, 29, "a4b4f7790be828aa23cfd0ca40292df9ecd541595eca24410bc6ddea85732301"),
        (1264, 29, "797ff51ca5303b0134983b1ebe7fb63ece20789b4c61e5bd92c345a05d6c1fa8"),
        (1265, 30, "28798d030fa45af65546aa14319fb399e6e308943d24b8ea6e2939f4d32dd4f8"),
        (1370, 30, "bcf87e3a18bfe3a8336c8d8ff98ef20781af9b7c463f7ca8e1f1700bf7acac7b"),
        (1371, 31, "72e16da483ed9503158f12ce45c24acb75704b7e60348e55ce13ee3ab5c40331"),
        (1452, 31, "5760990a60ff330fbb953c087d1fac283724e179df8d32b5e18b004ba34995a8"),
        (1453, 32, "4cfac9d0f973e8023ceb4925712ab9c7248e6077cbca55a0f5999093e92591ea"),
        (1538, 32, "0a64a9562ead873456763849b3c3ab0064717ad90c534afcc988530092448eae"),
        (1539, 33, "4b073f1163a959224b8b4c7fcd2e562a4e812c077744495fa0c7b58b054d87b1"),
        (1628, 33, "b438a225fed635669f3a66db91520f441cc0df90090df1dd209c20b812cf71c9"),
        (1629, 34, "acfc1a4149d12d89d96aef530b23fdeaa14de7dfe0306517fd3b3e6a41d64332"),
        (1722, 34, "55805521321ac3b61e548353706adff93e2728a6c9020a45c0ae5f16a12f9dbb"),
        (1723, 35, "40d7d9e09357547af6a0cf82682a8cbe93624a7b65544a4917bd9a883cd6a765"),
        (1809, 35, "adcfea4608533a6704051176af40969ee843ada69ae86bafd2ac26579176f0dd"),
        (1810, 36, "83ae0ced5745b328ae5d6304c5aa606249223abc8aa27ae7a46e57c6b299e9cb"),
        (1911, 36, "05b5f9d20f6119edd0fb8e2bde6b810eb88392fc2084efcb91f4fe87c2c0eaba"),
        (1912, 37, "6ee24aa9aa9949529cfeab21019a51ebf4abf588f0d26e8323277f6e110a781e"),
        (1989, 37, "627a21c6b92610fd13b8beab50b1a0058ba2c3f5950006dff68d9d682e10afbc"),
        (1990, 38, "6f4784d7e3ffdc2419f3ff1d45ddb5c6d9fb077552e5fb6b507b4261f19324ff"),
        (2099, 38, "1341d98da8325ec68431a485fca96836baa88fb0b94ee0fadcbd5de123dbe213"),
        (2100, 39, "b65f2925e3e27d1718a1ae20f22827c0f6fcaea0df2a37a0b36793d7015d710d"),
        (2213, 39, "8fd244e9c9035e62117283abd0f78ac868e1c168b8b6577d78cd38b86e8d3103"),
        (2214, 40, "0927b3ee16f7a7174416daa0ab5210b7735093496dc144d407f590bd0c8c0930"),
        (2331, 40, "0e396e8c8d64dcf5742a4abbc9e16e46fe0fc16cea9a08d9f1116f79f9b08563"),
    ];

    static int Pruefe(string was, string ist, string soll)
    {
        if (ist == soll) { Console.WriteLine($"ok    {was}"); return 0; }
        Console.WriteLine($"FEHL  {was}: erwartet '{soll}', bekommen '{ist}'");
        return 1;
    }
}
