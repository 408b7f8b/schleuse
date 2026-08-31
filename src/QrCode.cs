namespace Schleuse;

/// <summary>
/// QR-Kodierer nach ISO/IEC 18004, so weit wie hier gebraucht: Byte-Modus,
/// Fehlerkorrektur M, Fassung 1 bis 40 nach Laenge.
///
/// Gebraucht wird er an genau einer Stelle - dem Einrichten des zweiten
/// Faktors. Die <c>otpauth://</c>-Zeile enthaelt das Geheimnis; sie an einen
/// Kodierdienst im Netz zu schicken hoebe die ganze Uebung auf. Also steht der
/// Kodierer hier.
///
/// Selbstgeschriebene Bitschieberei ist die haeufigste Quelle stiller Fehler:
/// der Code sieht richtig aus, ein Leser kommt sogar damit zurecht, und erst
/// ein bestimmter Inhalt kippt ihn. Darum wird nicht an einem Beispiel geprueft,
/// sondern ueber den ganzen Bereich - scripts/qr-gegenpruefen.py stellt knapp
/// tausend Eingaben Modul fuer Modul gegen eine fremde Umsetzung, die Maskenwahl
/// gegen die eigenstaendig nachgerechneten Strafterme, und entziffert jeden
/// erzeugten Code wieder. Die Randlaengen aller vierzig Fassungen liegen als
/// Rasterpruefsummen in <see cref="VerifyCrypto"/>, damit auch das ausgelieferte
/// Binary sich jederzeit nachrechnen laesst.
///
/// Kein Micro-QR, keine anderen Fehlerkorrekturstufen, keine Zahlen- oder
/// Buchstabenmodi: was nicht gebraucht wird, ist nicht da und kann nicht
/// falsch sein. Byte-Modus kodiert jede Zeichenkette, nur etwas groesser.
/// </summary>
internal static class QrCode
{
    /// <summary>Groesste Fassung; darueber hinaus gibt es kein QR mehr.</summary>
    public const int MaxVersion = 40;

    /// <summary>Fehlerkorrektur M in der Zaehlweise der Formatinformation.</summary>
    const int EcLevelBits = 0b00;

    // Die beiden einzigen abgeschriebenen Tabellen. Alles andere rechnet sich
    // aus der Fassung aus; was hier stuende und falsch waere, faellt beim
    // Gegenpruefen sofort auf - eine falsche Blockaufteilung verschiebt jedes
    // Codewort.

    /// <summary>Fehlerkorrekturbytes je Block, Stufe M, Fassung 1 bis 40.</summary>
    static ReadOnlySpan<byte> EcProBlock =>
    [
        0, // Fassung 0 gibt es nicht
        10, 16, 26, 18, 24, 16, 18, 22, 22, 26,
        30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
        26, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ];

    /// <summary>Anzahl Bloecke, Stufe M, Fassung 1 bis 40.</summary>
    static ReadOnlySpan<byte> Bloecke =>
    [
        0,
        1, 1, 1, 2, 2, 4, 4, 4, 5, 5,
        5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
        17, 17, 18, 20, 21, 23, 25, 26, 28, 29,
        31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ];

    // -- Oeffentlich ---------------------------------------------------------

    /// <summary>
    /// Kodiert einen Text. Liefert das Modulraster ohne Ruhezone,
    /// <c>raster[zeile][spalte]</c>, <c>true</c> = dunkel.
    /// </summary>
    /// <exception cref="ArgumentException">Der Text passt in keine Fassung.</exception>
    public static bool[][] Encode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var roh = System.Text.Encoding.UTF8.GetBytes(text);
        var fassung = KleinsteFassung(roh.Length);
        var daten = Datenstrom(roh, fassung);
        var block = MitFehlerkorrektur(daten, fassung);
        return Zeichne(block, fassung);
    }

    /// <summary>
    /// Gibt das Raster als eigenstaendiges SVG aus - ein Element im Dokument,
    /// kein nachgeladenes Bild. Die Inhaltsregel der Oberflaeche darf damit
    /// <c>default-src 'none'</c> bleiben; ein <c>&lt;img src="data:..."&gt;</c>
    /// braeuchte eine Lockerung auf <c>img-src</c>.
    ///
    /// Farben stehen fest im Element. Ein Leser rechnet mit dunkel auf hell,
    /// und die Oberflaeche kann dunkel dargestellt werden - ein QR-Code, der
    /// sich der Umgebung anpasst, ist einer, den kein Telefon mehr liest.
    /// </summary>
    public static string Svg(bool[][] raster, string beschreibung, int rand = 4)
    {
        ArgumentNullException.ThrowIfNull(raster);
        ArgumentOutOfRangeException.ThrowIfNegative(rand);

        int n = raster.Length;
        int kante = n + 2 * rand;

        // Waagerechte Laeufe zusammenfassen: ein Pfad statt einiger tausend
        // Rechtecke, sonst wird das Dokument unnoetig gross.
        var pfad = new System.Text.StringBuilder(n * n / 4);
        for (int y = 0; y < n; y++)
        {
            var zeile = raster[y];
            for (int x = 0; x < n;)
            {
                if (!zeile[x]) { x++; continue; }
                int start = x;
                while (x < n && zeile[x]) x++;
                pfad.Append(System.Globalization.CultureInfo.InvariantCulture,
                            $"M{start + rand} {y + rand}h{x - start}v1h-{x - start}z");
            }
        }

        return $"""
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {kante} {kante}" width="{kante * 5}" height="{kante * 5}" shape-rendering="crispEdges" role="img" aria-label="{Html.E(beschreibung)}"><rect width="{kante}" height="{kante}" fill="#fff"/><path d="{pfad}" fill="#000"/></svg>
            """;
    }

    // -- Datenstrom ----------------------------------------------------------

    /// <summary>Breite des Laengenfeldes im Byte-Modus.</summary>
    static int LaengenBits(int fassung) => fassung <= 9 ? 8 : 16;

    /// <summary>Datenbytes (ohne Fehlerkorrektur), die eine Fassung fasst.</summary>
    static int Datenbytes(int fassung)
        => GesamtBytes(fassung) - EcProBlock[fassung] * Bloecke[fassung];

    /// <summary>
    /// Alle Codewoerter einer Fassung. Die Modulzahl ergibt sich aus der
    /// Kantenlaenge abzueglich der festen Muster; Anhang D der Norm fuehrt
    /// dieselben Zahlen als Tabelle.
    /// </summary>
    static int GesamtBytes(int fassung)
    {
        int module = (16 * fassung + 128) * fassung + 64;
        if (fassung >= 2)
        {
            int a = fassung / 7 + 2;                        // Ausrichtungsmuster je Achse
            module -= (25 * a - 10) * a - 55;
            if (fassung >= 7) module -= 36;                 // zweimal 18 Bit Fassungsangabe
        }
        return module / 8;
    }

    /// <summary>
    /// Die kleinste Fassung, in die der Inhalt passt. Gerechnet wird in Bits,
    /// nicht in Bytes: der Kopf ist 20 Bit lang, und wer ihn auf drei Bytes
    /// aufrundet, verschenkt das letzte Byte der groessten Fassung.
    /// </summary>
    static int KleinsteFassung(int bytes)
    {
        for (int v = 1; v <= MaxVersion; v++)
            if (Datenbytes(v) * 8 >= 4 + LaengenBits(v) + 8 * bytes) return v;
        int grenze = (Datenbytes(MaxVersion) * 8 - 4 - LaengenBits(MaxVersion)) / 8;
        throw new ArgumentException($"{bytes} Bytes passen in keinen QR-Code (Grenze bei Stufe M: {grenze} Bytes)");
    }

    static byte[] Datenstrom(byte[] roh, int fassung)
    {
        int platz = Datenbytes(fassung);
        var bits = new BitPuffer(platz);
        bits.Add(0b0100, 4);                                // Byte-Modus
        bits.Add(roh.Length, LaengenBits(fassung));
        foreach (var b in roh) bits.Add(b, 8);

        // Abschluss, dann bis zur Bytegrenze auffuellen.
        bits.Add(0, Math.Min(4, platz * 8 - bits.Length));
        bits.Add(0, (8 - bits.Length % 8) % 8);

        // Der Rest wird mit zwei festgelegten Bytes im Wechsel gefuellt.
        var daten = bits.ToBytes();
        var voll = new byte[platz];
        daten.CopyTo(voll, 0);
        for (int i = daten.Length, w = 0; i < platz; i++, w++)
            voll[i] = w % 2 == 0 ? (byte)0xEC : (byte)0x11;
        return voll;
    }

    /// <summary>
    /// Teilt die Daten in Bloecke, haengt jedem seine Fehlerkorrektur an und
    /// verschraenkt beides so, wie die Norm es vorschreibt: ein Kratzer auf dem
    /// Aufkleber trifft dann viele Bloecke ein wenig statt einen ganz.
    /// </summary>
    static byte[] MitFehlerkorrektur(byte[] daten, int fassung)
    {
        int anzahl = Bloecke[fassung];
        int ecLen = EcProBlock[fassung];
        int kurzeLaenge = daten.Length / anzahl;
        int kurze = anzahl - daten.Length % anzahl;         // die uebrigen sind ein Byte laenger

        var teil = new byte[anzahl][];
        var ec = new byte[anzahl][];
        for (int i = 0, off = 0; i < anzahl; i++)
        {
            int len = kurzeLaenge + (i < kurze ? 0 : 1);
            teil[i] = daten[off..(off + len)];
            ec[i] = ReedSolomon.Rest(teil[i], ecLen);
            off += len;
        }

        var aus = new byte[daten.Length + ecLen * anzahl];
        int p = 0;
        for (int i = 0; i <= kurzeLaenge; i++)              // Datenbytes spaltenweise
            for (int b = 0; b < anzahl; b++)
                if (i < teil[b].Length) aus[p++] = teil[b][i];
        for (int i = 0; i < ecLen; i++)                     // dann die Fehlerkorrektur
            for (int b = 0; b < anzahl; b++)
                aus[p++] = ec[b][i];
        return aus;
    }

    // -- Raster --------------------------------------------------------------

    static bool[][] Zeichne(byte[] codewoerter, int fassung)
    {
        int n = 4 * fassung + 17;
        var raster = Neu(n);
        var fest = Neu(n);                                  // Funktionsmuster: nicht ueberschreiben, nicht maskieren

        FesteMuster(raster, fest, fassung);
        Formatbits(raster, fest, 0);                        // Platzhalter, damit die Felder als fest gelten
        Daten(raster, fest, codewoerter);

        // Die Maske, die das Ergebnis am besten lesbar macht. Was "am besten"
        // heisst, legt die Norm mit vier Straftermen fest.
        int beste = 0, bestwert = int.MaxValue;
        for (int m = 0; m < 8; m++)
        {
            Maskiere(raster, fest, m);
            Formatbits(raster, fest, m);
            int wert = Strafe(raster);
            if (wert < bestwert) { bestwert = wert; beste = m; }
            Maskiere(raster, fest, m);                      // XOR ist seine eigene Umkehrung
        }
        Maskiere(raster, fest, beste);
        Formatbits(raster, fest, beste);
        return raster;
    }

    static bool[][] Neu(int n)
    {
        var a = new bool[n][];
        for (int i = 0; i < n; i++) a[i] = new bool[n];
        return a;
    }

    static void Setze(bool[][] raster, bool[][] fest, int x, int y, bool dunkel)
    {
        raster[y][x] = dunkel;
        fest[y][x] = true;
    }

    static void FesteMuster(bool[][] raster, bool[][] fest, int fassung)
    {
        int n = raster.Length;

        // Waagerechte und senkrechte Taktlinie.
        for (int i = 0; i < n; i++)
        {
            Setze(raster, fest, 6, i, i % 2 == 0);
            Setze(raster, fest, i, 6, i % 2 == 0);
        }

        // Die drei Suchmuster mit ihrem hellen Rand.
        Suchmuster(raster, fest, 3, 3);
        Suchmuster(raster, fest, n - 4, 3);
        Suchmuster(raster, fest, 3, n - 4);

        // Ausrichtungsmuster ueberall dort, wo sich zwei Achsen kreuzen -
        // ausser unter den Suchmustern.
        var achse = Achsen(fassung);
        for (int i = 0; i < achse.Length; i++)
            for (int j = 0; j < achse.Length; j++)
            {
                bool unterSuchmuster = (i == 0 && j == 0)
                                    || (i == 0 && j == achse.Length - 1)
                                    || (i == achse.Length - 1 && j == 0);
                if (!unterSuchmuster) Ausrichtung(raster, fest, achse[i], achse[j]);
            }

        // Die Felder der Formatinformation gelten als fest; die Bits kommen
        // spaeter, wenn die Maske feststeht.
        for (int i = 0; i < 9; i++) { fest[8][i] = true; fest[i][8] = true; }
        for (int i = 0; i < 8; i++) { fest[8][n - 1 - i] = true; fest[n - 1 - i][8] = true; }

        if (fassung >= 7) Fassungsbits(raster, fest, fassung);
    }

    static void Suchmuster(bool[][] raster, bool[][] fest, int cx, int cy)
    {
        int n = raster.Length;
        for (int dy = -4; dy <= 4; dy++)
            for (int dx = -4; dx <= 4; dx++)
            {
                int x = cx + dx, y = cy + dy;
                if (x < 0 || x >= n || y < 0 || y >= n) continue;
                int d = Math.Max(Math.Abs(dx), Math.Abs(dy));
                Setze(raster, fest, x, y, d != 2 && d != 4);
            }
    }

    static void Ausrichtung(bool[][] raster, bool[][] fest, int cx, int cy)
    {
        for (int dy = -2; dy <= 2; dy++)
            for (int dx = -2; dx <= 2; dx++)
                Setze(raster, fest, cx + dx, cy + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
    }

    /// <summary>
    /// Mittellinien der Ausrichtungsmuster. Die erste liegt immer bei 6, die
    /// letzte sieben Module vor dem Rand; dazwischen gleichmaessig verteilt,
    /// mit geradem Abstand.
    /// </summary>
    static int[] Achsen(int fassung)
    {
        if (fassung == 1) return [];
        int anzahl = fassung / 7 + 2;
        int schritt = fassung == 32 ? 26 : (fassung * 4 + anzahl * 2 + 1) / (anzahl * 2 - 2) * 2;
        var a = new int[anzahl];
        a[0] = 6;
        for (int i = anzahl - 1, pos = 4 * fassung + 10; i >= 1; i--, pos -= schritt) a[i] = pos;
        return a;
    }

    /// <summary>15 Bit Formatinformation, zweimal im Raster, BCH-gesichert.</summary>
    static void Formatbits(bool[][] raster, bool[][] fest, int maske)
    {
        int n = raster.Length;
        int daten = EcLevelBits << 3 | maske;
        int rest = daten;
        for (int i = 0; i < 10; i++) rest = rest << 1 ^ (rest >> 9) * 0x537;
        int bits = (daten << 10 | rest) ^ 0x5412;           // feste Maske gegen lauter Nullen

        for (int i = 0; i <= 5; i++) Setze(raster, fest, 8, i, Bit(bits, i));
        Setze(raster, fest, 8, 7, Bit(bits, 6));
        Setze(raster, fest, 8, 8, Bit(bits, 7));
        Setze(raster, fest, 7, 8, Bit(bits, 8));
        for (int i = 9; i < 15; i++) Setze(raster, fest, 14 - i, 8, Bit(bits, i));

        for (int i = 0; i < 8; i++) Setze(raster, fest, n - 1 - i, 8, Bit(bits, i));
        for (int i = 8; i < 15; i++) Setze(raster, fest, 8, n - 15 + i, Bit(bits, i));
        Setze(raster, fest, 8, n - 8, true);                // das eine immer dunkle Modul
    }

    /// <summary>18 Bit Fassungsangabe ab Fassung 7, zweimal im Raster.</summary>
    static void Fassungsbits(bool[][] raster, bool[][] fest, int fassung)
    {
        int n = raster.Length;
        int rest = fassung;
        for (int i = 0; i < 12; i++) rest = rest << 1 ^ (rest >> 11) * 0x1F25;
        int bits = fassung << 12 | rest;
        for (int i = 0; i < 18; i++)
        {
            bool b = Bit(bits, i);
            int a = n - 11 + i % 3, k = i / 3;
            Setze(raster, fest, a, k, b);
            Setze(raster, fest, k, a, b);
        }
    }

    static bool Bit(int wert, int stelle) => (wert >> stelle & 1) != 0;

    /// <summary>
    /// Die Codewoerter im Zickzack von rechts unten nach links oben, zwei
    /// Spalten breit, unter Auslassung der Taktspalte 6.
    /// </summary>
    static void Daten(bool[][] raster, bool[][] fest, byte[] codewoerter)
    {
        int n = raster.Length;
        int i = 0;
        for (int rechts = n - 1; rechts >= 1; rechts -= 2)
        {
            if (rechts == 6) rechts = 5;
            for (int schritt = 0; schritt < n; schritt++)
                for (int j = 0; j < 2; j++)
                {
                    int x = rechts - j;
                    bool aufwaerts = (rechts + 1 & 2) == 0;
                    int y = aufwaerts ? n - 1 - schritt : schritt;
                    if (fest[y][x] || i >= codewoerter.Length * 8) continue;
                    raster[y][x] = Bit(codewoerter[i >> 3], 7 - (i & 7));
                    i++;
                }
        }
    }

    static void Maskiere(bool[][] raster, bool[][] fest, int maske)
    {
        int n = raster.Length;
        for (int y = 0; y < n; y++)
            for (int x = 0; x < n; x++)
            {
                if (fest[y][x]) continue;
                bool umkehren = maske switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (y / 2 + x / 3) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                if (umkehren) raster[y][x] = !raster[y][x];
            }
    }

    /// <summary>
    /// Die vier Strafterme der Norm. Sie bewerten, wie schwer ein Leser sich
    /// mit dem Bild tut: lange gleichfarbige Laeufe, gleichfarbige Vierecke,
    /// Muster die dem Suchmuster aehneln, und ein Ungleichgewicht zwischen
    /// hell und dunkel.
    /// </summary>
    static int Strafe(bool[][] raster)
    {
        int n = raster.Length;
        int summe = 0;

        for (int y = 0; y < n; y++)
            for (int x = 0; x < n; x++)
            {
                // Regel 1, waagerecht und senkrecht: Laeufe ab fuenf Modulen.
                if (x == 0 || raster[y][x] != raster[y][x - 1])
                {
                    int lauf = 1;
                    while (x + lauf < n && raster[y][x + lauf] == raster[y][x]) lauf++;
                    if (lauf >= 5) summe += 3 + (lauf - 5);
                }
                if (y == 0 || raster[y][x] != raster[y - 1][x])
                {
                    int lauf = 1;
                    while (y + lauf < n && raster[y + lauf][x] == raster[y][x]) lauf++;
                    if (lauf >= 5) summe += 3 + (lauf - 5);
                }

                // Regel 2: gleichfarbige Bloecke aus zwei mal zwei Modulen.
                if (x + 1 < n && y + 1 < n
                    && raster[y][x] == raster[y][x + 1]
                    && raster[y][x] == raster[y + 1][x]
                    && raster[y][x] == raster[y + 1][x + 1]) summe += 3;
            }

        // Regel 3: das Verhaeltnis 1:1:3:1:1 mit vier hellen Modulen daneben,
        // also genau das, was ein Leser fuer ein Suchmuster halten wuerde.
        for (int y = 0; y < n; y++)
            for (int x = 0; x + 10 < n; x++)
            {
                if (Suchaehnlich(raster, y, x, waagerecht: true)) summe += 40;
            }
        for (int x = 0; x < n; x++)
            for (int y = 0; y + 10 < n; y++)
            {
                if (Suchaehnlich(raster, y, x, waagerecht: false)) summe += 40;
            }

        // Regel 4: Abweichung vom halb-und-halb, in vollen Schritten von fuenf
        // Prozent. In Ganzzahlen gerechnet: |20*dunkel - 10*gesamt| / gesamt
        // ist genau |Anteil in Prozent - 50| / 5, abgerundet.
        int dunkel = 0;
        foreach (var zeile in raster) foreach (var m in zeile) if (m) dunkel++;
        int gesamt = n * n;
        summe += Math.Abs(dunkel * 20 - gesamt * 10) / gesamt * 10;

        return summe;
    }

    /// <summary>Elf Module ab (y,x) gegen die beiden Suchmuster-Folgen.</summary>
    static bool Suchaehnlich(bool[][] raster, int y, int x, bool waagerecht)
    {
        const int Vorwaerts = 0b10111010000;
        const int Rueckwaerts = 0b00001011101;
        int wert = 0;
        for (int i = 0; i < 11; i++)
            wert = wert << 1 | ((waagerecht ? raster[y][x + i] : raster[y + i][x]) ? 1 : 0);
        return wert == Vorwaerts || wert == Rueckwaerts;
    }

    // -- Hilfsmittel ---------------------------------------------------------

    /// <summary>Sammelt Bits und gibt sie als Bytes aus, hoechstwertiges zuerst.</summary>
    sealed class BitPuffer(int bytes)
    {
        readonly List<byte> _aus = new(bytes);
        int _puffer, _bits;

        public int Length { get; private set; }

        public void Add(int wert, int anzahl)
        {
            for (int i = anzahl - 1; i >= 0; i--)
            {
                _puffer = _puffer << 1 | (wert >> i & 1);
                _bits++;
                Length++;
                if (_bits != 8) continue;
                _aus.Add((byte)_puffer);
                _puffer = 0;
                _bits = 0;
            }
        }

        public byte[] ToBytes()
        {
            if (_bits > 0) throw new InvalidOperationException("angebrochenes Byte");
            return [.. _aus];
        }
    }
}

/// <summary>
/// Reed-Solomon ueber GF(256) mit dem Grundpolynom x^8+x^4+x^3+x^2+1 - das
/// Fehlerkorrekturverfahren des QR-Codes. Nur die Kodierseite: der Rest der
/// Polynomdivision ist genau das, was an die Daten angehaengt wird.
/// </summary>
internal static class ReedSolomon
{
    const int Grundpolynom = 0x11D;

    static readonly byte[] Exp = new byte[512];
    static readonly byte[] Log = new byte[256];

    static ReedSolomon()
    {
        int x = 1;
        for (int i = 0; i < 255; i++)
        {
            Exp[i] = (byte)x;
            Log[x] = (byte)i;
            x <<= 1;
            if (x >= 256) x ^= Grundpolynom;
        }
        for (int i = 255; i < 512; i++) Exp[i] = Exp[i - 255];
    }

    static byte Mal(byte a, byte b) => a == 0 || b == 0 ? (byte)0 : Exp[Log[a] + Log[b]];

    /// <summary>Erzeugerpolynom (x-a^0)(x-a^1)...(x-a^(n-1)), ohne den fuehrenden Term.</summary>
    static byte[] Erzeuger(int n)
    {
        var g = new byte[n];
        g[n - 1] = 1;
        for (int i = 0, wurzel = 1; i < n; i++)
        {
            for (int j = 0; j < n - 1; j++)
                g[j] = (byte)(Mal(g[j], (byte)wurzel) ^ g[j + 1]);
            g[n - 1] = Mal(g[n - 1], (byte)wurzel);
            wurzel = Mal((byte)wurzel, 2);
        }
        return g;
    }

    /// <summary>Der Rest der Division durch das Erzeugerpolynom.</summary>
    public static byte[] Rest(byte[] daten, int n)
    {
        ArgumentNullException.ThrowIfNull(daten);
        var g = Erzeuger(n);
        var rest = new byte[n];
        foreach (var b in daten)
        {
            byte faktor = (byte)(b ^ rest[0]);
            Array.Copy(rest, 1, rest, 0, n - 1);
            rest[n - 1] = 0;
            for (int j = 0; j < n; j++) rest[j] ^= Mal(g[j], faktor);
        }
        return rest;
    }
}
