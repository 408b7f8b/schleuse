#!/usr/bin/env python3
"""Stellt den eingebauten QR-Kodierer gegen unabhaengige Umsetzungen.

Ein QR-Kodierer ist die Sorte Code, in der sich ein Fehler versteckt, ohne
aufzufallen: das Bild sieht richtig aus, eine App liest es sogar, und erst ein
bestimmter Inhalt kippt es. Ein einzelnes Beispiel beweist darum nichts. Dieses
Skript prueft drei Dinge, jedes gegen eine andere Instanz:

  1. Raster   - Modul fuer Modul gegen die Bibliothek `qrcode`, ueber den ganzen
                Bereich: Fassung 1 bis 40, beide Breiten des Laengenfeldes, dazu
                ein paar hundert zufaellige otpauth-Zeilen der Art, die die
                Oberflaeche wirklich erzeugt. Das deckt Datenstrom, Reed-Solomon,
                Verschraenkung, Modulplatzierung und Formatbits ab.
  2. Maske     - gegen die hier noch einmal frei nach der Norm ausgerechneten
                Strafterme. Fremde Umsetzungen weichen hier gern ab (siehe
                unten), darum wird nicht abgeschrieben, sondern nachgerechnet.
  3. Lesbarkeit - jeder erzeugte Code wird mit zxing-cpp wieder entziffert und
                mit der Eingabe verglichen. Am Ende zaehlt, was ein Leser damit
                anfaengt, nicht was eine Bibliothek meint. (Der Leser aus OpenCV
                taugt dafuer nicht: er scheitert ab etwa Fassung 9 haeufig, und
                zwar auch an den unveraendert uebernommenen Rastern der
                Vergleichsbibliothek - das ist seine Grenze, nicht ihre.)

Warum nicht `segno`: dessen `write_padding_bits` haengt auch dann ein volles
Nullbyte an, wenn der Bitstrom nach dem Abschluss bereits auf der Bytegrenze
endet - im Byte-Modus also immer. Die Codes lassen sich trotzdem lesen (ein
Leser hoert beim Abschlusszeichen auf), als Vergleichsmassstab Modul fuer Modul
taugen sie deshalb aber nicht.

Voraussetzung:
    python3 -m venv .venv
    .venv/bin/pip install qrcode zxing-cpp numpy

Aufruf:
    scripts/qr-gegenpruefen.py [pfad/zu/schleuse] [--vektoren]

    --vektoren   gibt die Zeilen fuer die Tabelle in src/VerifyCrypto.cs aus.
                 Die Pruefsummen stammen dann aus `qrcode`, nicht aus schleuse -
                 sonst pruefte sich der Kodierer gegen sich selbst.
"""

import hashlib
import random
import subprocess
import sys

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M
    from qrcode.util import QRData, MODE_8BIT_BYTE
except ImportError:
    sys.exit("qrcode fehlt:  python3 -m venv .venv && .venv/bin/pip install qrcode")

try:
    import numpy as np
    import zxingcpp
except ImportError:
    zxingcpp = None

# Dasselbe Muster wie QrProbe() in src/VerifyCrypto.cs - und wie dort
# absichtlich ohne den Namen des Programms: die Pruefsummen haengen daran.
MUSTER = "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=X&algorithm=SHA1&digits=6&period=30&x=0123456789"

# Wie viele Eingaben zusaetzlich durch die Maskenpruefung gehen. Die Strafterme
# sind in Python O(n^2) je Maske, achtmal je Eingabe; ueber alle tausend
# Eingaben liefe das stundenlang. Entziffert wird dagegen jeder Code: das
# uebernimmt eine C++-Bibliothek und kostet nichts.
MASKENPROBEN = 60


def datenbytes(v):
    """Datencodewoerter einer Fassung bei Stufe M."""
    module = (16 * v + 128) * v + 64
    if v >= 2:
        a = v // 7 + 2
        module -= (25 * a - 10) * a - 55
        if v >= 7:
            module -= 36
    ec = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28,
          26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
          28, 28, 28, 28, 28][v]
    bl = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45,
          47, 49][v]
    return module // 8 - ec * bl


def probe(laenge):
    """Dieselbe Probe wie QrProbe() in src/VerifyCrypto.cs."""
    return "".join(MUSTER[i % len(MUSTER)] for i in range(laenge))


def referenz(text, maske):
    """Raster der Bibliothek `qrcode`, Byte-Modus, Stufe M, feste Maske."""
    q = qrcode.QRCode(error_correction=ERROR_CORRECT_M, border=0, box_size=1,
                      mask_pattern=maske)
    q.add_data(QRData(text.encode("utf-8"), mode=MODE_8BIT_BYTE, check_data=False))
    q.make(fit=True)
    return [[1 if m else 0 for m in zeile] for zeile in q.get_matrix()]


def strafe(m):
    """Die vier Strafterme, frei nach ISO/IEC 18004 nachgerechnet."""
    n = len(m)
    s = 0

    # Regel 1: gleichfarbige Laeufe ab fuenf Modulen, waagerecht und senkrecht.
    linien = [[m[y][x] for x in range(n)] for y in range(n)]
    linien += [[m[y][x] for y in range(n)] for x in range(n)]
    for linie in linien:
        lauf = 1
        for i in range(1, n):
            if linie[i] == linie[i - 1]:
                lauf += 1
            else:
                if lauf >= 5:
                    s += 3 + (lauf - 5)
                lauf = 1
        if lauf >= 5:
            s += 3 + (lauf - 5)

    # Regel 2: gleichfarbige Bloecke aus zwei mal zwei Modulen.
    for y in range(n - 1):
        for x in range(n - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                s += 3

    # Regel 3: 1:1:3:1:1 mit vier hellen Modulen davor oder dahinter.
    p1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    p2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for y in range(n):
        for x in range(n - 10):
            if m[y][x:x + 11] in (p1, p2):
                s += 40
    for x in range(n):
        for y in range(n - 10):
            if [m[y + i][x] for i in range(11)] in (p1, p2):
                s += 40

    # Regel 4: Abweichung vom halb-und-halb in Schritten von fuenf Prozent.
    dunkel = sum(sum(z) for z in m)
    s += int(abs(dunkel * 100.0 / (n * n) - 50) / 5) * 10
    return s


def maske_aus_format(m):
    """Liest die Maskennummer aus den Formatbits des Rasters."""
    bits = 0
    for i in range(6):
        bits |= m[i][8] << i
    bits |= m[7][8] << 6
    bits |= m[8][8] << 7
    bits |= m[8][7] << 8
    for i in range(9, 15):
        bits |= m[8][14 - i] << i
    return ((bits ^ 0x5412) >> 10) & 7


def schleuse_raster(binary, texte):
    """Ruft `schleuse verify-crypto -qr` einmal fuer alle Texte auf."""
    eingabe = "".join(t + "\n" for t in texte)
    p = subprocess.run([binary, "verify-crypto", "-qr"], input=eingabe,
                       capture_output=True, text=True, check=True)
    zeilen = p.stdout.splitlines()
    aus, i = [], 0
    for _ in texte:
        n = int(zeilen[i])
        i += 1
        aus.append([[int(c) for c in z] for z in zeilen[i:i + n]])
        i += n
    return aus


def fingerabdruck(raster):
    return hashlib.sha256(
        "".join("".join(str(m) for m in z) + "\n" for z in raster).encode()).hexdigest()


def entziffern(raster):
    """Liest den Code so, wie ein Telefon es taete."""
    n, rand, kachel = len(raster), 4, 4
    kante = (n + 2 * rand) * kachel
    bild = np.full((kante, kante), 255, np.uint8)
    for y, zeile in enumerate(raster):
        for x, m in enumerate(zeile):
            if m:
                bild[(y + rand) * kachel:(y + rand + 1) * kachel,
                     (x + rand) * kachel:(x + rand + 1) * kachel] = 0
    gelesen = zxingcpp.read_barcode(bild)
    return gelesen.text if gelesen else ""


def zufallszeilen(anzahl, rnd):
    """otpauth-Zeilen, wie Totp.OtpAuthUri sie baut - mit echten Geheimnissen."""
    b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    aus = []
    for _ in range(anzahl):
        geheim = "".join(rnd.choice(b32) for _ in range(32))
        benutzer = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz.-_")
                           for _ in range(rnd.randint(1, 40)))
        ausgeber = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz")
                           for _ in range(rnd.randint(1, 30)))
        aus.append(f"otpauth://totp/{ausgeber}:{benutzer}?secret={geheim}"
                   f"&issuer={ausgeber}&algorithm=SHA1&digits=6&period=30")
    return aus


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    nur_vektoren = "--vektoren" in sys.argv[1:]
    binary = argv[0] if argv else "out/linux-x64/schleuse"
    rnd = random.Random(20260831)

    laengen = list(range(1, 300)) + list(range(300, 2332, 7)) + [2329, 2330, 2331]
    texte = [probe(n) for n in laengen] + zufallszeilen(400, rnd)

    print(f"{len(texte)} Eingaben, Fassung 1 bis 40 ...", file=sys.stderr)
    ist = schleuse_raster(binary, texte)

    fehler = 0

    # 1. Raster Modul fuer Modul.
    for text, raster in zip(texte, ist):
        maske = maske_aus_format(raster)
        soll = referenz(text, maske)
        if len(soll) != len(raster):
            print(f"FEHL  {len(text)} Bytes: Kantenlaenge {len(raster)}, erwartet {len(soll)}")
            fehler += 1
            continue
        schlecht = [(y, x) for y in range(len(soll)) for x in range(len(soll))
                    if soll[y][x] != raster[y][x]]
        if schlecht:
            y, x = schlecht[0]
            print(f"FEHL  Raster, {len(text)} Bytes, Fassung {(len(soll) - 17) // 4}: "
                  f"{len(schlecht)} Module abweichend, erstes bei Zeile {y}, Spalte {x}")
            fehler += 1
    print(f"  Raster:      {len(texte) - fehler} von {len(texte)} stimmen Modul fuer Modul")

    # 2. Maskenwahl gegen die eigenstaendig nachgerechneten Strafterme.
    stichprobe = [texte[i] for i in sorted(rnd.sample(range(len(texte)), MASKENPROBEN))]
    maskenfehler = 0
    for text in stichprobe:
        raster = schleuse_raster(binary, [text])[0]
        werte = [(strafe(referenz(text, m)), m) for m in range(8)]
        beste = min(werte)[1]
        gewaehlt = maske_aus_format(raster)
        if gewaehlt != beste:
            print(f"FEHL  Maske, {len(text)} Bytes: gewaehlt {gewaehlt}, "
                  f"guenstigste {beste} (Strafen {[w for w, _ in werte]})")
            maskenfehler += 1
    fehler += maskenfehler
    print(f"  Maske:       {len(stichprobe) - maskenfehler} von {len(stichprobe)} "
          f"treffen die guenstigste")

    # 3. Wieder entziffern - jeden einzelnen.
    if zxingcpp is None:
        print("  Lesbarkeit:  uebersprungen (zxing-cpp fehlt)")
    else:
        lesefehler = 0
        for text, raster in zip(texte, ist):
            zurueck = entziffern(raster)
            if zurueck != text:
                print(f"FEHL  Lesbarkeit, {len(text)} Bytes, "
                      f"Fassung {(len(raster) - 17) // 4}: zurueck {zurueck[:40]!r}")
                lesefehler += 1
        fehler += lesefehler
        print(f"  Lesbarkeit:  {len(texte) - lesefehler} von {len(texte)} "
              f"kommen unveraendert zurueck")

    if fehler:
        print(f"\n{fehler} Abweichungen")
        return 1
    print("\nkeine Abweichung")

    if nur_vektoren:
        # Fuer jede Fassung die beiden Randlaengen: die kleinste, die sie noch
        # noetig macht, und die groesste, die sie noch fasst. Dort sitzen die
        # Fehler - beim Fassungswechsel, beim Wechsel der Laengenfeldbreite und
        # dort, wo der Abschluss nicht mehr ganz hineinpasst. Die Pruefsummen
        # stammen aus `qrcode`, nicht aus schleuse.
        print("\n--- fuer src/VerifyCrypto.cs ---", file=sys.stderr)
        raender, vorher = [], 0
        for v in range(1, 41):
            groesste = (datenbytes(v) * 8 - 4 - (8 if v <= 9 else 16)) // 8
            raender += [vorher + 1, groesste]
            vorher = groesste
        raster = schleuse_raster(binary, [probe(n) for n in raender])
        zeilen = []
        for n, r in zip(raender, raster):
            soll = referenz(probe(n), maske_aus_format(r))
            if soll != r:
                print(f"FEHL  Randlaenge {n}: Raster weicht ab, kein Vektor")
                return 1
            zeilen.append(f'        ({n}, {(len(soll) - 17) // 4}, "{fingerabdruck(soll)}"),')
        print("\n".join(zeilen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
