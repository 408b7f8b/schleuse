# Offene Punkte

## Natives AOT-Binary für arm64

**Stand:** Auf dem Relay (Raspberry Pi 3, `relais.local`) läuft ein
self-contained Single-File-Bundle mit JIT: 20 MB auf der Platte, 46 MB
Arbeitsspeicher. Das Querbauen eines nativen Binarys braucht `clang` und `lld`,
die auf dem Entwicklungsrechner fehlen.

**Folge:** Die systemd-Einheit musste `MemoryDenyWriteExecute=yes` ablegen — ein
JIT braucht beschreibbaren ausführbaren Speicher. Damit fehlt eine Schutzlage,
die für alle anderen Rollen greift.

**Warum es noch fehlt:** `apt install` braucht Rechte, die dieser Arbeitsgang
nicht hat. Ohne Root lässt sich das nicht nachholen; ein von Hand entpacktes
clang wäre eine Bastelei, die beim nächsten Systemwechsel bricht.

**Wie es geht:**

```sh
sudo apt install clang lld
./build.sh linux-arm64
./scripts/deploy-relay.sh
```

`build.sh` schaltet von selbst auf Native AOT um, sobald `clang` vorhanden ist,
und schreibt `aot` statt `singlefile` in `out/linux-arm64/BUILD-MODE`.
`deploy-relay.sh` liest diese Datei und macht die Härtung damit wieder scharf —
das ist bereits eingebaut, es braucht keinen weiteren Handgriff.

**Noch zu prüfen:** ob `clang` und `lld` allein reichen. Zum Binden für arm64
braucht der Binder auch die Zielbibliotheken (`libc`, `zlib`); je nach
Einrichtung kommen `gcc-aarch64-linux-gnu` und `zlib1g-dev:arm64` dazu. Wenn das
Querbauen scheitert, ist der zweite Weg das Bauen auf dem Gerät selbst — dort
gibt es die Zielumgebung ohnehin, nötig ist nur das .NET-SDK.

**Aufwand:** eine Viertelstunde, sofern das Querbauen auf Anhieb bindet.

---

## Wo die übrigen offenen Punkte stehen

* **Cyber Resilience Act** — Vertriebsweg klären, Einstufung gegen die
  Durchführungsverordnung (EU) 2025/2392 schriftlich festhalten, Konformitätsweg
  wählen: Abschnitt *Cyber Resilience Act* in [README.md](README.md).
* **Kontaktadresse, Unterstützungszeitraum, Signaturschlüssel für Freigaben** —
  Platzhalter in [SECURITY.md](SECURITY.md).

---

## Erledigt

### QR-Code für das TOTP-Geheimnis

`/login/2fa-neu` zeigt den Code jetzt als inline-SVG, darunter weiterhin das
Geheimnis in Base32 und die vollständige `otpauth://`-Zeile. Kodiert wird in
`src/QrCode.cs`: Byte-Modus, Fehlerkorrektur M, Fassung 1 bis 40 nach Länge.
Kein Dienst im Netz — die Zeile enthält das Geheimnis des zweiten Faktors.

Gegengeprüft wird auf drei Wegen, jeder gegen eine andere Instanz
(`scripts/qr-gegenpruefen.py`, 993 Eingaben über den ganzen Bereich):

* das Raster Modul für Modul gegen die Bibliothek `qrcode`,
* die Maskenwahl gegen die eigenständig nachgerechneten Strafterme der Norm,
* jeder erzeugte Code einmal mit `zxing-cpp` wieder entziffert.

Das Gegenprüfen hat zwei echte Fehler gefunden, die beide „richtig aussahen":
die Kapazitätsrechnung rundete den 20-Bit-Kopf auf volle Bytes auf und
verschenkte damit das letzte Byte der Fassung 40, und Strafterm 4 rundete in die
falsche Richtung, was bei etwa jeder sechzigsten Eingabe die falsche Maske
wählte. Beide hätten lesbare Codes erzeugt — genau die Sorte Fehler, die ohne
Gegenprüfung über den ganzen Bereich unentdeckt bleibt.

Aus dem Gegenprüfen stammen auch die 80 Prüfsummen, gegen die
`schleuse verify-crypto` den Kodierer seitdem nachrechnet: für jede der vierzig
Fassungen die beiden Randlängen, jeweils das ganze Raster.

`segno` taugt hier übrigens nicht als Maßstab: dessen `write_padding_bits` hängt
auch dann ein volles Nullbyte an, wenn der Bitstrom nach dem Abschluss bereits
auf der Bytegrenze endet — im Byte-Modus also immer. Die Codes lassen sich
trotzdem lesen, Modul für Modul vergleichbar sind sie nicht.
