# Offene Punkte

## Natives AOT-Binary für arm64

**Erledigt für veröffentlichte Binaries.** `.github/workflows/release.yml` baut
`linux-arm64` auf einem arm64-Runner, also auf der eigenen Architektur — dort
genügt die vorhandene Toolchain, und `build.sh` schaltet von selbst auf Native
AOT um. Das Binary aus dem Release ist damit AOT (rund 12 MB statt 20), und
`install-relay.sh` lässt `MemoryDenyWriteExecute=yes` in der systemd-Einheit
stehen.

**Offen bleibt das Querbauen auf dem Arbeitsplatz.** Ohne `clang` weicht
`build.sh` weiter auf ein Single-File-Bundle mit JIT aus; wer so ein Binary
ausliefert, verliert die Sperre gegen beschreibbaren ausführbaren Speicher.
Für 32-bit-ARM (`linux-arm`) gibt es ohnehin kein AOT.

```sh
sudo apt install clang lld     # danach baut build.sh auch arm64 nativ
```

Noch zu prüfen, falls das jemand braucht: ob `clang` und `lld` allein reichen.
Zum Binden für arm64 braucht der Binder auch die Zielbibliotheken (`libc`,
`zlib`); je nach Einrichtung kommen `gcc-aarch64-linux-gnu` und
`zlib1g-dev:arm64` dazu. Der einfachere Weg ist inzwischen das Release.

**Auf dem laufenden Relay** liegt noch das alte Bundle mit JIT. Ein Wechsel auf
das Release-Binary bringt die Härtung zurück und spart Arbeitsspeicher:

```sh
sudo ./install-relay.sh -holen -name <name>
```

---

## Sprache der Oberfläche

Die Weboberfläche ist seit der Umstellung **englisch, und nur englisch**. Die
Texte stehen weiterhin fest in den HTML-Literalen (`src/WebUiSeiten.cs`,
`src/WebUi.cs`, `src/Html.cs`); es gibt keinen Schalter und keine
Ressourcentabelle.

Wer beide Sprachen will, kommt um den größeren Umbau nicht herum: Texte in eine
Tabelle mit Schlüsseln, ein Schlüssel `web.language` in `relay.json`, und —
das ist der Teil, den man beim Schätzen übersieht — die Ausnahmen in
`src/Enrollment.cs`, `src/Users.cs` und `src/ApiTokens.cs` müssen einen
Schlüssel tragen statt eines fertigen Satzes. Sonst zeigt eine englische
Oberfläche bei jedem Fehler wieder Deutsch.

Nicht umgestellt sind die Protokollausgaben und die Meldungen der
Kommandozeile. Beide bleiben deutsch.

---

## Wo die übrigen offenen Punkte stehen

* **Cyber Resilience Act** — Vertriebsweg klären, Einstufung gegen die
  Durchführungsverordnung (EU) 2025/2392 schriftlich festhalten,
  Konformitätsweg wählen. Gehört in die technische Dokumentation, nicht in
  das README.
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
