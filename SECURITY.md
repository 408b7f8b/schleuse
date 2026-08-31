# Sicherheit

## Schwachstellen melden

Wer eine Schwachstelle in schleuse findet, meldet sie bitte **nicht öffentlich**,
sondern an:

    security@example.invalid           ← vor Inbetriebnahme eintragen
    PGP-Fingerabdruck: …               ← optional, für vertrauliche Meldungen

Bitte angeben: betroffene Fassung, betroffene Rolle (Relay, Agent, Client,
Oberfläche, Schnittstelle), was passiert, und wie es sich nachstellen lässt.
Ein Nachweis in Form eines kleinen Skripts hilft sehr.

**Zusagen an die meldende Person:**

| | |
|---|---|
| Eingangsbestätigung | innerhalb von 3 Werktagen |
| Erste Einschätzung | innerhalb von 10 Werktagen |
| Behebung oder Übergangslösung | so früh wie möglich, Ziel 90 Tage |
| Veröffentlichung | koordiniert, in Absprache; spätestens mit der Behebung |
| Namensnennung | auf Wunsch |

Wir verfolgen niemanden rechtlich, der in gutem Glauben forscht, nur eigene
Systeme oder ausdrücklich freigegebene Installationen prüft, keine fremden
Daten abzieht und die Meldung vertraulich hält, bis sie behoben ist.

## Unterstützungszeitraum

    Fassung 1.x        unterstützt bis: … (Datum vor Inbetriebnahme festlegen)

Innerhalb dieses Zeitraums gibt es Sicherheitsaktualisierungen kostenlos. Der
Cyber Resilience Act verlangt mindestens fünf Jahre ab Inverkehrbringen, sofern
die erwartete Nutzungsdauer nicht kürzer ist — bei einem Fernwartungsdienst für
Anlagen ist sie eher länger.

## Wie Aktualisierungen ausgeliefert werden

schleuse ist ein einzelnes Binary ohne Selbstaktualisierung. Das ist Absicht: ein
Dienst, der sich selbst nachladen kann, ist ein Angriffsziel mehr. Der Weg ist:

1. Neues Binary und die zugehörige `sbom.cdx.json` von der Bezugsquelle laden.
2. Signatur oder Prüfsumme vergleichen (siehe unten).
3. `install -m755 schleuse /usr/local/bin/schleuse && systemctl restart schleuse-agent`.

**Freigaben werden signiert.** Vor der ersten Auslieferung einzurichten:

```sh
# beim Erzeugen
sha256sum out/linux-x64/schleuse > schleuse.sha256
gpg --detach-sign --armor schleuse.sha256

# beim Einspielen
gpg --verify schleuse.sha256.asc && sha256sum -c schleuse.sha256
```

Der öffentliche Schlüssel gehört auf einen anderen Weg als das Binary.

## Was in einer Sicherheitsmeldung steht

Zu jeder behobenen Schwachstelle wird veröffentlicht: betroffene Fassungen,
Auswirkung, Schweregrad, ob sie ausgenutzt wurde, und was zu tun ist. Solange
keine Behebung vorliegt, wird eine Übergangslösung genannt.

## Sicherheitsrelevante Voreinstellungen

Was schleuse von sich aus tut, ohne dass es jemand einstellen muss:

* TLS 1.3, beidseitige Zertifikatsprüfung, keine älteren Fassungen.
* **Kein Gerät darf sich anmelden**, solange es nicht in der Geräteliste steht.
  Die offene Betriebsart ist ein ausdrücklicher Schalter
  (`allow_unlisted_devices`), keine Voreinstellung.
* Ein neu angemeldetes Gerät wartet ohne Zertifikat, bis ein Mensch freigibt.
* Die Weboberfläche verlangt Passwort **und** zweiten Faktor; ohne Marke gibt
  die Schnittstelle keine Auskunft, auch nicht darüber, ob es einen Pfad gibt.
* Private Schlüssel mit Rechten 0600, Zustandsverzeichnis 0700.
* Der Dienst läuft ohne Capabilities, ohne beschreibbaren ausführbaren Speicher
  und mit eingeschränktem Systemaufruf-Satz (siehe `deploy/*.service`).

## Was protokolliert wird

Nach stdout, im Betrieb also nach journald: jede Anmeldung und jede Abweisung
mit Identität und Herkunft, jede Änderung an Geräten, Zugängen und Benutzern
mit Urheber, jeder Auf- und Abbau einer Sitzung. **Keine Nutzdaten** — der
Inhalt der Tunnel wird nirgends mitgeschrieben.

Personenbezug entsteht durch IP-Adressen in diesen Zeilen. Die Aufbewahrung
steuert der Betreiber über journald (`SystemMaxUse`, `MaxRetentionSec`); wer
gar nicht protokollieren will, setzt für den Dienst
`StandardOutput=null`. Adressen in den Zustandsdateien: die Herkunft eines
Antrags wird 30 Tage nach der Entscheidung verworfen, die zuletzt benutzte
Adresse einer Marke bis zu deren Rückzug.

## Zurücksetzen und Ausmustern

```sh
# Relay: alles, was er über Geräte, Zugänge und Benutzer weiß
systemctl stop schleuse-relay
shred -u /var/lib/schleuse/*.json
rm -f /etc/schleuse/device-ca.key            # Zwischen-CA zurückziehen

# Gerät: Identität restlos entfernen
systemctl stop schleuse-agent
shred -u /etc/schleuse/device.key /etc/schleuse/device.crt /etc/schleuse/enroll-state.json
```

Danach ist das Gerät ohne erneute Selbstanmeldung nicht mehr erreichbar. Auf
dem Relay bleibt der Eintrag in der Geräteliste stehen, bis er dort entfernt
wird — er allein berechtigt zu nichts.

## Bekannte Grenzen

Siehe den Abschnitt *Grenzen* in der [README](README.md). Für die Bewertung am
wichtigsten: der Schlüssel der Zwischen-CA liegt auf dem Relay. Wer den Relay
übernimmt, kann Gerätezertifikate ausstellen — aber keine Bediener-Zertifikate,
weil der Relay diese nur unmittelbar von der Wurzel-CA annimmt. Der Schlüssel
der Wurzel-CA gehört nicht auf den Relay.
