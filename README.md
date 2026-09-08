# schleuse — Reverse-Tunnel für Linux-Geräte

**Deutsch** · [English](README.en.md)

Zugriff auf Geräte hinter NAT und Firewall, ohne dort einen Port zu öffnen.
Das Gerät baut selbst eine ausgehende TLS-Verbindung zu einem Relay im Internet
auf; über dieselbe Verbindung wird auf Anforderung SSH, SCP, HTTP oder jedes
andere TCP-Protokoll durchgereicht.

Ein neues Gerät meldet sich mit einem Befehl selbst an, landet in einer
Warteschlange und wird im Browser freigegeben. Ein Binary, keine
Laufzeit-Abhängigkeiten.

```
        Anlagennetz                          Internet                  Bediener

  ┌──────────────────────┐                                     ┌──────────────────────┐
  │ werk1-hmi            │                                     │  ein schleuse client │
  │   sshd :22           │                                     │                      │
  │   httpd :80          │                                     │  :2201 → werk1/ssh   │
  │   schleuse agent ────┼───┐                                 │  :8001 → werk1/http  │
  └──────────────────────┘   │                                 │  :2202 → werk2/ssh   │
                             │         ┌───────────────────┐   │  :5021 → werk2/mb    │
  ┌──────────────────────┐   │         │       relay       │   │                      │
  │ werk2-hmi            │   ├────────▶│  :443   Tunnel    │◀──┤  alles gleichzeitig  │
  │   sshd, httpd,       │   │ ausgeh. │  Selbstanmeldung  │   └──────────────────────┘
  │   modbus :502        │   │   TLS   │  :8443 Oberfläche │
  │   schleuse agent ────┼───┘         └─────────▲─────────┘
  └──────────────────────┘                       │ Passwort + 2FA
                                                 │
  ┌──────────────────────┐             ┌─────────┴─────────┐
  │ neues Gerät          │  Antrag     │   Warteschlange   │
  │   schleuse enroll ───┼────────────▶│                   ├─── freigeben ──▶ Betrieb
  └──────────────────────┘             └───────────────────┘

     kein offener Port                 einziger offener Port      kein offener Port
                                       für Geräte                 (nur loopback)
```

Beliebig viele Geräte, je mit beliebig vielen Diensten, alle gleichzeitig. Jede
einzelne Nutzsitzung bekommt ihre eigene TLS-Verbindung vom Gerät zum Relay —
zwei Sitzungen teilen sich keinen Puffer, keinen Zustand und keine Reihenfolge.

## Ein neues Gerät anschließen

Auf dem Gerät, einmalig — **dieselbe Zeile für jedes Gerät der Anlage, sie
enthält kein Geheimnis** und darf im Provisionierungsskript stehen:

```sh
schleuse enroll -relay tunnel.example.com:443 -ca-pin PGVZ-4CT3-JUFW-E3RD \
            -service ssh=127.0.0.1:22 -service http=127.0.0.1:80
```

```
Antrag gestellt. Das Gerät wartet auf die Freigabe.

    Fingerabdruck   3K25-4FIL-6UI3-QDWD

Diesen Fingerabdruck in der Weboberfläche des Relays vergleichen,
bevor freigegeben wird.
```

Solange es wartet, hat das Gerät **kein Zertifikat**, steht in keiner
Geräteliste und erreicht nichts. In der Weboberfläche erscheint der Antrag mit
demselben Fingerabdruck; stimmen beide überein, hat unterwegs niemand etwas
ausgetauscht. Der Betreiber vergibt Namen und Portfreigaben und gibt frei —
erst dann entsteht ein Zertifikat, das sich das Gerät bei der nächsten
Nachfrage abholt und in den Betrieb geht.

Der private Schlüssel wird auf dem Gerät erzeugt und verlässt es nie.

## Warum so und nicht anders

Der Kern des Entwurfs ist, dass **niemand außer dem Relay einen Port im Internet
hat** und **der Relay von sich aus nichts anstoßen kann**. Er vermittelt nur
zwischen einem angemeldeten Gerät und einem berechtigten Bediener.

Es gibt bewusst kein Multiplexing-Protokoll über eine einzige Verbindung. Statt
dessen hält der Agent einen dauerhaften Control-Kanal und öffnet **pro Sitzung
eine eigene TLS-Verbindung nach außen**. Das kostet einen Roundtrip beim
Verbindungsaufbau und spart dafür eine ganze Schicht: kein eigenes
Fenster-Management, kein Head-of-Line-Blocking, kein Pufferzustand, den man
falsch machen kann. Der Kernel macht das Flusskontroll-Handwerk.

## Sicherheitsmodell

| | |
|---|---|
| **Transport** | TLS 1.3, keine älteren Versionen, keine Aushandlung nach unten |
| **Authentisierung** | beidseitig (mTLS) gegen eine private CA — auch das Gerät prüft den Relay |
| **Identität** | steckt im CN des Zertifikats: `device:werk1-hmi`, `client:db`. Ein Gerät kann sich nicht als ein anderes ausgeben, denn die Konfiguration wird dabei nicht gefragt |
| **Zwei CAs** | Die Wurzel-CA bleibt offline und signiert Relay- und Bediener-Zertifikate. Auf dem Relay liegt nur eine Zwischen-CA für Geräte. **Der Relay nimmt Bediener-Zertifikate nur an, wenn die Wurzel-CA sie unmittelbar signiert hat** — wer den Relay übernimmt, kann sich damit keinen Zugang schaffen |
| **Erstkontakt** | Das Gerät kennt die CA noch nicht und prüft den Relay am Fingerabdruck aus seiner Konfiguration, **bevor** der Zertifikatsantrag das Gerät verlässt |
| **Quarantäne** | Ein neu angemeldetes Gerät hat kein Zertifikat und erreicht nichts, bis ein Mensch es freigibt und dabei den Schlüssel-Fingerabdruck vergleicht |
| **Geräteliste** | Nur wer in `acl.json` steht, darf sich anmelden. Fehlt die Liste ganz, ist die Anmeldung für jedes Zertifikat der CA offen — der Relay warnt dann beim Start |
| **Berechtigung** | Welcher Bediener auf welche Geräte und Dienste darf; Muster wie `werk1-*` sind erlaubt |
| **Freigabe am Gerät** | Der Agent verbindet sich nur zu Zielen aus seiner Dienstetabelle. Der Relay kennt nur Dienstnamen, nie Adressen — er kann freigeben und sperren, aber ein Gerät nicht auf beliebige Adressen im Anlagennetz zeigen lassen |
| **Trennung der Geräte** | Streams werden je Geräte-Sitzung geführt und über eine 128-Bit-Zufalls-Id angefordert. Ein Gerät kann keinen Stream eines anderen abholen — nachgeschlagen wird über sein Zertifikat, nicht über die Id allein |
| **Trennung der Bediener** | Zwei Budgets je Gerät: eines für alle Sitzungen zusammen, ein engeres je Bediener |
| **Sichtbarkeit** | `schleuse client -list` und die Weboberfläche zeigen jedem nur, was er erreichen darf |
| **Sperren** | Eintrag in `acl.json` oder ein Klick in der Oberfläche. Wirkt sofort — auch **laufende** Sitzungen werden getrennt |
| **Weboberfläche** | Eigener Port mit eigenem Zertifikat. Benutzername, Passwort (PBKDF2-HMAC-SHA256, 600 000 Runden) und zweiter Faktor (TOTP). Sitzungen im Speicher, Kennung nach jedem Anmeldeschritt neu, Merkmal gegen fremde Formulare bei jeder Änderung, Sperre nach fünf Fehlversuchen, kein JavaScript und eine Inhaltsregel, die das erzwingt |
| **Schnittstelle** | Marken mit 256 Zufallsbit, einmalig angezeigt, als SHA-256 gespeichert, mit Rolle und Ablauf. Ohne gültige Marke antwortet **jeder** Pfad gleich: 404, leerer Rumpf, kein `WWW-Authenticate`. Kein Verzeichnis der Pfade, keine Beschreibung, kein Swagger. Ein Sitzungskeks gilt nicht als Marke — sonst genügte einer fremden Seite ein Link an einen angemeldeten Verwalter |
| **Vertraulichkeit gegenüber dem Relay** | SSH und HTTPS sind Ende-zu-Ende verschlüsselt; der Relay sieht nur Ciphertext |
| **Speicher** | Übertragungspuffer werden geleert zurückgegeben, bevor sie an die nächste Sitzung gehen |
| **Rechte** | Beide Dienste laufen als eigener Nutzer ohne Capabilities, mit `MemoryDenyWriteExecute` und `SystemCallFilter` |

Der Relay ist damit *Vermittler, nicht Vertrauensanker*: Wer ihn übernimmt, kann
Verbindungen verweigern, Metadaten sehen und Gerätezertifikate ausstellen — aber
sich weder als Bediener ausgeben noch SSH-Verkehr mitlesen.

Die Konfiguration wird streng gelesen: ein Tippfehler in `services` oder
`devices` bricht den Start ab, statt still zu einer leeren Liste zu werden.

## Bauen

```sh
./build.sh                       # für die eigene Architektur
./build.sh linux-x64 linux-arm64 # mehrere Ziele
```

Ergebnis: `out/<rid>/schleuse`, rund 12 MB. Auf dem Zielgerät wird keine
.NET-Runtime gebraucht. Querbauen für eine andere Architektur braucht `clang`; fehlt es, weicht
`build.sh` selbsttätig auf ein self-contained Single-File-Bundle aus (rund
20 MB, läuft ebenso ohne vorinstallierte Runtime). Dasselbe gilt für
32-bit-ARM, für das es kein Native AOT gibt. Ein solches Bundle bringt einen
JIT mit und lässt sich darum nicht mit `MemoryDenyWriteExecute=yes` betreiben —
die Zeile muss dann aus der systemd-Einheit.

## Einrichten

**1 — CAs** (auf einem sicheren Rechner, nicht auf dem Relay):

```sh
./scripts/schleuse-pki.sh init                     # Wurzel-CA, bleibt hier
./scripts/schleuse-pki.sh device-ca                # Zwischen-CA für die Selbstanmeldung
./scripts/schleuse-pki.sh relay tunnel.example.com
./scripts/schleuse-pki.sh client db
```

`pki/ca.key` bleibt dort und wird nirgendwohin kopiert. Auf den Relay gehen nur
`ca.crt`, `relay.crt`, `relay.key`, `device-ca.crt` und `device-ca.key`.

**2 — Relay:**

```sh
install -m755 out/linux-x64/schleuse /usr/local/bin/schleuse
useradd --system --no-create-home --shell /usr/sbin/nologin schleuse
install -d -m750 -o root -g schleuse /etc/schleuse
install -m640 -o root -g schleuse ca.crt relay.crt relay.key device-ca.crt device-ca.key /etc/schleuse/
cp examples/relay.json /etc/schleuse/           # und anpassen
cp deploy/schleuse-relay.service /etc/systemd/system/
systemctl enable --now schleuse-relay
```

Für die Weboberfläche empfiehlt sich ein öffentlich vertrauenswürdiges
Zertifikat, damit der Browser nicht warnt:

```sh
certbot certonly --standalone -d tunnel.example.com
# Pfade in relay.json unter "web" eintragen
```

Das Protokoll nennt beim Start das Einrichtungskennwort für den ersten
Verwalter und den CA-Fingerabdruck für die Selbstanmeldung:

```
warn  web    noch kein Benutzer eingerichtet. Zum Anlegen des ersten Verwalters:
warn  web        https://tunnel.example.com:8443/setup   Kennwort: QID47-SXOJZ-...
info  relay  CA-Fingerabdruck fuer 'schleuse enroll': PGVZ-4CT3-JUFW-E3RD
```

**3 — Geräte:** siehe [Ein neues Gerät anschließen](#ein-neues-gerät-anschließen).
Nach der Freigabe:

```sh
cp deploy/schleuse-agent.service /etc/systemd/system/
systemctl enable --now schleuse-agent
```

**4 — Bediener:** `ca.crt`, `client-db.crt`, `client-db.key` und `client.json`
nach `~/.config/schleuse/`.

## Verwalten im Browser

Die Oberfläche kommt ohne JavaScript aus und tut sechs Dinge. **Ihre Texte
sind englisch**; das Protokoll des Relays bleibt deutsch:

* **Overview** — was ist verbunden, was läuft gerade.
* **Queue** — neue Anträge mit Fingerabdruck zum Vergleichen, Name und
  Portfreigaben vergeben, freigeben oder ablehnen.
* **Devices** — Notiz, freigegebene Dienste, sperren, entfernen. Welche Adresse
  hinter einem Dienstnamen steht, entscheidet weiterhin das Gerät; hier wird nur
  freigegeben oder gesperrt.
* **Access** — wer auf welche Geräte und Dienste darf. Die Zertifikate dazu
  entstehen offline, nicht hier.
* **Users** — Verwalter und nur-lesende Zugänge, Passwort und zweiten Faktor
  zurücksetzen.
* **API** — Marken ausgeben und zurückziehen.

Jeder Benutzer braucht Passwort und zweiten Faktor. Beim ersten Anmelden wird
das Geheimnis für die Authenticator-App als QR-Code angezeigt, darunter zum
Abtippen in Base32 und als vollständige `otpauth://`-Zeile — nicht jede App kann
scannen, und wer den Code auf demselben Bildschirm hat wie die App, braucht den
Text. Dazu kommen acht Wiederherstellungscodes, die je einmal gelten.

Der QR-Code entsteht im Dienst und steht als SVG im Dokument. Kein Kodierdienst
im Netz: die Zeile enthält das Geheimnis des zweiten Faktors, sie an einen
Fremden zu schicken höbe die ganze Übung auf. Kein nachgeladenes Bild: die
Inhaltsregel der Oberfläche bleibt damit bei `default-src 'none'`.

## Maschinell verwalten

Jede Funktion der Oberfläche gibt es auch als Aufruf. Ausgewiesen wird sich mit
einer Marke, die in der Oberfläche oder über die Schnittstelle selbst entsteht:

```sh
T=schleuse_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
B=https://tunnel.example.com:8443/api

curl -H "Authorization: Bearer $T" $B/status
curl -H "Authorization: Bearer $T" $B/pending

curl -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
     -d '{"id":"a1b2…","device":"werk3-hmi","note":"Halle 3","services":["ssh","http"]}' \
     $B/pending/approve
```

| Lesen (`GET`) | |
|---|---|
| `/status` | Überblick, CA-Fingerabdruck, laufende Sitzungen |
| `/devices` | Geräteliste mit Online-Zustand und Freigaben |
| `/pending` | Warteschlange mit Fingerabdrücken |
| `/clients` | Zugänge und ihre Muster |
| `/users` | Benutzer der Oberfläche (ohne Geheimnisse) |
| `/tokens` | ausgegebene Marken (nie im Klartext) |

| Ändern (`POST`, nur Verwalter-Marke) | Felder |
|---|---|
| `/pending/approve` | `id`, `device`, `note`, `services[]` |
| `/pending/reject`, `/pending/delete` | `id` |
| `/devices/save` | `device`, `note`, `services[]`, `revoked` |
| `/devices/delete` | `device` |
| `/clients/save` | `client`, `devices[]`, `services[]`, `revoked` |
| `/clients/delete` | `client` |
| `/users/add` | `user`, `role` → gibt das Anfangspasswort einmalig zurück |
| `/users/delete` | `user` |
| `/users/reset` | `user`, `what` = `password` \| `2fa` |
| `/tokens/create` | `name`, `role`, `days` → gibt die Marke einmalig zurück |
| `/tokens/delete` | `id` |
| `/ui` | `enabled` — schaltet die Weboberfläche ab oder ein |

Eine Marke mit der Rolle `viewer` darf nur lesen; ein Schreibversuch bekommt
`403`. Ein Pfad, den es nicht gibt, bekommt `404` — genau wie jeder Pfad ohne
Marke, damit sich die Schnittstelle nicht absuchen lässt.

**Oberfläche abschalten.** Wer die Verwaltung nach der Einrichtung nur noch
maschinell betreiben will:

```sh
curl -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
     -d '{"enabled":false}' $B/ui
```

Danach antwortet der Port auf jeden Oberflächenpfad mit 404, als gäbe es sie
nicht; die Schnittstelle bleibt erreichbar und kann sie wieder einschalten.
Geht die Marke verloren, hilft auf dem Relay:

```sh
schleuse ui -c /etc/schleuse/relay.json -on
systemctl reload schleuse-relay
```

Der Vorsatz aller Pfade ist über `web.api_path` frei wählbar. Ein
nicht erratbarer Wert hält beiläufiges Absuchen fern — die eigentliche
Absicherung ist und bleibt die Marke.

## Benutzen

**Was ist gerade erreichbar?**

```sh
$ schleuse client -list
GERAET                   DIENSTE                             ONLINE  SITZUNGEN
pumpstation-nord         ssh                                     3s          0
werk1-hmi                http,ssh                                2s          0
werk2-hmi                http,modbus,ssh                         3s          0
```

Ein anderer Zugang sieht an derselben Stelle etwas anderes.

**Mehrere Geräte und Protokolle in einem Prozess:**

```sh
schleuse client -forward werk1-hmi/ssh=127.0.0.1:2201 \
            -forward werk1-hmi/http=127.0.0.1:8001 \
            -forward werk2-hmi/ssh=127.0.0.1:2202 \
            -forward werk2-hmi/modbus=127.0.0.1:5021

ssh  -p 2201 root@127.0.0.1
curl http://127.0.0.1:8001/
```

Stehen die Weiterleitungen unter `forwards` in `~/.config/schleuse/client.json`,
genügt `schleuse client`.

Für die lokalen Ports lohnt ein Blick auf
`/proc/sys/net/ipv4/ip_local_port_range` (üblich 32768–60999): wer eine
Weiterleitung dort hineinlegt, bekommt gelegentlich „Address already in use",
weil eine ausgehende Verbindung denselben Port gerade als Quellport belegt hat.
Werte darunter sind unauffällig.

**Einzeln:**

```sh
schleuse client -device werk1-hmi -service ssh -listen 127.0.0.1:2222
scp -P 2222 firmware.bin root@127.0.0.1:/tmp/
```

**Ohne offenen Port, als ProxyCommand** — der sauberste Weg für SSH:

```
Host werk1-hmi werk2-hmi pumpstation-nord
    ProxyCommand schleuse client -device %h -service ssh -stdio
    User root
```

Danach genügt `ssh werk1-hmi` und `scp datei werk2-hmi:/tmp/`.

## Erweitern

Ein weiteres Protokoll ist ein Eintrag in `services` des Geräts:

```json
"services": {
  "ssh":    "127.0.0.1:22",
  "modbus": "192.168.10.5:502",
  "opcua":  "192.168.10.7:4840",
  "vnc":    "127.0.0.1:5900"
}
```

Das Ziel muss nicht auf dem Gerät liegen: `192.168.10.5:502` macht das Gerät zum
kontrollierten Zugang in sein Anlagennetz — aber nur zu genau dieser Adresse.
Bei der Selbstanmeldung lässt sich das gleich mitgeben (`-service …`); in der
Oberfläche wird der Dienst dann nur noch freigegeben.

## Testen

Fünf Suiten, alle ohne Vorbereitung lauffähig — sie bauen sich CAs, Relay,
Geräte und Bediener in einem temporären Verzeichnis selbst auf:

```sh
./build.sh
./out/linux-x64/schleuse verify-crypto   # 186 Testvektoren aus den Spezifikationen
./scripts/selftest.sh                # 22 Prüfungen: tut es, was es soll
./scripts/securitytest.sh            # 24 Prüfungen: lehnt es ab, was es ablehnen muss
./scripts/multitest.sh               # 19 Prüfungen: mehrere Geräte, parallel, getrennt
./scripts/webtest.sh                 # 39 Prüfungen: Oberfläche und Selbstanmeldung
./scripts/apitest.sh                 # 44 Prüfungen: Schnittstelle und Verschwiegenheit
./scripts/sbom.sh                    # Stückliste im CycloneDX-Format
```

`verify-crypto` rechnet TOTP gegen RFC 6238, Base32 gegen RFC 4648 und PBKDF2
gegen RFC 6070 nach — selbstgeschriebene Krypto-Bausteine, die nur plausibel
aussehen, sind die häufigste Ursache stiller Sicherheitslücken. Dazu den
QR-Kodierer gegen ISO/IEC 18004: für jede der vierzig Fassungen die beiden
Randlängen, jeweils das ganze Raster als Prüfsumme.

Diese Prüfsummen stammen nicht aus schleuse selbst — sonst prüfte sich der Kodierer
gegen sich selbst. Sie kommen aus `scripts/qr-gegenpruefen.py`, das den Kodierer
gegen unabhängige Umsetzungen stellt: knapp tausend Eingaben über den ganzen
Bereich, Modul für Modul gegen die Bibliothek `qrcode`, die Maskenwahl gegen die
eigenständig nachgerechneten Strafterme der Norm, und jeder erzeugte Code einmal
mit `zxing-cpp` wieder entziffert. Das Skript braucht zusätzliche Pakete und
läuft darum nicht in den Suiten mit; nötig ist es beim Ändern des Kodierers.

`webtest.sh` spielt den ganzen Weg durch: Ersteinrichtung, zweiter Faktor,
Anmeldung, ein Gerät meldet sich selbst an, wartet, wird freigegeben, holt sein
Zertifikat und trägt danach einen Tunnel. Dazwischen: Zugriff ohne Sitzung,
Formular mit falschem Merkmal, nur-lesende Rolle, Sperre nach fünf
Fehlversuchen, Fingerabdruck-Abgleich zwischen Gerät und Oberfläche.

`apitest.sh` prüft, dass ohne Marke nichts zu erfahren ist (auch nicht unter
`/openapi`, `/swagger` oder `/docs`), dass ein Sitzungskeks nicht als Marke
gilt, dass eine lesende Marke nichts ändern kann, dass der ganze Ablauf von der
Selbstanmeldung bis zum Tunnel auch maschinell geht, und dass sich die
Oberfläche ab- und wieder einschalten lässt.

`KEEP=1` vor dem Aufruf behält das Arbeitsverzeichnis samt Logs zur Nachschau.

## Gemessen

Native-AOT-Binary, x86-64, alle Rollen auf einer Maschine über Loopback:

| | |
|---|---|
| Binary | 12 MB, keine Laufzeit-Abhängigkeit |
| Startzeit | 3,2 ms |
| Speicher, Relay und Agent je | 14 MB RSS im Leerlauf |
| Relay mit 50 angemeldeten Geräten | 23 MB RSS, 1,7 % CPU — rund 190 kB je Gerät |
| Durchsatz HTTP durch den Tunnel | 439 MB/s (50 MB, drei TLS-Strecken hintereinander) |
| 100 Anfragen, 50 gleichzeitig | alle mit 200 in 0,7 s |

### Wie groß muss der Relay sein?

Gemessen mit dem Relay allein, unter Last aus simulierten Geräten und
gehaltenen Tunneln; für den Kerntest auf einen einzigen Kern geheftet:

| | |
|---|---|
| Grundbedarf | 20 MB RSS |
| je angemeldetem Gerät | **rund 200 kB** (300 Geräte: 73 MB, 2,7 % eines Kerns) |
| je gleichzeitigem Tunnel | **rund 300 kB** (250 Tunnel: 95 MB, 4,2 % eines Kerns) |
| Verbindungsaufbauten | rund 1 500/s bei halber Auslastung eines Kerns |
| Durchsatz auf einem Kern | 673 MB/s |

Daraus die Faustformel:

    RAM ≈ 25 MB + 0,2 MB × Geräte + 0,3 MB × gleichzeitige Tunnel + Reserve

Eine Anlage mit 50 Geräten und fünf gleichzeitigen Sitzungen braucht also rund
40 MB. Selbst 500 Geräte mit 50 Sitzungen bleiben unter 150 MB.

**Empfehlung: 1 vCore und 1 GB RAM genügen bis in den Bereich einiger hundert
Geräte.** Zwei Kerne und 2 GB sind die bequeme Wahl, wenn über tausend Geräte
zusammenkommen, regelmäßig viele Firmware-Übertragungen gleichzeitig laufen
oder auf derselben Maschine noch etwas anderes wohnt. Bei 1 GB gehört eine
Auslagerungsdatei dazu.

Die Messungen stammen von einem Arbeitsplatzrechner; ein vCore beim Anbieter
ist zwei- bis viermal langsamer. Auch dann bleiben mehrere hundert
Verbindungsaufbauten je Sekunde und ein Durchsatz weit über dem, was die
Leitung hergibt — 1 Gbit/s sind 125 MB/s.

**Der Kostentreiber ist deshalb nicht Rechenleistung oder Speicher, sondern
durchgereichter Datenverkehr.** Jedes Byte läuft durch den Relay. Beim Vergleich
von Angeboten zählt das Freivolumen, nicht die Zahl der Kerne.

**Ausprobieren geht ohne Anbieter.** Ein systemd-Bereich sperrt die ganze
Testumgebung in die Grenzen einer kleinen VM:

```sh
systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=2G \
    ./scripts/multitest.sh
```

Alle fünf Suiten laufen darin durch — Relay, drei Agenten, sechs
Weiterleitungen und sechs Testserver zusammen — mit einer Speicherspitze von
143 MB und 19 Sekunden Rechenzeit. Auf einer echten Maschine wohnt dort nur der
Relay.

Zwei Stellschrauben, falls es doch eng wird: die Übertragungspuffer sind 64 kB
je Richtung (`Pump.BufferSize`) und machen den Löwenanteil der 300 kB je Tunnel
aus; und der Speicher wird nach Lastspitzen nur langsam an das Betriebssystem
zurückgegeben, die Zahlen oben sind also Höchststände, nach denen zu bemessen
ist.

## Grenzen

* **Ein lokaler Port ist für jeden auf dem Rechner offen.** Wer sich am Notebook
  des Bedieners anmelden kann, kann die eingerichteten Weiterleitungen
  mitbenutzen — das gilt für jede Portweiterleitung, auch für `ssh -L`. Wo das
  stört, ist `-stdio` der Weg.
* **Bediener-Zertifikate entstehen offline.** Die Oberfläche verwaltet
  Berechtigungen, stellt aber nichts aus — bewusst, denn die Zwischen-CA auf dem
  Relay darf nur Geräte beglaubigen.
* **UDP wird nicht getunnelt.** Der Tunnel ist TCP.
* **Die Uhr des Geräts muss ungefähr stimmen.** Bei Hardware ohne gepufferte Uhr
  gehört NTP vor den schleuse-Dienst.
* **Zertifikate laufen ab** (Geräte 825 Tage, Bediener 365). Es gibt keine
  automatische Erneuerung; `schleuse-pki.sh list` zeigt die Restlaufzeiten.
* **Der Relay ist ein Single Point of Failure.** Er hält seinen Zustand in
  wenigen JSON-Dateien; ein zweiter Relay ist schnell aufgesetzt, aber die
  Agenten kennen nur eine Adresse.
* **Zwei Agenten mit demselben Zertifikat verdrängen sich gegenseitig.** Jedes
  Gerät braucht sein eigenes.

## Aufbau des Quelltexts

| Datei | Inhalt |
|---|---|
| `src/Protocol.cs` | Drahtformat: zeilenweises JSON für Handshake und Control, danach rohe Bytes |
| `src/Tls.cs` | mTLS, Prüfung gegen die eigene CA, Identität und Aussteller aus dem Zertifikat |
| `src/Relay.cs` | Vermittlung, Geräteregister, Zugriffsliste, Annahme von Anträgen |
| `src/Agent.cs` | Anmeldung, Wiederverbindung, Dienstefreigabe |
| `src/Client.cs` | Weiterleitungen, ProxyCommand-Modus, Übersicht |
| `src/Enrollment.cs` | Warteschlange und Ausstellung von Gerätezertifikaten |
| `src/EnrollClient.cs` | `schleuse enroll` auf dem Gerät |
| `src/WebUi.cs`, `src/WebUiSeiten.cs` | Weboberfläche |
| `src/WebApi.cs`, `src/ApiTypes.cs`, `src/ApiTokens.cs` | Schnittstelle, Datenformen, Marken |
| `src/Users.cs`, `src/Passwords.cs`, `src/Totp.cs` | Benutzer, Passwörter, zweiter Faktor |
| `src/Pump.cs` | bidirektionales Kopieren mit korrekter Halb-Schließung |
| `src/Config.cs` | Konfiguration, Zugriffsliste, Glob-Muster |

Daneben: [SECURITY.md](SECURITY.md) mit Meldeweg, Unterstützungszeitraum,
Protokollierung und Löschverfahren, [TODO.md](TODO.md) mit den offenen
Punkten, sowie `sbom.cdx.json` als Stückliste.
