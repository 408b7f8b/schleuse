# schleuse — Reverse-Tunnel für Linux-Geräte

Zugriff auf Geräte hinter NAT und Firewall, ohne dort einen Port zu öffnen.
Das Gerät baut selbst eine ausgehende TLS-Verbindung zu einem Relay im Internet
auf; über dieselbe Verbindung wird auf Anforderung SSH, SCP, HTTP oder jedes
andere TCP-Protokoll durchgereicht.

Ein neues Gerät meldet sich mit einem Befehl selbst an, landet in einer
Warteschlange und wird im Browser freigegeben. Ein Binary, keine
Laufzeit-Abhängigkeiten.

```
        Anlagennetz                   Internet                    Bediener

  ┌───────────────────┐                                    ┌────────────────────┐
  │ werk1-hmi         │                                    │  ein schleuse client   │
  │  sshd :22  ──┐    │─┐                                  │                    │
  │  httpd :80 ──┤    │ │                                  │  :2201 → werk1/ssh │
  │      schleuse agent ──┼─┤                                  │  :8001 → werk1/http│
  └───────────────────┘ │       ┌───────────────┐          │  :2202 → werk2/ssh │
  ┌───────────────────┐ │       │     relay     │          │  :5021 → werk2/mb  │
  │ werk2-hmi         │ ├───────▶  :443  Tunnel ◀──────────┤                    │
  │  sshd, httpd,     │ │ausgeh.│         + Selbstanmeldung│  alles gleichzeitig│
  │  modbus :502      │ │  TLS  │  :8443 Weboberfläche     │                    │
  │      schleuse agent ──┼─┘       └───────▲───────┘          └────────────────────┘
  └───────────────────┘                 │ Passwort + 2FA
  ┌───────────────────┐                 │
  │ neues Gerät       │─ Antrag ─┐  ┌───┴────────────┐
  │   schleuse enroll ────┼──────────┴─▶│  Warteschlange │──── freigeben ──▶ Betrieb
  └───────────────────┘             └────────────────┘
     kein offener Port      einziger offener Port         kein offener Port
                            für Geräte                    (nur loopback)
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

## Gefundene und behobene Schwachstellen

Beim Durchsehen des Codes sind fünf Punkte aufgefallen. Alle sind behoben und
durch die Testsuiten abgedeckt:

1. **Die Handshake-Drossel wurde über die gesamte Sitzungsdauer gehalten.** Ab
   256 angemeldeten Geräten hätte der Relay keine neue Verbindung mehr
   angenommen. Der Platz wird jetzt direkt nach dem Handshake freigegeben.
2. **Eine Sperre wirkte nur auf neue Verbindungen.** Ein Reload beendet nun auch
   laufende Sitzungen, deren Berechtigung weggefallen ist.
3. **Keine Bindung der Schlüsselverwendung.** Server- und Client-Authentisierung
   sind jetzt getrennt erzwungen, damit ein Gerätezertifikat auch mit passendem
   Hostnamen keinen Relay vortäuschen kann.
4. **Zertifikatsnamen gingen ungeprüft ins Log.** Text aus fremder Hand wird
   jetzt entschärft.
5. **Ausgestellte Zertifikate begannen fünf Minuten vor der ausstellenden CA.**
   Eine frisch angelegte Zwischen-CA konnte deshalb ihr erstes Gerät nicht
   freigeben. Gültigkeitszeitraum wird jetzt an dem der CA beschnitten.
6. **Die Bremse der Schnittstelle sperrte die Herkunft statt den Fehlversuch.**
   Hinter einem NAT hätte ein einziger Störer alle anderen mit ausgesperrt. Eine
   gültige Marke kommt jetzt immer durch; verzögert wird nur der Fehlversuch.
7. **Lesen-Ändern-Schreiben auf der Zugriffsliste war nicht zusammenhängend.**
   Zwei gleichzeitige Änderungen — eine aus der Oberfläche, eine über die
   Schnittstelle — konnten sich überschreiben. Ausgerechnet eine verlorene
   Sperre wäre so ein Fall gewesen. Jetzt unter einem Schloss.
8. **Das Zertifikat der Oberfläche wurde nur beim Start geladen.** Ein von
   certbot erneuertes wäre erst beim nächsten Neustart wirksam geworden — und
   spätestens nach neunzig Tagen hätte der Browser gewarnt.
9. **Eingaben der Schnittstelle waren unbegrenzt.** Notizen und Muster gingen
   ungeprüft in die Zugriffsliste; jetzt gekürzt, von Steuerzeichen befreit und
   auf brauchbare Zeichen beschränkt.
10. **Eine Prüfung auf unbekannte Benutzer kostete zwei PBKDF2-Durchgänge**
    statt einem — doppelte Rechenlast je Fehlversuch, also doppelt so wirksam
    als Hebel für eine Überlastung. Der Vergleichswert wird jetzt einmal beim
    Start gebildet.
11. **Die Geräteliste war offen, wenn sie fehlte.** Das war nicht „secure by
    default"; jetzt darf sich ohne Eintrag niemand anmelden.

Zusätzlich wird die Konfiguration streng gelesen: ein Tippfehler in `services`
oder `devices` bricht den Start ab, statt still zu einer leeren Liste zu werden.

## Bauen

```sh
./build.sh                       # für die eigene Architektur
./build.sh linux-x64 linux-arm64 # mehrere Ziele
```

Ergebnis: `out/<rid>/schleuse`, rund 12 MB. Auf dem Zielgerät wird keine
.NET-Runtime gebraucht. Querbauen für eine andere Architektur braucht `clang`; fehlt es, weicht
`build.sh` selbsttätig auf ein self-contained Single-File-Bundle aus (rund
20 MB, läuft ebenso ohne vorinstallierte Runtime). Dasselbe gilt für
32-bit-ARM, für das es kein Native AOT gibt.

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

Die Oberfläche kommt ohne JavaScript aus und tut fünf Dinge:

* **Übersicht** — was ist verbunden, was läuft gerade.
* **Warteschlange** — neue Anträge mit Fingerabdruck zum Vergleichen, Name und
  Portfreigaben vergeben, freigeben oder ablehnen.
* **Geräte** — Notiz, freigegebene Dienste, sperren, entfernen. Welche Adresse
  hinter einem Dienstnamen steht, entscheidet weiterhin das Gerät; hier wird nur
  freigegeben oder gesperrt.
* **Zugänge** — wer auf welche Geräte und Dienste darf. Die Zertifikate dazu
  entstehen offline, nicht hier.
* **Benutzer** — Verwalter und nur-lesende Zugänge, Passwort und zweiten Faktor
  zurücksetzen.
* **Schnittstelle** — Marken ausgeben und zurückziehen.

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

## Cyber Resilience Act

**Die Einstufung zuerst, weil sie über alles Weitere entscheidet.** schleuse trifft
gleich drei Kategorien der Anhang-III-Klasse I („wichtige Produkte"):
*VPN-Produkte* (Nr. 5), *Netzwerkverwaltungssysteme* (Nr. 6) und — am
eindeutigsten — *Software zur Ausstellung digitaler Zertifikate* (Nr. 9), denn
der Relay stellt Gerätezertifikate aus.

### Konformitätsweg für Klasse I

Eine Zertifizierung durch eine benannte Stelle ist **nicht** zwingend. Art. 32
Abs. 2 lässt für Klasse I die interne Kontrolle (Modul A, Eigenerklärung) zu —
aber nur, wenn harmonisierte Normen, gemeinsame Spezifikationen oder ein
EU-Zertifizierungsschema auf Stufe „substanziell" **vollständig** angewandt
werden und die einschlägigen Anforderungen abdecken. Nur teilweise angewandt,
nicht vorhanden oder nicht abdeckend, dann bleibt Modul B+C
(EU-Baumusterprüfung) oder Modul H (umfassende Qualitätssicherung) — beides mit
benannter Stelle. Der Unterschied zu Klasse II liegt genau hier: dort steht
Modul A gar nicht erst zur Wahl.

**Der Haken ist der Zeitplan.** Bislang ist keine CRA-Norm im Amtsblatt
zitiert; die Konformitätsvermutung besteht also noch für kein Produkt. Es sind
zwei Tore hintereinander: ETSI muss die Norm veröffentlichen, und die
Kommission muss sie im Amtsblatt zitieren. Erst das zweite zählt rechtlich —
der Entwurf sagt es selbst: *„Once the present document is cited in the
Official Journal … compliance … confers … a presumption of conformity."*

| Norm | deckt ab | Stand (August 2026) |
|---|---|---|
| EN 304 620 | VPN-Produkte | **Entwurf** V1.0.0, kombinierte Umfrage- und Abstimmungsphase |
| EN 304 621 | Netzwerkverwaltungssysteme | Entwurf, öffentliche Umfrage |
| EN 304 624 | PKI und Zertifikatsausstellung | Entwurf, öffentliche Umfrage |
| EN 40000-1-3 | Umgang mit Schwachstellen (horizontal) | Umfrage abgeschlossen |
| EN 40000-1-4 | allgemeine Sicherheitsanforderungen (horizontal) | in Arbeit, Liefertermin Oktober 2027 |

Die Entwürfe tragen bereits die Kopfzeile „Harmonised European Standard" und
sind unter dem Normungsauftrag C(2025)618 entstanden — das ist die Bauart des
Dokuments, nicht sein Status. Auf dem Deckblatt steht „Draft".

„Vollständig angewandt" heißt: alle einschlägigen, nicht die bequemste. Drei
vertikale Normen sind mehr Arbeit als eine.

### Die Einstufung ist inzwischen nachlesbar

Seit der **Durchführungsverordnung (EU) 2025/2392 vom 28. November 2025** gibt
es verbindliche technische Beschreibungen der Anhang-III-Kategorien. Die
Einstufung gehört dagegen geprüft und schriftlich festgehalten, nicht gegen die
Kategorienamen. Kategorie 5 lautet dort:

> Produkte mit digitalen Elementen, die einen verschlüsselten logischen Tunnel
> herstellen, der aus den Systemressourcen eines physischen oder virtuellen
> Netzes gebildet wird.

Darauf passt schleuse der Sache nach, auch wenn es kein VPN im hergebrachten Sinn
ist: es gibt keine virtuelle Netzwerkschnittstelle und kein Routing, sondern
weitergeleitete TCP-Verbindungen. Der Anwendungsbereich von EN 304 620 nennt
ausdrücklich Software als VPN-Endpunkt, als Server und als „remote data
processing" — Agent und Relay lassen sich darunter fassen. Wer anders
entscheidet, sollte die Begründung aufschreiben; eine Einstufung, die niemand
nachvollziehen kann, ist im Streitfall keine.

**Ein Hebel, der in eurer Hand liegt:** Kategorie 9 kommt allein durch die
Selbstanmeldung ins Spiel — der Relay stellt nur dann Zertifikate aus, wenn der
Abschnitt `enrollment` gesetzt ist. Ohne ihn verwaltet die Oberfläche bloß und
schleuse ist keine Zertifikatsausstellungs-Software mehr. Wer den Aufwand klein
halten will, liefert die Selbstanmeldung abgeschaltet aus oder trennt sie ab und
stellt Gerätezertifikate weiter offline mit `schleuse-pki.sh` aus.

Auch bei Modul A bleibt die Substanz gleich: technische Dokumentation nach
Anhang VII, Risikobeurteilung, Prozesse für den Umgang mit Schwachstellen. Es
entfällt nur der Dritte.

**Ob das überhaupt greift, hängt am Vertriebsweg.** Der CRA bindet den
Hersteller, der ein Produkt *auf dem Markt bereitstellt*. Wer schleuse
ausschließlich für die eigenen Anlagen betreibt, stellt nichts bereit — dann
gelten die Herstellerpflichten nicht. Sobald es mit Maschinen ausgeliefert, in
ein Produkt eingebaut oder Kunden zur Verfügung gestellt wird, gelten sie.
Diese Frage gehört beantwortet, bevor der Aufwand geschätzt wird.

**Termine:** Meldepflichten für aktiv ausgenutzte Schwachstellen ab
**11. September 2026** (24 h Frühwarnung, 72 h Meldung, 14 Tage Abschluss),
der Rest ab **11. Dezember 2027**.

### Was der Code bereits erfüllt

| Anhang I Teil I | Stand |
|---|---|
| Sichere Voreinstellung (1c) | Ohne Eintrag in der Geräteliste darf sich **niemand** anmelden; die offene Betriebsart ist ein ausdrücklicher Schalter |
| Zugangsschutz (2a) | mTLS beidseitig, Rollentrennung durch den Aussteller erzwungen, ACL je Bediener, Passwort + zweiter Faktor, Marken mit Rolle |
| Vertraulichkeit (2b) | TLS 1.3; Schlüssel 0600, Zustandsverzeichnis 0700; Passwörter als PBKDF2, Marken als SHA-256 |
| Integrität (2c) | Unteilbares Schreiben aller Zustandsdateien; strenges Lesen der Konfiguration — ein Tippfehler bricht den Start ab |
| Datensparsamkeit (2d) | Keine Nutzdaten protokolliert; Anträge samt Herkunft nach 30 Tagen verworfen |
| Verfügbarkeit (2e) | Handshake-Drossel, Sitzungsbudgets je Gerät und je Bediener, begrenzte Warteschlange, wachsende Bremse bei Fehlversuchen, begrenzte Rumpfgröße |
| Angriffsfläche (2g) | Ein Port für Geräte; Verwaltung getrennt und abschaltbar; keine Selbstauskunft der Schnittstelle |
| Schadensbegrenzung (2h) | Kein JIT, kein beschreibbarer ausführbarer Speicher, keine unsicheren Speicherzugriffe, systemd-Härtung |
| Protokollierung (2i) | Jede Anmeldung, Abweisung und Änderung mit Urheber und Herkunft; Aufbewahrung und Abschaltung über journald |
| Sicheres Löschen (2j) | Verfahren in [SECURITY.md](SECURITY.md) |

| Anhang I Teil II | Stand |
|---|---|
| Stückliste (1) | `./scripts/sbom.sh` erzeugt `sbom.cdx.json` im CycloneDX-Format aus dem echten Abhängigkeitsgraphen |
| Prüfungen (3) | Fünf Suiten mit 147 Prüfungen und die Nachrechnung der Krypto-Bausteine gegen ihre Spezifikationen |
| Meldeweg (5, 6) | Politik zur koordinierten Offenlegung in [SECURITY.md](SECURITY.md) |

### Was noch offen ist

Das sind keine Codefragen, sondern Aufgaben des Herstellers:

* **Vertriebsweg klären** — davon hängt ab, ob überhaupt etwas davon greift.
* **Kontaktadresse und Unterstützungszeitraum eintragen.** In
  [SECURITY.md](SECURITY.md) stehen Platzhalter; ohne beides ist Anhang II
  nicht erfüllt.
* **Freigaben signieren.** Das Verfahren steht in SECURITY.md, der Schlüssel
  fehlt noch. Ohne Signatur gibt es keine sichere Verteilung (Teil II Nummer 7).
* **Risikobeurteilung schreiben** (Art. 13 Abs. 2) und der technischen
  Dokumentation beilegen. Das Sicherheitsmodell oben ist die Vorarbeit dazu,
  aber keine Beurteilung.
* **Konformitätsweg wählen** — siehe oben. Solange keine Norm im Amtsblatt
  steht, ist Modul A praktisch versperrt; die Pflichten greifen ab Dezember 2027
  unabhängig davon, ob es bis dahin eine gibt.
* **Meldeprozess einrichten**, der die 24-Stunden-Frist ab September 2026 halten
  kann — inklusive Zugang zur einheitlichen Meldeplattform.
* **CE-Kennzeichnung und EU-Konformitätserklärung** vorbereiten.

Diese Einschätzung stammt aus dem Verordnungstext und der öffentlichen
Auslegung; sie ersetzt keine rechtliche Prüfung.

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
Protokollierung und Löschverfahren, [BETRIEB.md](BETRIEB.md) mit der laufenden
Installation, [TODO.md](TODO.md) mit den offenen Punkten, sowie
`sbom.cdx.json` als Stückliste.
