#!/bin/sh
# install-relay.sh - richtet den Relay auf DIESER Maschine ein
#
# Gegenstueck zu deploy-relay.sh: dort schiebt der Arbeitsplatz alles per SSH
# auf den Server, hier wird vor Ort eingerichtet - an der Konsole, im
# Rechenzentrum, auf einer Maschine, die von aussen niemanden hereinlaesst.
#
# Gebraucht wird das Binary und - sofern nicht hier erzeugt - die PKI:
#
#     schleuse                        zwingend, oder mit -holen herunterladen
#     ca.crt relay.crt relay.key      zwingend, oder mit -pki-neu erzeugen
#     device-ca.crt device-ca.key     fuer die Selbstanmeldung
#     BUILD-MODE                      sagt, ob Native AOT oder Bundle
#
# Alles davon neben dieses Skript legen und aufrufen:
#
#     sudo ./install-relay.sh
#
# Auf einem Geraet ohne alles genuegt das Skript selbst: -holen laedt das
# Binary zur erkannten Architektur aus dem neuesten Release und prueft es
# gegen die dort veroeffentlichten Pruefsummen.
#
#     sudo ./install-relay.sh -holen -pki-neu -name relais.example.com
#
# Aus dem Quellbaum heraus findet das Skript Binary und PKI von selbst
# (out/<rid>/ und ./pki bzw. $SCHLEUSE_PKI).
#
# Wiederholbar: ein zweiter Lauf tauscht das Binary und laesst eine vorhandene
# relay.json unangetastet.
#
# Zu den Zertifikaten: der Schluessel der Wurzel-CA gehoert eigentlich NICHT
# auf den Relay. Wer ihn hat, kann Bediener-Zugaenge ausstellen - und der Relay
# ist die Maschine, die im Internet steht. Mit -pki-neu erzeugt dieses Skript
# die CA trotzdem hier, weil es sonst keinen Weg gaebe, eine Anlage allein von
# dieser Maschine aus aufzusetzen. Es sagt dann am Ende, wie der Schluessel
# wieder von hier verschwindet.

set -eu

# --- Voreinstellungen --------------------------------------------------------
SELBST=$(cd "$(dirname "$0")" && pwd)
Q_BIN=""          # Verzeichnis mit dem Binary
Q_CERT=""         # Verzeichnis mit den Zertifikaten
PKI=""            # Ablage der CA, wenn hier ausgestellt wird
NAMEN=""          # Namen im Relay-Zertifikat
PORT=443          # Tunnelport
WEBPORT=8443      # Weboberflaeche, 'aus' schaltet sie ab
MODUS=""          # aot | singlefile, sonst erkannt
PROBE=nein        # -n: nur berichten, nichts anfassen
PKINEU=nein       # -pki-neu: CA hier erzeugen, ohne zu fragen
ENROLL=ja         # Selbstanmeldung einrichten
CLIENT=""         # zusaetzlich ein Bediener-Zertifikat ausstellen
HOLEN=nein        # -holen: Binary aus dem Release laden
FASSUNG=""        # -fassung <tag>: statt des neuesten Release
DIENST=schleuse-relay
REPO="${SCHLEUSE_REPO:-408b7f8b/schleuse}"

# Alles, was beim Beenden wieder wegkommt.
AUFRAEUMEN=""
trap 'rm -rf $AUFRAEUMEN' EXIT

CA_DAYS="${CA_DAYS:-3650}"
RELAY_DAYS="${RELAY_DAYS:-825}"
CLIENT_DAYS="${CLIENT_DAYS:-365}"

rot=''; fett=''; aus=''
if [ -t 1 ]; then
	fett=$(printf '\033[1m'); rot=$(printf '\033[31m'); aus=$(printf '\033[0m')
fi

sag()  { printf '\n%s== %s ==%s\n' "$fett" "$1" "$aus"; }
zeile(){ printf '  %s\n' "$*"; }
warn() { printf '  %sACHTUNG:%s %s\n' "$rot" "$aus" "$*"; }
die()  { printf '%sinstall-relay: %s%s\n' "$rot" "$*" "$aus" >&2; exit 1; }

# Fuehrt aus - oder sagt im Probelauf nur, was geschehen wuerde.
tu() {
	if [ "$PROBE" = ja ]; then printf '  [probe] %s\n' "$*"; else "$@"; fi
}
# Vollzugsmeldung: im Probelauf ist nichts vollzogen, also schweigen.
getan() { if [ "$PROBE" = nein ]; then zeile "$@"; fi; }

hilfe() {
	cat <<'EOF'
Aufruf: install-relay.sh [Angaben]

  -d <verz>        Verzeichnis mit Binary und Zertifikaten
                   (Vorgabe: neben diesem Skript, sonst der Quellbaum)
  -holen           Binary aus dem neuesten Release laden, Pruefsumme pruefen
  -fassung <tag>   dabei diese Fassung statt der neuesten (z.B. v1.0.0)
  -name <name>     Name, unter dem Geraete den Relay ansprechen. Mehrfach
                   moeglich; der erste steht im CN. Ohne Angabe wird geraten.
  -port <n>        Tunnelport (Vorgabe 443)
  -web <n|aus>     Port der Weboberflaeche (Vorgabe 8443)

  -pki <verz>      Ablage der CA (Vorgabe /root/schleuse-pki)
  -pki-neu         fehlende Zertifikate hier ausstellen, ohne zu fragen
  -client <name>   zusaetzlich ein Bediener-Zertifikat ausstellen
  -ohne-enrollment keine Selbstanmeldung einrichten

  -modus <art>     aot oder singlefile; sonst am Binary erkannt
  -n               Probelauf: nur pruefen und berichten
  -h               diese Hilfe
EOF
}

# --- Angaben lesen -----------------------------------------------------------
ARGS="$*"
braucht() { [ "$2" -ge 2 ] || die "$1 braucht einen Wert"; }
while [ $# -gt 0 ]; do
	case "$1" in
	-d)               braucht -d $#; Q_BIN=$2; Q_CERT=$2; shift 2 ;;
	-name)            braucht -name $#; NAMEN="$NAMEN $2"; shift 2 ;;
	-port)            braucht -port $#; PORT=$2; shift 2 ;;
	-web)             braucht -web $#; WEBPORT=$2; shift 2 ;;
	-pki)             braucht -pki $#; PKI=$2; shift 2 ;;
	-holen)           HOLEN=ja; shift ;;
	-fassung)         braucht -fassung $#; FASSUNG=$2; HOLEN=ja; shift 2 ;;
	-pki-neu)         PKINEU=ja; shift ;;
	-client)          braucht -client $#; CLIENT=$2; shift 2 ;;
	-ohne-enrollment) ENROLL=nein; shift ;;
	-modus|-mode)     braucht -modus $#; MODUS=$2; shift 2 ;;
	-n|-probe)        PROBE=ja; shift ;;
	-h|-help|--help)  hilfe; exit 0 ;;
	*)                die "unbekannte Angabe '$1' (-h zeigt die Verwendung)" ;;
	esac
done

[ "$PROBE" = ja ] || [ "$(id -u)" = 0 ] || die "muss als root laufen: sudo $0 $ARGS"
case "$WEBPORT" in aus|nein|0) WEBPORT=aus ;; *[!0-9]*) die "-web: '$WEBPORT' ist keine Portnummer" ;; esac
case "$PORT" in *[!0-9]*|'') die "-port: '$PORT' ist keine Portnummer" ;; esac
command -v openssl >/dev/null || die "openssl fehlt - ohne das laesst sich hier nichts pruefen"
command -v systemctl >/dev/null || die "kein systemd gefunden - dieser Installer richtet eine systemd-Einheit ein"

# --- Zielsystem --------------------------------------------------------------
sag "Zielsystem"
. /etc/os-release 2>/dev/null || true
zeile "System:   ${PRETTY_NAME:-unbekannt}"
zeile "Kernel:   $(uname -srm)"
zeile "Kerne:    $(nproc 2>/dev/null || echo ?), Speicher: $(free -m 2>/dev/null | awk '/^Spe|^Mem/ {print $2" MB"}')"
zeile "systemd:  $(systemctl --version | head -1)"

case "$(uname -m)" in
	x86_64)          RID=linux-x64 ;;
	aarch64|arm64)   RID=linux-arm64 ;;
	armv7l|armv6l)   RID=linux-arm ;;
	*) die "unbekannte Architektur '$(uname -m)'" ;;
esac
zeile "Architektur: $(uname -m) -> $RID"

# --- Binary holen ------------------------------------------------------------
# Laedt <url> nach <ziel>. curl und wget koennen beide, was hier gebraucht wird;
# auf einem frisch aufgesetzten Geraet ist mal das eine, mal das andere da.
lade() {
	if [ -n "$LADER" ]; then
		case "$LADER" in
			curl) curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" ;;
			wget) wget -q -T 15 -O "$2" "$1" ;;
		esac
	fi
}

if [ "$HOLEN" = ja ]; then
	sag "Binary holen"
	LADER=""
	if command -v curl >/dev/null; then LADER=curl
	elif command -v wget >/dev/null; then LADER=wget
	else die "weder curl noch wget vorhanden - ohne eines von beiden kann ich nichts holen"
	fi
	command -v sha256sum >/dev/null ||
		die "sha256sum fehlt - ohne Pruefsumme lade ich nichts aus dem Netz"

	# Ohne Angabe die neueste Fassung. GitHub leitet /releases/latest auf
	# /releases/tag/<tag> um; damit steht der Name fest, bevor irgendetwas
	# geladen wird - und er steht nachher im Bericht.
	if [ -z "$FASSUNG" ] && [ "$LADER" = curl ]; then
		FASSUNG=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
			"https://github.com/$REPO/releases/latest" 2>/dev/null |
			sed -n 's|.*/releases/tag/||p')
	fi
	if [ -n "$FASSUNG" ]; then
		BASIS="https://github.com/$REPO/releases/download/$FASSUNG"
		zeile "Release:  $FASSUNG"
	else
		BASIS="https://github.com/$REPO/releases/latest/download"
		zeile "Release:  neuestes"
	fi

	HOLDIR=$(mktemp -d); AUFRAEUMEN="$AUFRAEUMEN $HOLDIR"
	zeile "hole:     $BASIS/schleuse-$RID"
	if ! MELDUNG=$(lade "$BASIS/schleuse-$RID" "$HOLDIR/schleuse" 2>&1); then
		die "Download fehlgeschlagen: ${MELDUNG:-keine naehere Angabe}
             Gibt es zu $RID ein Binary in diesem Release?
             Uebersicht: https://github.com/$REPO/releases"
	fi
	if ! MELDUNG=$(lade "$BASIS/SHA256SUMS" "$HOLDIR/SHA256SUMS" 2>&1); then
		die "SHA256SUMS liess sich nicht laden: ${MELDUNG:-keine naehere Angabe}
             Ohne Pruefsumme geht es nicht weiter."
	fi

	SOLL=$(awk -v n="schleuse-$RID" '$2 == n || $2 == "*" n {print $1}' "$HOLDIR/SHA256SUMS")
	[ -n "$SOLL" ] || die "in SHA256SUMS steht kein Eintrag zu schleuse-$RID"
	IST=$(sha256sum "$HOLDIR/schleuse" | awk '{print $1}')
	if [ "$SOLL" != "$IST" ]; then
		die "Pruefsumme stimmt nicht.
             erwartet $SOLL
             bekommen $IST
             Nichts installiert. Das kann ein abgebrochener Download sein - oder
             etwas, das man nicht ausfuehren will."
	fi
	chmod 755 "$HOLDIR/schleuse"
	zeile "SHA256:   $IST"
	zeile "stimmt mit SHA256SUMS aus dem Release ueberein"
	Q_BIN=$HOLDIR
	[ -n "$Q_CERT" ] || Q_CERT=$SELBST
fi

# --- Quelle bestimmen --------------------------------------------------------
sag "Quelle"
if [ -z "$Q_BIN" ]; then
	if [ -f "$SELBST/schleuse" ]; then
		Q_BIN=$SELBST; Q_CERT=$SELBST
	elif [ -f "$SELBST/../out/$RID/schleuse" ]; then
		# aus dem Quellbaum heraus aufgerufen
		QUELLBAUM=$(cd "$SELBST/.." && pwd)
		Q_BIN="$QUELLBAUM/out/$RID"
		Q_CERT="${SCHLEUSE_PKI:-$QUELLBAUM/pki}"
	else
		die "kein Binary gefunden. Entweder neben dieses Skript legen
             ($SELBST/schleuse), mit -d <verz> zeigen, aus dem Quellbaum
             bauen ('./build.sh $RID') - oder mit -holen herunterladen."
	fi
fi
BIN="$Q_BIN/schleuse"
[ -f "$BIN" ] || die "$BIN fehlt"

# Laeuft das Binary auf dieser Maschine? Das beantwortet in einem Zug die Frage
# nach der Architektur und die nach der C-Bibliothek (musl gegen glibc) - und
# zwar hier, wo die Antwort noch eine Zeile ist und kein Dienst, der stumm
# nicht startet.
PRUEF=$BIN
if [ ! -x "$BIN" ]; then
	# Frisch per scp uebertragen ist es oft nicht ausfuehrbar. Eine Kopie
	# beantwortet die Frage, ohne die Vorlage anzufassen.
	PRUEF=$(mktemp); AUFRAEUMEN="$AUFRAEUMEN $PRUEF"
	cp "$BIN" "$PRUEF"; chmod 755 "$PRUEF"
fi
FASSUNG=$("$PRUEF" version 2>&1) || die "das Binary laeuft auf dieser Maschine nicht:
             $FASSUNG
             Passt es zu $RID? Gebaut wird mit './build.sh $RID'."
zeile "Binary:   $FASSUNG"
case "$FASSUNG" in
	*"($RID)"*) ;;
	*) warn "das Binary meldet eine andere Architektur als $RID - es laeuft, aber das ist selten Absicht" ;;
esac

# Betriebsart: ein Single-File-Bundle bringt einen JIT mit und braucht
# beschreibbaren ausfuehrbaren Speicher. Die systemd-Einheit verbietet genau
# das, weil sie fuer Native AOT geschrieben ist - wer beides nicht aufeinander
# abstimmt, bekommt einen Absturz beim Start und keine Erklaerung dazu.
if [ -z "$MODUS" ]; then
	if [ -f "$Q_BIN/BUILD-MODE" ]; then
		MODUS=$(cat "$Q_BIN/BUILD-MODE")
	elif grep -aq DOTNET_BUNDLE_EXTRACT_BASE_DIR "$BIN" 2>/dev/null; then
		MODUS=singlefile
	else
		MODUS=aot
	fi
fi
case "$MODUS" in
	aot)        zeile "Betriebsart: Native AOT - volle Haertung" ;;
	singlefile) zeile "Betriebsart: Single-File-Bundle mit JIT - MemoryDenyWriteExecute wird abgeschaltet" ;;
	*) die "-modus: 'aot' oder 'singlefile', nicht '$MODUS'" ;;
esac

# --- Zertifikate -------------------------------------------------------------
sag "Zertifikate"
[ -n "$PKI" ] || PKI=/root/schleuse-pki
# Eine bereits hier angelegte CA gilt, wenn im Quellverzeichnis keine liegt.
[ -f "$Q_CERT/ca.crt" ] || [ ! -f "$PKI/ca.crt" ] || Q_CERT=$PKI

# CN eines Zertifikats.
cn_von() {
	openssl x509 -in "$1" -noout -subject -nameopt multiline 2>/dev/null |
		sed -n 's/ *commonName *= *//p'
}
# Gehoeren Schluessel und Zertifikat zusammen?
paar_passt() {
	a=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null) || return 1
	b=$(openssl pkey -in "$2" -pubout 2>/dev/null) || return 1
	[ "$a" = "$b" ]
}
# Namen fuer ein neues Relay-Zertifikat raten: alles, worunter die Maschine
# ansprechbar ist. Lieber einer zu viel - Agenten und Bediener pruefen den
# Namen, und ein spaeter nachgereichter DNS-Eintrag zwingt sonst zum
# Neuausstellen der ganzen Anlage.
namen_raten() {
	{
		hostname -f 2>/dev/null || true
		hostname 2>/dev/null || true
		hostname -s 2>/dev/null | sed 's/$/.local/' || true
		# Bruecken von Docker, libvirt und Konsorten sind keine Adressen, unter
		# denen jemand den Relay anspricht - und der erste Name landet im CN.
		ip -o -4 addr show scope global 2>/dev/null |
			awk '$2 !~ /^(docker|br-|virbr|veth|tun|tap|zt|tailscale)/ {split($4,a,"/"); print a[1]}' || true
	} | grep -Ev '^(localhost.*|)$' | awk '!gesehen[$0]++' | tr '\n' ' '
}

# Vorhanden - oder im Probelauf das, was dieser Lauf ausstellen wuerde.
NEU=""
vorhanden() {
	if [ -f "$1" ]; then return 0; fi
	case " $NEU " in *" $(basename "$1") "*) return 0 ;; esac
	return 1
}

# Ausstellen, wortgleich zu scripts/schleuse-pki.sh. Wer dort etwas an den
# Erweiterungen aendert, aendert es hier mit.
pki_verz() {
	# Ein vorhandenes Verzeichnis bleibt, wie es ist - sonst wuerde ein Lauf aus
	# dem Quellbaum heraus die dortige pki-Ablage dem Betreiber wegnehmen.
	if [ -d "$PKI" ]; then return 0; fi
	tu install -d -m700 "$PKI"
}
pki_init() {
	if [ "$PROBE" = ja ]; then
		zeile "[probe] wuerde anlegen: $PKI/ca.crt und ca.key (gueltig $CA_DAYS Tage)"
		NEU="$NEU ca.crt ca.key"
		return 0
	fi
	pki_verz
	openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca.key"
	chmod 600 "$PKI/ca.key"
	openssl req -new -x509 -key "$PKI/ca.key" -sha256 -days "$CA_DAYS" \
		-subj "/CN=schleuse-ca" -out "$PKI/ca.crt" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
		-addext "keyUsage=critical,keyCertSign,cRLSign"
	zeile "Wurzel-CA angelegt: $PKI/ca.crt (gueltig $CA_DAYS Tage)"
}
# blatt <name> <CN> <tage> <erweiterungen>
pki_blatt() {
	bl_n=$1; bl_cn=$2; bl_t=$3; bl_e=$4
	if [ "$PROBE" = ja ]; then
		zeile "[probe] wuerde ausstellen: $PKI/$bl_n.crt (CN=$bl_cn, $bl_t Tage)"
		NEU="$NEU $bl_n.crt $bl_n.key"
		return 0
	fi
	pki_verz
	openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/$bl_n.key"
	chmod 600 "$PKI/$bl_n.key"
	openssl req -new -key "$PKI/$bl_n.key" -subj "/CN=$bl_cn" -out "$PKI/$bl_n.csr"
	printf '%s\n' "$bl_e" > "$PKI/$bl_n.ext"
	openssl x509 -req -in "$PKI/$bl_n.csr" \
		-CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
		-out "$PKI/$bl_n.crt" -days "$bl_t" -sha256 \
		-extfile "$PKI/$bl_n.ext" 2>/dev/null
	rm -f "$PKI/$bl_n.csr" "$PKI/$bl_n.ext"
	zeile "ausgestellt: $PKI/$bl_n.crt   CN=$bl_cn   gueltig $bl_t Tage"
}
pki_device_ca() {
	pki_blatt device-ca schleuse-device-ca "$CA_DAYS" \
"basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign"
}
pki_relay() {
	san=""
	for n in $1; do
		if echo "$n" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
			san="$san,IP:$n"
		else
			san="$san,DNS:$n"
		fi
	done
	set -- $1
	pki_blatt relay "$1" "$RELAY_DAYS" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${san#,}"
}
pki_client() {
	echo "$1" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || die "unbrauchbarer Name '$1' (erlaubt: A-Z a-z 0-9 . _ -)"
	pki_blatt "client-$1" "client:$1" "$CLIENT_DAYS" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth"
}

# Darf hier ausgestellt werden?
CA_HIER=nein
darf_ausstellen() {
	if [ "$CA_HIER" = ja ]; then return 0; fi
	if [ "$PKINEU" = ja ]; then CA_HIER=ja; return 0; fi
	# Kommt das Skript aus einer Pipe ('curl ... | sh'), ist die Standardeingabe
	# das Skript selbst - gefragt wird dann am Terminal.
	if [ -t 0 ]; then
		EIN=/dev/stdin
	elif [ -c /dev/tty ]; then
		EIN=/dev/tty
	else
		return 1
	fi
	printf '\n'
	printf '  Auf dieser Maschine soll eine eigene CA entstehen (%s).\n' "$PKI"
	printf '  Wer deren Schluessel hat, kann Bediener-Zugaenge zu allen Geraeten\n'
	printf '  ausstellen. Auf dem Relay - der Maschine im Internet - ist er darum\n'
	printf '  schlechter aufgehoben als auf einem Rechner ohne offene Ports.\n'
	printf '  Am Ende sage ich, wie er hier wieder verschwindet.\n\n'
	printf '  Fortfahren? [j/N] '
	read -r antwort < "$EIN" || antwort=n
	case "$antwort" in j|J|ja|y|Y|yes) CA_HIER=ja; return 0 ;; esac
	return 1
}

GERATEN=nein
if [ -z "$NAMEN" ]; then NAMEN=$(namen_raten); GERATEN=ja; fi
NAMEN=$(echo $NAMEN)          # Leerraum glaetten
ERSTER=$(echo $NAMEN | awk '{print $1}')
[ -n "$ERSTER" ] || die "kein Name fuer das Relay-Zertifikat - mit -name <name> angeben"
# Geraete tragen diesen Namen dauerhaft in ihrer Konfiguration. Eine geratene
# LAN-Adresse oder ein mDNS-Name taugt dafuer nur im Labor.
if [ "$GERATEN" = ja ]; then
	TAUGT=nein
	case "$ERSTER" in
		*.local|*.localdomain) ;;       # nur im eigenen Netz aufloesbar
		*.*) TAUGT=ja ;;                # sieht nach einem Namen aus dem DNS aus
	esac
	if echo "$ERSTER" | grep -Eq '^[0-9.]+$'; then TAUGT=nein; fi
	if [ "$TAUGT" = nein ]; then
		warn "geraten: '$ERSTER'. Genau diesen Namen tragen die Geraete dauerhaft in
           ihre Konfiguration - er sollte ueberall aufloesbar sein und bleiben.
           Besser: -name <name aus dem DNS>"
	fi
fi

# 1. Wurzel-CA
if [ ! -f "$Q_CERT/ca.crt" ]; then
	zeile "keine CA in $Q_CERT"
	darf_ausstellen || die "ohne CA geht es nicht weiter. Entweder ca.crt, relay.crt und
             relay.key neben dieses Skript legen (ausgestellt auf einem sicheren
             Rechner mit scripts/schleuse-pki.sh), oder hier erzeugen lassen:
             $0 -pki-neu -name <name>"
	pki_init
	Q_CERT=$PKI
fi
CA_KEY=""
if vorhanden "$Q_CERT/ca.key"; then CA_KEY="$Q_CERT/ca.key"; PKI=$Q_CERT; fi
if [ -f "$Q_CERT/ca.crt" ]; then
	zeile "Wurzel-CA: $Q_CERT/ca.crt (CN=$(cn_von "$Q_CERT/ca.crt"), bis $(openssl x509 -in "$Q_CERT/ca.crt" -noout -enddate | cut -d= -f2))"
fi

# 2. Relay-Zertifikat
if [ ! -f "$Q_CERT/relay.crt" ]; then
	[ -n "$CA_KEY" ] || die "relay.crt fehlt in $Q_CERT, und ohne ca.key kann ich keines ausstellen.
             Auf dem Rechner mit der CA: ./scripts/schleuse-pki.sh relay $ERSTER"
	darf_ausstellen || die "relay.crt fehlt. Mit -pki-neu wird es hier ausgestellt."
	zeile "Relay-Zertifikat fuer: $NAMEN"
	pki_relay "$NAMEN"
fi
if [ -f "$Q_CERT/relay.crt" ]; then
	paar_passt "$Q_CERT/relay.crt" "$Q_CERT/relay.key" ||
		die "relay.key gehoert nicht zu relay.crt"
	openssl verify -CAfile "$Q_CERT/ca.crt" "$Q_CERT/relay.crt" >/dev/null 2>&1 ||
		die "relay.crt ist nicht von dieser CA unterschrieben - Agenten und Bediener
             wuerden den Relay ablehnen"
	openssl x509 -in "$Q_CERT/relay.crt" -noout -checkend 0 >/dev/null ||
		die "relay.crt ist abgelaufen ($(openssl x509 -in "$Q_CERT/relay.crt" -noout -enddate | cut -d= -f2))"
	openssl x509 -in "$Q_CERT/relay.crt" -noout -checkend 2592000 >/dev/null ||
		warn "relay.crt laeuft in weniger als 30 Tagen ab"
	zeile "Relay-Zertifikat: CN=$(cn_von "$Q_CERT/relay.crt"), bis $(openssl x509 -in "$Q_CERT/relay.crt" -noout -enddate | cut -d= -f2)"
	zeile "gilt fuer: $(openssl x509 -in "$Q_CERT/relay.crt" -noout -ext subjectAltName 2>/dev/null | sed -n '2p' | sed 's/^ *//;s/DNS://g;s/IP Address://g')"
	# Agenten und Bediener pruefen den Namen, unter dem sie den Relay ansprechen.
	# Steht er nicht im Zertifikat, kommt keiner durch - und die Meldung, die sie
	# dann sehen, klingt nach einem Netzproblem.
	for n in $NAMEN; do
		openssl x509 -in "$Q_CERT/relay.crt" -noout -checkhost "$n" >/dev/null 2>&1 ||
			openssl x509 -in "$Q_CERT/relay.crt" -noout -checkip "$n" >/dev/null 2>&1 ||
			warn "relay.crt gilt nicht fuer '$n' - wer den Relay so anspricht, kommt nicht durch.
           Neu ausstellen: rm $Q_CERT/relay.crt $Q_CERT/relay.key && $0 -name $n ..."
	done
fi

# 3. Zwischen-CA fuer die Selbstanmeldung
if [ "$ENROLL" = ja ] && [ ! -f "$Q_CERT/device-ca.crt" ] && [ -n "$CA_KEY" ] && darf_ausstellen; then
	pki_device_ca
fi
if [ "$ENROLL" = ja ] && vorhanden "$Q_CERT/device-ca.crt"; then
	if [ -f "$Q_CERT/device-ca.crt" ]; then
		[ -f "$Q_CERT/device-ca.key" ] ||
			die "device-ca.crt liegt in $Q_CERT, device-ca.key fehlt. Ohne den Schluessel
             kann der Relay keine Geraete ausstellen - beide gehoeren hierher."
		paar_passt "$Q_CERT/device-ca.crt" "$Q_CERT/device-ca.key" ||
			die "device-ca.key gehoert nicht zu device-ca.crt"
	fi
	zeile "Zwischen-CA device-ca.crt - die Selbstanmeldung wird eingerichtet"
else
	ENROLL=nein
	zeile "keine Zwischen-CA - ohne Selbstanmeldung"
fi

# 4. Bediener-Zertifikat auf Wunsch
if [ -n "$CLIENT" ]; then
	[ -n "$CA_KEY" ] || die "-client braucht den Schluessel der Wurzel-CA. Der liegt nicht hier -
             und das ist richtig so. Auf dem Rechner mit der CA:
             ./scripts/schleuse-pki.sh client $CLIENT"
	if [ -f "$PKI/client-$CLIENT.crt" ]; then die "$PKI/client-$CLIENT.crt gibt es schon"; fi
	pki_client "$CLIENT"
fi

# Der CA-Pin, mit dem sich ein Geraet selbst anmeldet: 10 Byte aus SHA-256 ueber
# das Zertifikat, Base32 in Vierergruppen - dasselbe, was der Relay beim Start
# ins Protokoll schreibt. Kein Geheimnis, er darf im Handbuch stehen.
PIN=""
if command -v base32 >/dev/null && [ -f "$Q_CERT/ca.crt" ]; then
	PIN=$(openssl x509 -in "$Q_CERT/ca.crt" -outform DER 2>/dev/null |
		openssl dgst -sha256 -binary | head -c 10 | base32 | tr -d '=' |
		sed 's/..../&-/g; s/-$//')
	if [ -n "$PIN" ]; then zeile "CA-Pin fuer 'schleuse enroll': $PIN"; fi
fi

# --- Belegte Ports -----------------------------------------------------------
if command -v ss >/dev/null; then
	for p in $PORT $WEBPORT; do
		if [ "$p" = aus ]; then continue; fi
		belegt=$(ss -ltnpH "sport = :$p" 2>/dev/null | head -1) || belegt=""
		case "$belegt" in
			'') ;;
			*schleuse*) ;;
			*) warn "Port $p ist belegt: $(echo "$belegt" | awk '{print $NF}')" ;;
		esac
	done
fi

# --- Einrichten --------------------------------------------------------------
sag "Einrichten"
if [ "$PROBE" = ja ]; then
	zeile "Probelauf - ab hier wird nichts geaendert."
fi

# Benutzer
if id schleuse >/dev/null 2>&1; then
	zeile "Benutzer schleuse gibt es bereits"
else
	# useradd liegt in /usr/sbin; das steht nicht in jedem PATH.
	USERADD=$(command -v useradd || echo /usr/sbin/useradd)
	if [ ! -x "$USERADD" ]; then
		if [ "$PROBE" = ja ]; then
			warn "useradd nicht gefunden - als root sollte es da sein"
		else
			die "useradd fehlt - Benutzer 'schleuse' von Hand anlegen"
		fi
	fi
	tu "$USERADD" --system --no-create-home --shell /usr/sbin/nologin schleuse
	getan "Benutzer schleuse angelegt"
fi

# Binary. Erst daneben, dann umbenennen: ein laufender Dienst haelt die alte
# Datei offen, ueberschreiben ergaebe 'Text file busy'. Umbenennen nicht.
tu install -m755 "$BIN" /usr/local/bin/.schleuse.neu
tu mv -f /usr/local/bin/.schleuse.neu /usr/local/bin/schleuse
getan "/usr/local/bin/schleuse ($FASSUNG)"

# Zertifikate
tu install -d -m750 -o root -g schleuse /etc/schleuse
tu install -m640 -o root -g schleuse "$Q_CERT/ca.crt" "$Q_CERT/relay.crt" "$Q_CERT/relay.key" /etc/schleuse/
getan "/etc/schleuse/{ca,relay}.crt, relay.key (0640 root:schleuse)"
if [ "$ENROLL" = ja ]; then
	tu install -m640 -o root -g schleuse "$Q_CERT/device-ca.crt" "$Q_CERT/device-ca.key" /etc/schleuse/
	getan "/etc/schleuse/device-ca.crt, device-ca.key"
fi
tu install -d -m700 -o schleuse -g schleuse /var/lib/schleuse

# Konfiguration - eine vorhandene bleibt, wie sie ist.
if [ -f /etc/schleuse/relay.json ]; then
	zeile "/etc/schleuse/relay.json ist vorhanden und bleibt unveraendert"
else
	TMPJ=$(mktemp)
	{
		echo '{'
		echo "  \"listen\": \"0.0.0.0:$PORT\","
		echo '  "ca":   "/etc/schleuse/ca.crt",'
		echo '  "cert": "/etc/schleuse/relay.crt",'
		echo '  "key":  "/etc/schleuse/relay.key",'
		echo ''
		echo '  // Wird von der Weboberflaeche geschrieben - darum unter /var/lib.'
		echo '  "acl": "/var/lib/schleuse/acl.json",'
		echo ''
		echo '  // Ohne Eintrag in der Geraeteliste darf sich niemand anmelden.'
		echo '  "allow_unlisted_devices": false,'
		if [ "$ENROLL" = ja ]; then
			echo ''
			echo '  "enrollment": {'
			echo '    "ca":    "/etc/schleuse/device-ca.crt",'
			echo '    "key":   "/etc/schleuse/device-ca.key",'
			echo '    "queue": "/var/lib/schleuse/pending.json"'
			echo '  },'
		fi
		if [ "$WEBPORT" != aus ]; then
			echo ''
			echo '  // Verwaltung im Browser. Ohne diesen Abschnitt laeuft keine.'
			echo '  "web": {'
			echo "    \"listen\": \"0.0.0.0:$WEBPORT\","
			echo '    "users":  "/var/lib/schleuse/users.json",'
			echo '    "state":  "/var/lib/schleuse/api.json",'
			echo "    \"issuer\": \"schleuse $ERSTER\""
			echo '  },'
		fi
		echo ''
		echo '  "max_streams_per_device": 64,'
		echo '  "max_streams_per_client": 16'
		echo '}'
	} > "$TMPJ"
	tu install -m640 -o root -g schleuse "$TMPJ" /etc/schleuse/relay.json
	rm -f "$TMPJ"
	getan "/etc/schleuse/relay.json angelegt (Tunnel $PORT, Weboberflaeche $WEBPORT)"
fi

# systemd-Einheit. Liegt die gepflegte Fassung daneben, gilt die; sonst die
# eingebaute Abschrift von deploy/schleuse-relay.service.
TMPU=$(mktemp)
VORLAGE=""
for k in "$Q_BIN/schleuse-relay.service" "$SELBST/schleuse-relay.service" "$SELBST/../deploy/schleuse-relay.service"; do
	if [ -f "$k" ]; then VORLAGE=$k; break; fi
done
if [ -n "$VORLAGE" ]; then
	cp "$VORLAGE" "$TMPU"
	zeile "Einheit aus $VORLAGE"
else
	cat > "$TMPU" <<'EINHEIT'
# Vermittlungsdienst auf dem Server im Internet.
# Abschrift von deploy/schleuse-relay.service, angelegt von install-relay.sh.

[Unit]
Description=schleuse relay - Vermittlung zwischen Geraeten und Bedienern
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=exec
ExecStart=/usr/local/bin/schleuse relay -c /etc/schleuse/relay.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
User=schleuse
Group=schleuse
UMask=0077

# Fuer Port 443 und den Port der Weboberflaeche unter 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# --- Haertung ---------------------------------------------------------------
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @obsolete
ReadOnlyPaths=/etc/schleuse
StateDirectory=schleuse
StateDirectoryMode=0700

LimitNOFILE=65536
MemoryMax=512M
TasksMax=4096

[Install]
WantedBy=multi-user.target
EINHEIT
	zeile "Einheit aus der eingebauten Vorlage"
fi
if [ "$MODUS" = singlefile ]; then
	sed -i 's|^MemoryDenyWriteExecute=yes|# Kein Native AOT: dieses Binary bringt einen JIT mit und braucht\n# beschreibbaren ausfuehrbaren Speicher.\n# MemoryDenyWriteExecute=yes|' "$TMPU"
	# Das Bundle entpackt seine nativen Bibliotheken; unter ProtectSystem=strict
	# ist dafuer nur das Zustandsverzeichnis beschreibbar.
	sed -i 's|^StateDirectory=schleuse|StateDirectory=schleuse\nEnvironment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/schleuse/.bundle|' "$TMPU"
	zeile "Haertung angepasst: MemoryDenyWriteExecute aus (JIT-Binary)"
fi
tu install -m644 "$TMPU" "/etc/systemd/system/$DIENST.service"
rm -f "$TMPU"

if [ "$PROBE" = ja ]; then
	sag "Probelauf beendet"
	zeile "Nichts geaendert. Ohne -n wuerde der Dienst jetzt eingerichtet und gestartet."
	exit 0
fi

# --- Starten -----------------------------------------------------------------
sag "Starten"
SEIT=$(date '+%Y-%m-%d %H:%M:%S')
systemctl daemon-reload
systemctl enable "$DIENST" >/dev/null 2>&1 || true
systemctl restart "$DIENST" || true

n=0
while [ $n -lt 15 ]; do
	zustand=$(systemctl is-active "$DIENST" || true)
	[ "$zustand" = activating ] || break
	n=$((n + 1)); sleep 1
done
zeile "Zustand: $zustand"

PROTOKOLL=$(journalctl -u "$DIENST" --since "$SEIT" --no-pager 2>/dev/null || true)

if [ "$zustand" != active ]; then
	sag "Der Dienst laeuft nicht"
	echo "$PROTOKOLL" | tail -30 | sed 's/^/  /'
	echo
	case "$PROTOKOLL" in
		*"Operation not permitted"*|*SIGSYS*|*"Trace/breakpoint"*)
			warn "sieht nach der Haertung aus. Ist das Binary doch ein Bundle mit JIT?
           Dann: $0 -modus singlefile" ;;
		*"Address already in use"*)
			warn "der Port ist belegt. Wer ihn haelt: ss -ltnp | grep -E ':($PORT|$WEBPORT)'" ;;
		*"Permission denied"*)
			warn "Rechte an /etc/schleuse pruefen: ls -l /etc/schleuse" ;;
	esac
	zeile "Vollstaendig: journalctl -u $DIENST -n 100 --no-pager"
	exit 1
fi

echo "$PROTOKOLL" | grep -E 'relay|web' | tail -12 | sed 's/^/  /'

# --- Fertig ------------------------------------------------------------------
sag "Fertig"
[ "$WEBPORT" = aus ] || zeile "Weboberflaeche:  https://$ERSTER:$WEBPORT/setup"
zeile "Tunnelport:      $ERSTER:$PORT"
if [ -n "$PIN" ]; then zeile "CA-Pin:          $PIN"; fi

KENNWORT=$(echo "$PROTOKOLL" | grep -o 'Kennwort: [^ ]*' | tail -1 | cut -d' ' -f2 || true)
if [ -n "$KENNWORT" ]; then
	zeile "Einrichtungskennwort: $KENNWORT   (gilt, bis der erste Verwalter angelegt ist)"
fi

# Die Rundenzahl der Passwortableitung haengt an der Maschine. Der Relay misst
# sie beim Start; dauert eine Anmeldung zu lange, ist die Vorgabe fuer dieses
# Blech zu hoch gegriffen.
MESSUNG=$(echo "$PROTOKOLL" | grep -o 'Passwortpruefung: [0-9]* ms bei [0-9]* Runden' | tail -1 || true)
if [ -n "$MESSUNG" ]; then
	ms=$(echo "$MESSUNG" | awk '{print $2}')
	runden=$(echo "$MESSUNG" | awk '{print $5}')
	if [ "$ms" -gt 800 ]; then
		# Erst teilen, dann malnehmen - sonst laeuft die Zwischenzahl auf
		# kleinen Shells ueber.
		vorschlag=$(( runden / ms * 500 / 50000 * 50000 ))
		if [ "$vorschlag" -lt 50000 ]; then vorschlag=50000; fi
		echo
		warn "eine Anmeldung dauert hier $ms ms ($runden Runden). Das bremst jeden
           Anmeldeversuch - auch den eigenen. Passend waeren rund $vorschlag Runden:
           in /etc/schleuse/relay.json unter \"web\" eintragen
               \"password_iterations\": $vorschlag,
           danach: systemctl restart $DIENST"
	fi
fi

if [ "$ENROLL" = ja ] && [ -n "$PIN" ]; then
	cat <<EOF

  So meldet sich ein neues Geraet an:

      schleuse enroll -relay $ERSTER:$PORT -ca-pin $PIN \\
               -service ssh=127.0.0.1:22

  Der Antrag landet in der Weboberflaeche und wartet dort auf Freigabe.
EOF
fi

if [ "$CA_HIER" = ja ] && [ -f "$PKI/ca.key" ]; then
	cat <<EOF

  ${rot}Noch offen: der Schluessel der Wurzel-CA liegt auf dieser Maschine.${aus}

      $PKI/ca.key

  Wer ihn hat, kann sich einen Bediener-Zugang zu allen Geraeten ausstellen -
  und diese Maschine hat offene Ports im Internet. Hol ihn von einem sicheren
  Rechner ab und loesche ihn hier:

      scp $(id -un)@$ERSTER:$PKI/ca.key  ./pki/
      scp $(id -un)@$ERSTER:$PKI/ca.crt  ./pki/
      ssh $(id -un)@$ERSTER 'sudo shred -u $PKI/ca.key'

  Auf dem Relay bleiben nur ca.crt und die Zwischen-CA. Die kann ausschliesslich
  Geraete ausstellen; Bediener-Zertifikate nimmt der Relay nur an, wenn die
  Wurzel-CA sie unmittelbar unterschrieben hat.
EOF
fi
if [ -n "$CLIENT" ]; then
	cat <<EOF

  Bediener-Zertifikat fuer '$CLIENT': $PKI/client-$CLIENT.crt (und .key)
  Auf den Arbeitsplatz nach ~/.config/schleuse/, und '$CLIENT' in der
  Weboberflaeche unter Zugriffsregeln eintragen.
EOF
fi

cat <<EOF

  Zustand:    systemctl status $DIENST
  Protokoll:  journalctl -u $DIENST -f
  Nach dem Aendern von relay.json: systemctl restart $DIENST
EOF
