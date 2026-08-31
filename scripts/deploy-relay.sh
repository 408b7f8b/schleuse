#!/bin/bash
# deploy-relay.sh <benutzer@host> [hostname-fuer-zertifikat]
#
# Richtet den Relay auf einer entfernten Maschine ein. Alles, was der Vorgang
# anfasst, steht hier - nachlesbar, wiederholbar, und ohne dass jemand zwanzig
# Einzelbefehle von Hand tippt.
#
# Erwartet Schluessel-Anmeldung. Ist noch keine eingerichtet:
#     ssh-copy-id benutzer@host
#
# Der Schluessel der Wurzel-CA bleibt auf DIESEM Rechner. Auf die Zielmaschine
# gehen nur ca.crt, das Relay-Zertifikat samt Schluessel und - fuer die
# Selbstanmeldung - die Zwischen-CA.

set -eu
cd "$(dirname "$0")/.."

ZIEL="${1:-}"
[ -n "$ZIEL" ] || { echo "Aufruf: $0 <benutzer@host> [hostname-fuer-zertifikat]"; exit 1; }
HOST_CN="${2:-${ZIEL#*@}}"
PKI="${SCHLEUSE_PKI:-./pki}"
S="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new $ZIEL"

sag() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# --- Zielsystem erkunden -----------------------------------------------------
sag "Zielsystem"
$S 'echo "  Kernel:    $(uname -srm)"
    echo "  Userland:  $(dpkg --print-architecture 2>/dev/null || echo unbekannt)"
    echo "  System:    $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    echo "  Speicher:  $(free -m | awk "/^Spe|^Mem/ {print \$2\" MB\"}")"
    echo "  Kerne:     $(nproc)"
    echo "  systemd:   $(systemctl --version | head -1)"'

ARCH=$($S 'dpkg --print-architecture 2>/dev/null || uname -m')
case "$ARCH" in
	arm64|aarch64) RID=linux-arm64 ;;
	armhf|armv7l|armv6l) RID=linux-arm ;;
	amd64|x86_64) RID=linux-x64 ;;
	*) echo "unbekannte Architektur '$ARCH'"; exit 1 ;;
esac
echo "  -> passendes Binary: $RID"

[ -x "out/$RID/schleuse" ] || { echo "out/$RID/schleuse fehlt - './build.sh $RID' ausfuehren"; exit 1; }
MODUS=$(cat "out/$RID/BUILD-MODE" 2>/dev/null || echo unbekannt)
echo "  -> Betriebsart: $MODUS"

# --- Zertifikate -------------------------------------------------------------
sag "Zertifikate"
[ -f "$PKI/ca.crt" ] || { echo "keine CA in $PKI - './scripts/schleuse-pki.sh init' ausfuehren"; exit 1; }
if [ ! -f "$PKI/relay.crt" ]; then
	echo "  Relay-Zertifikat fuer '$HOST_CN' wird ausgestellt"
	SCHLEUSE_PKI="$PKI" ./scripts/schleuse-pki.sh relay "$HOST_CN" >/dev/null
fi
if ! openssl x509 -in "$PKI/relay.crt" -noout -checkhost "$HOST_CN" >/dev/null 2>&1; then
	echo "  ACHTUNG: das vorhandene Relay-Zertifikat gilt nicht fuer '$HOST_CN'."
	echo "           Agenten und Bediener pruefen den Namen - so kommt keiner durch."
	echo "           Zum Neuausstellen: rm $PKI/relay.crt $PKI/relay.key"
	exit 1
fi
echo "  Relay-Zertifikat gilt fuer '$HOST_CN'"
if [ -f "$PKI/device-ca.crt" ]; then
	echo "  Zwischen-CA vorhanden, Selbstanmeldung wird eingerichtet"
	MIT_ENROLL=ja
else
	echo "  keine Zwischen-CA - ohne Selbstanmeldung ('schleuse-pki.sh device-ca' waere noetig)"
	MIT_ENROLL=nein
fi

# --- Uebertragen -------------------------------------------------------------
sag "Uebertragen"
TMP=$($S 'mktemp -d')
scp -q "out/$RID/schleuse" "$PKI/ca.crt" "$PKI/relay.crt" "$PKI/relay.key" "$ZIEL:$TMP/"
[ "$MIT_ENROLL" = ja ] && scp -q "$PKI/device-ca.crt" "$PKI/device-ca.key" "$ZIEL:$TMP/"
# Die Einheit an die Betriebsart des Binarys anpassen. Ein Single-File-Bundle
# bringt den JIT mit und braucht beschreibbaren ausfuehrbaren Speicher; die
# Vorlage verbietet das, weil sie fuer Native AOT geschrieben ist.
if [ "$MODUS" = aot ]; then
	cp deploy/schleuse-relay.service /tmp/schleuse.service
else
	sed 's|^MemoryDenyWriteExecute=yes|# Kein Native AOT: dieses Binary bringt einen JIT mit und braucht\n# beschreibbaren ausfuehrbaren Speicher.\n# MemoryDenyWriteExecute=yes|' \
		deploy/schleuse-relay.service > /tmp/schleuse.service
	# Das Bundle entpackt seine nativen Bibliotheken; unter ProtectSystem=strict
	# ist dafuer nur das Zustandsverzeichnis beschreibbar.
	sed -i 's|^StateDirectory=schleuse|StateDirectory=schleuse\nEnvironment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/schleuse/.bundle|' /tmp/schleuse.service
	echo "  -> Haertung angepasst: MemoryDenyWriteExecute aus (JIT-Binary)"
fi
scp -q /tmp/schleuse.service "$ZIEL:$TMP/schleuse-relay.service"
rm -f /tmp/schleuse.service

# Konfiguration erst auf dem Ziel bauen, damit die Rundenzahl zur Maschine passt.
KERNE=$($S nproc)
cat > /tmp/schleuse-relay.json <<EOF
{
  "listen": "0.0.0.0:443",
  "ca":   "/etc/schleuse/ca.crt",
  "cert": "/etc/schleuse/relay.crt",
  "key":  "/etc/schleuse/relay.key",
  "acl":  "/var/lib/schleuse/acl.json",
  "allow_unlisted_devices": false,
$( [ "$MIT_ENROLL" = ja ] && cat <<'EOJ'
  "enrollment": {
    "ca":    "/etc/schleuse/device-ca.crt",
    "key":   "/etc/schleuse/device-ca.key",
    "queue": "/var/lib/schleuse/pending.json"
  },
EOJ
)
  "web": {
    "listen": "0.0.0.0:8443",
    "users":  "/var/lib/schleuse/users.json",
    "state":  "/var/lib/schleuse/api.json",
    "issuer": "schleuse $HOST_CN"
  }
}
EOF
scp -q /tmp/schleuse-relay.json "$ZIEL:$TMP/relay.json"
rm -f /tmp/schleuse-relay.json
echo "  uebertragen nach $TMP"

# --- Einrichtungsskript auf dem Ziel ablegen ---------------------------------
sag "Einrichtung vorbereiten"
$S "cat > $TMP/install.sh" <<EOF
#!/bin/sh
# Wird als root ausgefuehrt. Alles, was Rechte braucht, steht hier - und nur hier.
set -eu
install -m755 "$TMP/schleuse" /usr/local/bin/schleuse
id schleuse >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin schleuse
install -d -m750 -o root -g schleuse /etc/schleuse
install -m640 -o root -g schleuse "$TMP/ca.crt" "$TMP/relay.crt" "$TMP/relay.key" /etc/schleuse/
[ -f "$TMP/device-ca.crt" ] && install -m640 -o root -g schleuse "$TMP/device-ca.crt" "$TMP/device-ca.key" /etc/schleuse/
[ -f /etc/schleuse/relay.json ] || install -m640 -o root -g schleuse "$TMP/relay.json" /etc/schleuse/relay.json
install -d -m700 -o schleuse -g schleuse /var/lib/schleuse
install -m644 "$TMP/schleuse-relay.service" /etc/systemd/system/schleuse-relay.service
systemctl daemon-reload
systemctl enable schleuse-relay >/dev/null 2>&1
systemctl restart schleuse-relay
sleep 5
# Ab hier nur noch berichten. Ohne das "|| true" bricht set -e bei einem
# Dienst ab, der noch "activating" meldet - und raeumt dann nicht mehr auf.
systemctl is-active schleuse-relay || true
journalctl -u schleuse-relay -n 30 --no-pager || true
rm -rf "$TMP"
echo "--- Einrichtung beendet ---"
EOF
$S "chmod +x $TMP/install.sh"

if $S 'sudo -n true' 2>/dev/null; then
	sag "Einrichten"
	$S "sudo sh $TMP/install.sh" 2>&1 | sed 's/^/  /'
else
	sag "Jetzt bist du dran"
	cat <<EOF
  sudo verlangt auf dem Ziel ein Passwort, das ich nicht habe und auch nicht
  haben sollte. Alles ist vorbereitet und liegt in $TMP.

  Bitte in einem Terminal ausfuehren:

      ssh -t $ZIEL 'sudo sh $TMP/install.sh'

  Das Skript ist vorher einsehbar mit:

      ssh $ZIEL 'cat $TMP/install.sh'

  Danach melde dich zurueck, dann pruefe ich den Zustand.
EOF
	exit 0
fi

sag "Fertig"
cat <<EOF
  Weboberflaeche:  https://$HOST_CN:8443/setup
  Tunnelport:      $HOST_CN:443
  Einrichtungskennwort und CA-Fingerabdruck stehen im Protokoll oben.
EOF
