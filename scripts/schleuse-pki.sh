#!/bin/sh
# schleuse-pki.sh - private CA fuer schleuse
#
# Die Identitaet jeder Partei steckt im CN ihres Zertifikats:
#   relay      CN = <hostname>            (zusaetzlich als SAN)
#   Geraet     CN = device:<id>
#   Bediener   CN = client:<name>
#
# Verwendung:
#   ./schleuse-pki.sh init                 einmalig: Wurzel-CA anlegen
#   ./schleuse-pki.sh device-ca            Zwischen-CA fuer die Selbstanmeldung
#   ./schleuse-pki.sh relay tunnel.example.com [weitere-namen ...]
#   ./schleuse-pki.sh device werk1-hmi
#   ./schleuse-pki.sh client db
#   ./schleuse-pki.sh list
#
# Ablageort ueber $SCHLEUSE_PKI steuerbar (Vorgabe: ./pki).
#
# Der Schluessel der Wurzel-CA gehoert NICHT auf den Relay-Server. Nur die
# Zwischen-CA (device-ca) darf dorthin - sie kann ausschliesslich Geraete
# ausstellen, weil der Relay Bediener-Zertifikate nur akzeptiert, wenn die
# Wurzel-CA sie unmittelbar signiert hat.

set -eu

PKI="${SCHLEUSE_PKI:-./pki}"
CA_DAYS="${CA_DAYS:-3650}"
DEVICE_DAYS="${DEVICE_DAYS:-825}"
CLIENT_DAYS="${CLIENT_DAYS:-365}"
RELAY_DAYS="${RELAY_DAYS:-825}"

die() { echo "schleuse-pki: $*" >&2; exit 1; }

need_ca() {
	[ -f "$PKI/ca.key" ] || die "keine CA in $PKI - zuerst '$0 init' ausfuehren"
}

sane_name() {
	echo "$1" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || die "unbrauchbarer Name '$1' (erlaubt: A-Z a-z 0-9 . _ -)"
}

# leaf <dateiname> <CN> <tage> <extensions>
leaf() {
	lf_name="$1"; lf_cn="$2"; lf_days="$3"; lf_ext="$4"
	[ -f "$PKI/$lf_name.crt" ] && die "$PKI/$lf_name.crt existiert bereits - erst loeschen, wenn wirklich neu ausgestellt werden soll"

	openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/$lf_name.key"
	chmod 600 "$PKI/$lf_name.key"
	openssl req -new -key "$PKI/$lf_name.key" -subj "/CN=$lf_cn" -out "$PKI/$lf_name.csr"

	printf '%s\n' "$lf_ext" > "$PKI/$lf_name.ext"
	openssl x509 -req -in "$PKI/$lf_name.csr" \
		-CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
		-out "$PKI/$lf_name.crt" -days "$lf_days" -sha256 \
		-extfile "$PKI/$lf_name.ext" 2>/dev/null
	rm -f "$PKI/$lf_name.csr" "$PKI/$lf_name.ext"

	echo "$PKI/$lf_name.crt   CN=$lf_cn   gueltig $lf_days Tage"
}

cmd="${1:-}"
case "$cmd" in
init)
	mkdir -p "$PKI"
	chmod 700 "$PKI"
	[ -f "$PKI/ca.crt" ] && die "CA existiert bereits in $PKI"
	openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca.key"
	chmod 600 "$PKI/ca.key"
	openssl req -new -x509 -key "$PKI/ca.key" -sha256 -days "$CA_DAYS" \
		-subj "/CN=schleuse-ca" -out "$PKI/ca.crt" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
		-addext "keyUsage=critical,keyCertSign,cRLSign"
	echo "CA angelegt: $PKI/ca.crt (gueltig $CA_DAYS Tage)"
	echo "ACHTUNG: $PKI/ca.key niemals auf Relay oder Geraet kopieren."
	;;

device-ca)
	need_ca
	[ -f "$PKI/device-ca.crt" ] && die "Zwischen-CA existiert bereits in $PKI"
	openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/device-ca.key"
	chmod 600 "$PKI/device-ca.key"
	openssl req -new -key "$PKI/device-ca.key" -subj "/CN=schleuse-device-ca" -out "$PKI/device-ca.csr"
	printf '%s\n' \
"basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign" > "$PKI/device-ca.ext"
	openssl x509 -req -in "$PKI/device-ca.csr" \
		-CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
		-out "$PKI/device-ca.crt" -days "$CA_DAYS" -sha256 \
		-extfile "$PKI/device-ca.ext" 2>/dev/null
	rm -f "$PKI/device-ca.csr" "$PKI/device-ca.ext"
	echo "Zwischen-CA angelegt: $PKI/device-ca.crt"
	echo "Auf den Relay: device-ca.crt device-ca.key (nur diese, nie ca.key)"
	echo "Sie kann nur Geraete ausstellen - der Relay nimmt Bediener-Zertifikate"
	echo "nur an, wenn die Wurzel-CA sie unmittelbar signiert hat."
	;;

relay)
	need_ca
	shift
	[ $# -ge 1 ] || die "Verwendung: $0 relay <hostname> [weitere-namen ...]"
	# Mehrere Namen sind kein Luxus: Agenten und Bediener pruefen den Namen,
	# unter dem sie den Relay ansprechen. Steht spaeter ein DNS-Eintrag neben
	# dem mDNS-Namen, muesste sonst alles neu ausgestellt werden.
	san=""
	for n in "$@"; do
		if echo "$n" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
			san="$san,IP:$n"
		else
			san="$san,DNS:$n"
		fi
	done
	san="${san#,}"
	leaf "relay" "$1" "$RELAY_DAYS" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san"
	echo "Auf den Relay-Server: ca.crt relay.crt relay.key"
	;;

device)
	need_ca
	id="${2:-}"; [ -n "$id" ] || die "Verwendung: $0 device <id>"
	sane_name "$id"
	leaf "device-$id" "device:$id" "$DEVICE_DAYS" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth"
	echo "Auf das Geraet: ca.crt device-$id.crt device-$id.key"
	echo
	echo "Auf dem Relay in acl.json unter \"devices\" eintragen, sonst wird die"
	echo "Anmeldung abgelehnt (falls dort eine Geraeteliste gefuehrt wird):"
	echo "    \"$id\": { \"note\": \"\" }"
	echo "danach: systemctl reload schleuse-relay"
	;;

client)
	need_ca
	name="${2:-}"; [ -n "$name" ] || die "Verwendung: $0 client <name>"
	sane_name "$name"
	leaf "client-$name" "client:$name" "$CLIENT_DAYS" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth"
	echo "Nicht vergessen: '$name' in acl.json eintragen."
	;;

list)
	need_ca
	for f in "$PKI"/*.crt; do
		[ -e "$f" ] || continue
		cn=$(openssl x509 -in "$f" -noout -subject -nameopt multiline 2>/dev/null | sed -n 's/ *commonName *= *//p')
		end=$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)
		printf '%-28s %-24s bis %s\n' "$(basename "$f")" "$cn" "$end"
	done
	;;

*)
	sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
