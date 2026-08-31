#!/bin/bash
# securitytest.sh [pfad/zu/schleuse] - prueft das Abweisungsverhalten.
#
# Anders als selftest.sh geht es hier nicht um Funktion, sondern um die Frage,
# was schleuse ablehnt: abgelaufene und falsch ausgestellte Zertifikate, vertauschte
# Rollen, einen untergeschobenen Relay, Muell auf dem Port und den Entzug von
# Rechten waehrend einer laufenden Sitzung.

set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
SCHLEUSE="${1:-}"
# Die eigene Architektur zuerst: liegen mehrere Bauten nebeneinander, waehlte
# eine reine Reihenfolge sonst zum Beispiel arm64 auf einem x64-Rechner.
EIGEN="linux-$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/;s/armv7l/arm/')"
[ -n "$SCHLEUSE" ] || SCHLEUSE="$(ls "out/$EIGEN/schleuse" 2>/dev/null || ls out/*/schleuse 2>/dev/null | head -1)"
[ -n "$SCHLEUSE" ] || { echo "kein schleuse-Binary gefunden - zuerst ./build.sh"; exit 1; }
SCHLEUSE="$(readlink -f "$SCHLEUSE")"

W="$(mktemp -d)"; PIDS=()
pass=0; fail=0
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
            if [ -n "${KEEP:-}" ]; then echo "behalten: $W"; else rm -rf "$W"; fi; }
trap cleanup EXIT
ok()  { pass=$((pass+1)); printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  \033[31mFEHL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && echo "        $2"; }
# Erwartet, dass ein Kommando scheitert und dabei einen bestimmten Text nennt.
denied() { local name="$1" pat="$2"; shift 2
	local out; out="$("$@" 2>&1)"
	case "$out" in *"$pat"*) ok "$name";; *) bad "$name" "'$pat' fehlt in: $(echo "$out" | tail -1)";; esac
}

P_RELAY=27443; P_HTTP=27080; P_FWD=28080; P_FAKE=27444
for p in $P_RELAY $P_HTTP $P_FWD $P_FAKE; do
	ss -lntH "sport = :$p" 2>/dev/null | grep -q . && { echo "Port $p belegt"; exit 1; }
done

echo "schleuse-Sicherheitstest  ($SCHLEUSE)"
cd "$W"

# --- Zertifikatslandschaft --------------------------------------------------
P() { SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" "$@" >/dev/null; }
P init; P relay localhost; P device werk1; P client chef

# abgelaufene Zertifikate, je eines fuer Geraet und Bediener
printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n' > ext.cnf
vorher=$(date -u -d '400 days ago' +%Y%m%d%H%M%SZ)
gestern=$(date -u -d 'yesterday'   +%Y%m%d%H%M%SZ)
abgelaufen() {  # abgelaufen <dateiname> <CN>
	openssl ecparam -name prime256v1 -genkey -noout -out "pki/$1.key" 2>/dev/null
	openssl req -new -key "pki/$1.key" -subj "/CN=$2" -out "pki/$1.csr" 2>/dev/null
	openssl x509 -req -in "pki/$1.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial \
		-out "pki/$1.crt" -sha256 -extfile ext.cnf \
		-not_before "$vorher" -not_after "$gestern" 2>/dev/null
}
abgelaufen abgelaufen       "device:werk1"
abgelaufen abgelaufen-chef  "client:chef"

# Zertifikat mit SAN=localhost, aber nur clientAuth: der Versuch, sich als Relay auszugeben
openssl ecparam -name prime256v1 -genkey -noout -out pki/falscherelay.key 2>/dev/null
openssl req -new -key pki/falscherelay.key -subj "/CN=localhost" -out pki/falscherelay.csr 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:localhost\n' > ext2.cnf
openssl x509 -req -in pki/falscherelay.csr -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial \
	-out pki/falscherelay.crt -days 100 -sha256 -extfile ext2.cnf 2>/dev/null
ok "Zertifikate erzeugt (gueltig, abgelaufen, rollenfremd)"

cat > relay.json <<EOF
{ "listen": "127.0.0.1:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/relay.crt",
  "key": "pki/relay.key", "acl": "acl.json",
  "max_concurrent_handshakes": 2, "ping_interval_sec": 5, "ping_timeout_sec": 20 }
EOF
echo '{"devices":{"werk1":{"note":"Testgeraet"}},"clients":{"chef":{"devices":["*"],"services":["*"]}},"revoked":[]}' > acl.json
cat > agent.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/device-werk1.crt",
  "key": "pki/device-werk1.key", "services": { "http": "127.0.0.1:$P_HTTP" } }
EOF
mkc() { cat > "$1" <<EOF
{ "relay": "localhost:${3:-$P_RELAY}", "ca": "pki/ca.crt", "cert": "pki/$2.crt", "key": "pki/$2.key" }
EOF
}
mkc client-chef.json  client-chef
mkc client-alt.json   abgelaufen-chef
mkc agent-alsclient.json client-chef          # Bedienerzertifikat, aber Rolle Client -> ok
cat > agent-abgelaufen.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/abgelaufen.crt",
  "key": "pki/abgelaufen.key", "services": { "http": "127.0.0.1:$P_HTTP" } }
EOF
cat > agent-mitclientcert.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/client-chef.crt",
  "key": "pki/client-chef.key", "services": { "http": "127.0.0.1:$P_HTTP" } }
EOF
mkc client-alsgeraet.json device-werk1

mkdir www && echo "geheim" > www/i
python3 -m http.server $P_HTTP --bind 127.0.0.1 --directory www >/dev/null 2>&1 & PIDS+=($!)
"$SCHLEUSE" relay -c relay.json > relay.log 2>&1 & RELAY=$!; PIDS+=($RELAY)
sleep 1
"$SCHLEUSE" agent -c agent.json > agent.log 2>&1 & PIDS+=($!)
sleep 2

# --- Zertifikate ------------------------------------------------------------
echo "== Zertifikate =="
denied "abgelaufenes Geraetezertifikat wird abgewiesen" "abgelehnt" \
	timeout 20 "$SCHLEUSE" agent -c agent-abgelaufen.json
denied "abgelaufenes Bedienerzertifikat wird abgewiesen" "abgelehnt" \
	timeout 20 "$SCHLEUSE" client -c client-alt.json -device werk1 -service http -stdio

echo "== Rollen =="
denied "Bedienerzertifikat taugt nicht als Geraet" "keine Geraete-Identitaet" \
	timeout 20 "$SCHLEUSE" agent -c agent-mitclientcert.json
denied "Geraetezertifikat taugt nicht als Bediener" "keine Bediener-Identitaet" \
	timeout 20 "$SCHLEUSE" client -c client-alsgeraet.json -device werk1 -service http -stdio

# Die beiden Pruefungen oben laufen im eigenen Programm und liessen sich mit
# einem veraenderten Binary umgehen. Entscheidend ist, dass der Relay die
# Rollentrennung selbst durchsetzt - hier direkt auf Protokollebene geprueft.
cat > rolle.py <<'PY2'
import json, socket, ssl, sys
cert, key, hello, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain(cert, key)
try:
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                         server_hostname="localhost") as t:
        t.sendall(hello.encode() + b"\n")
        antwort = b""
        while not antwort.endswith(b"\n"):
            b = t.recv(1)
            if not b: break
            antwort += b
        print(antwort.decode(errors="replace").strip() or "VERBINDUNG-ZU")
except Exception as e:
    print("ABBRUCH:", e)
PY2
r=$(timeout 20 python3 rolle.py pki/device-werk1.crt pki/device-werk1.key \
      '{"v":1,"role":"client","device":"werk1","service":"http"}' $P_RELAY)
case "$r" in *'"ok":false'*|*ABBRUCH*|*VERBINDUNG-ZU*) ok "Relay weist Geraet in der Rolle Bediener ab";;
  *) bad "Relay weist Geraet in der Rolle Bediener ab" "Antwort: $r";; esac
r=$(timeout 20 python3 rolle.py pki/client-chef.crt pki/client-chef.key \
      '{"v":1,"role":"agent","services":["http"]}' $P_RELAY)
case "$r" in *'"ok":false'*|*ABBRUCH*|*VERBINDUNG-ZU*) ok "Relay weist Bediener in der Rolle Geraet ab";;
  *) bad "Relay weist Bediener in der Rolle Geraet ab" "Antwort: $r";; esac
r=$(timeout 20 python3 rolle.py pki/device-werk1.crt pki/device-werk1.key \
      '{"v":1,"role":"agent-data","stream":"00000000000000000000000000000000"}' $P_RELAY)
case "$r" in *'"ok":false'*|*ABBRUCH*|*VERBINDUNG-ZU*) ok "geratene Stream-Id wird abgewiesen";;
  *) bad "geratene Stream-Id wird abgewiesen" "Antwort: $r";; esac

echo "== TLS-Vorgaben =="
cat > tlsprobe.py <<'PY2'
import socket, ssl, sys
modus, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
if modus == "tls12":
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("pki/client-chef.crt", "pki/client-chef.key")
# modus == "nocert": bewusst ohne Client-Zertifikat
try:
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=8),
                         server_hostname="localhost") as t:
        t.sendall(b'{"v":1,"role":"client","device":"werk1","service":"http"}\n')
        print("DURCH:", t.recv(200))
except Exception as e:
    print("ABGEWIESEN:", type(e).__name__)
PY2
r=$(timeout 20 python3 tlsprobe.py tls12 $P_RELAY)
case "$r" in ABGEWIESEN*) ok "TLS 1.2 wird nicht angenommen";; *) bad "TLS 1.2 wird nicht angenommen" "$r";; esac
r=$(timeout 20 python3 tlsprobe.py nocert $P_RELAY)
case "$r" in ABGEWIESEN*|*"DURCH: b''"*) ok "Verbindung ohne Client-Zertifikat wird abgewiesen";;
  *) bad "Verbindung ohne Client-Zertifikat wird abgewiesen" "$r";; esac

# --- Untergeschobener Relay -------------------------------------------------
echo "== Untergeschobener Relay =="
cat > falscherelay.py <<PY
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("pki/falscherelay.crt", "pki/falscherelay.key")
ctx.verify_mode = ssl.CERT_NONE
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $P_FAKE)); s.listen(4)
while True:
    try:
        c, _ = s.accept()
        with ctx.wrap_socket(c, server_side=True) as t:
            t.recv(4096); t.sendall(b'{"ok":true}\n')
    except Exception:
        pass
PY
python3 falscherelay.py >/dev/null 2>&1 & PIDS+=($!)
sleep 1
cat > agent-gegen-falschen.json <<EOF
{ "relay": "localhost:$P_FAKE", "ca": "pki/ca.crt", "cert": "pki/device-werk1.crt",
  "key": "pki/device-werk1.key", "services": { "http": "127.0.0.1:$P_HTTP" },
  "reconnect_min_sec": 1, "reconnect_max_sec": 1 }
EOF
out=$(timeout 12 "$SCHLEUSE" agent -c agent-gegen-falschen.json 2>&1)
case "$out" in
  *angemeldet*) bad "Relay mit rollenfremdem Zertifikat wird abgewiesen" "Agent hat sich angemeldet!";;
  *) ok "Relay mit rollenfremdem Zertifikat wird abgewiesen";;
esac

# --- Muell auf dem Port -----------------------------------------------------
echo "== Robustheit des Relay-Ports =="
python3 - <<PY >/dev/null 2>&1
import socket
for payload in [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"\x00"*4096, b"\x16\x03\x01\xff\xff"+b"A"*2000, b""]:
    try:
        s = socket.create_connection(("127.0.0.1", $P_RELAY), timeout=5)
        s.sendall(payload); s.settimeout(3)
        try: s.recv(100)
        except Exception: pass
        s.close()
    except Exception: pass
for _ in range(50):                       # halboffene Verbindungen
    try: socket.create_connection(("127.0.0.1", $P_RELAY), timeout=5)
    except Exception: pass
PY
sleep 2
if kill -0 $RELAY 2>/dev/null; then ok "Relay ueberlebt Muell und halboffene Verbindungen"
else bad "Relay ueberlebt Muell und halboffene Verbindungen" "Prozess ist weg"; fi

# --- Drossel darf Sitzungen nicht blockieren --------------------------------
echo "== Handshake-Drossel =="
# max_concurrent_handshakes ist 2. Wuerde sie ueber die Sitzungsdauer gehalten,
# blockierten schon zwei offene Tunnel jeden weiteren Verbindungsaufbau.
"$SCHLEUSE" client -c client-chef.json -device werk1 -service http -listen 127.0.0.1:$P_FWD >c.log 2>&1 & PIDS+=($!)
sleep 1.5
cat > halten.py <<PY
import socket, time
h = []
for _ in range(6):
    try:
        s = socket.create_connection(("127.0.0.1", $P_FWD), timeout=5); h.append(s)
    except OSError: pass
time.sleep(6)
PY
python3 halten.py & HOLD=$!; PIDS+=($HOLD)
sleep 3
code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "http://127.0.0.1:$P_FWD/i")
if [ "$code" = "200" ]; then ok "neue Sitzungen trotz gehaltener Tunnel moeglich"
else bad "neue Sitzungen trotz gehaltener Tunnel moeglich" "HTTP $code"; fi
wait $HOLD 2>/dev/null

# --- Entzug waehrend laufender Sitzung --------------------------------------
echo "== Entzug im laufenden Betrieb =="
cat > langlauf.py <<PY
import socket, sys, time
s = socket.create_connection(("127.0.0.1", $P_FWD), timeout=10)
s.settimeout(25)
sys.stderr.write("offen\n"); sys.stderr.flush()
try:
    d = s.recv(1)            # blockiert, bis die Gegenseite schliesst
    print("EOF" if d == b"" else "daten")
except socket.timeout:
    print("laeuft-weiter")
PY
python3 langlauf.py > langlauf.out 2>langlauf.err & LL=$!; PIDS+=($LL)
sleep 2
python3 -c "import json;a=json.load(open('acl.json'));a['revoked']=['client:chef'];json.dump(a,open('acl.json','w'))"
kill -HUP $RELAY; sleep 2
wait $LL 2>/dev/null
res=$(cat langlauf.out)
if [ "$res" = "EOF" ]; then ok "laufende Sitzung endet bei Sperre per acl.json"
else bad "laufende Sitzung endet bei Sperre per acl.json" "Ergebnis: '$res'"; fi
grep -q "laufende Sitzung durch ACL beendet" relay.log && ok "Beendigung wird protokolliert" || bad "Beendigung wird protokolliert"

# --- Geraeteliste -----------------------------------------------------------
echo "== Geraeteliste =="
# werk9 hat ein gueltiges Zertifikat derselben CA, steht aber nicht in acl.json.
P device werk9
cat > agent-werk9.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/device-werk9.crt",
  "key": "pki/device-werk9.key", "services": { "http": "127.0.0.1:$P_HTTP" },
  "reconnect_min_sec": 1, "reconnect_max_sec": 1 }
EOF
out=$(timeout 12 "$SCHLEUSE" agent -c agent-werk9.json 2>&1)
case "$out" in
  *angemeldet*) bad "unbekanntes Geraet wird trotz gueltigem Zertifikat abgewiesen" "es hat sich angemeldet";;
  *) ok "unbekanntes Geraet wird trotz gueltigem Zertifikat abgewiesen";;
esac
grep -q "steht nicht in der Geraeteliste" relay.log && ok "Ablehnung nennt den Grund" || bad "Ablehnung nennt den Grund"

# In die Liste aufgenommen, muss es durchkommen.
python3 - <<'PY2'
import json
a = json.load(open('acl.json')); a['devices']['werk9'] = {"note": "nachtraeglich"}
json.dump(a, open('acl.json', 'w'))
PY2
kill -HUP $RELAY; sleep 1
"$SCHLEUSE" agent -c agent-werk9.json > agent-werk9.log 2>&1 & W9=$!; PIDS+=($W9)
sleep 3
grep -q "angemeldet" agent-werk9.log && ok "nach Eintrag in die Liste kommt es durch" || bad "nach Eintrag in die Liste kommt es durch"

# Wieder herausgenommen, muss die laufende Anmeldung enden.
python3 - <<'PY2'
import json
a = json.load(open('acl.json')); del a['devices']['werk9']
json.dump(a, open('acl.json', 'w'))
PY2
kill -HUP $RELAY; sleep 2
grep -q "nicht mehr in der Geraeteliste" relay.log && ok "Streichen beendet die laufende Anmeldung" || bad "Streichen beendet die laufende Anmeldung"
kill $W9 2>/dev/null

# Ohne Geraeteliste ist die Anmeldung offen - das muss der Relay deutlich sagen.
python3 - <<'PY2'
import json
a = json.load(open('acl.json')); a.pop('devices', None)
json.dump(a, open('acl.json', 'w'))
PY2
kill -HUP $RELAY; sleep 1
grep -q "es kann sich noch kein Geraet anmelden" relay.log \
	&& ok "ohne Liste darf sich in der Vorgabe niemand anmelden" \
	|| bad "ohne Liste darf sich in der Vorgabe niemand anmelden"
out=$(timeout 12 "$SCHLEUSE" agent -c agent-werk9.json 2>&1)
case "$out" in
  *angemeldet*) bad "leere Geraeteliste weist auch gueltige Zertifikate ab" "es hat sich angemeldet";;
  *) ok "leere Geraeteliste weist auch gueltige Zertifikate ab";;
esac

# --- Fehlerhafte Konfiguration ----------------------------------------------
echo "== Konfiguration =="
sed 's/"devices"/"device"/' acl.json > acl-tippfehler.json
sed "s|acl.json|acl-tippfehler.json|" relay.json > relay-tippfehler.json
denied "Tippfehler im ACL-Schluessel faellt beim Start auf" "device" \
	timeout 10 "$SCHLEUSE" relay -c relay-tippfehler.json
sed 's/"services"/"dienste"/' agent.json > agent-tippfehler.json
denied "Tippfehler in der Dienstetabelle faellt beim Start auf" "dienste" \
	timeout 10 "$SCHLEUSE" agent -c agent-tippfehler.json

# --- Ueberlange Protokollzeile ----------------------------------------------
echo "== Protokollgrenzen =="
python3 - <<PY >/dev/null 2>&1
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain("pki/client-chef.crt", "pki/client-chef.key")
try:
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", $P_RELAY), timeout=5),
                         server_hostname="localhost") as t:
        t.sendall(b'{"v":1,"role":"client","device":"' + b"A"*100000 + b'"}\n')
        t.recv(100)
except Exception:
    pass
PY
sleep 1
if kill -0 $RELAY 2>/dev/null; then ok "ueberlange Protokollzeile bringt den Relay nicht um"
else bad "ueberlange Protokollzeile bringt den Relay nicht um"; fi

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[ "$fail" -eq 0 ]
