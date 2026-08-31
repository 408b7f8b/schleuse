#!/bin/bash
# apitest.sh [pfad/zu/schleuse] - Schnittstelle: Absicherung, Verschwiegenheit, Funktionsumfang.
#
# Prueft, dass ohne gueltige Marke nichts zu erfahren ist, dass eine lesende
# Marke nichts aendern kann, dass jede Funktion der Oberflaeche auch maschinell
# erreichbar ist, und dass sich die Oberflaeche darueber ab- und wieder
# einschalten laesst.

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
ok()   { pass=$((pass+1)); printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \033[31mFEHL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && echo "        $2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "erwartet '$3', bekommen '$2'"; fi; }

R=43443; WEB=43444; HTTPD=43080
for p in $R $WEB $HTTPD; do
  ss -lntH "sport = :$p" 2>/dev/null | grep -q . && { echo "Port $p belegt"; exit 1; }
done

echo "schleuse-Schnittstellentest  ($SCHLEUSE)"
cd "$W"
P() { SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" "$@" >/dev/null; }
P init; P device-ca; P relay localhost; P client chef

cat > relay.json <<EOF
{ "listen": "127.0.0.1:$R", "ca": "pki/ca.crt", "cert": "pki/relay.crt", "key": "pki/relay.key",
  "acl": "acl.json", "allow_unlisted_devices": true,
  "enrollment": { "ca": "pki/device-ca.crt", "key": "pki/device-ca.key", "queue": "pending.json" },
  "web": { "listen": "127.0.0.1:$WEB", "users": "users.json", "state": "api.json",
           "api_path": "/leitung" } }
EOF
echo '{"devices":{},"clients":{"chef":{"devices":["*"],"services":["*"]}},"revoked":[]}' > acl.json
mkdir www && echo "hallo" > www/i
python3 -m http.server $HTTPD --bind 127.0.0.1 --directory www >/dev/null 2>&1 & PIDS+=($!)
"$SCHLEUSE" relay -c relay.json > relay.log 2>&1 & RELAY=$!; PIDS+=($RELAY)
sleep 3
TOKEN=$(grep -oP 'Kennwort: \K\S+' relay.log)
PIN=$(grep -oP "schleuse enroll': \K\S+" relay.log)

# Ersten Verwalter und eine Verwalter-Marke ueber die Oberflaeche anlegen
C="curl -sk -c $W/jar -b $W/jar"
B="https://127.0.0.1:$WEB"
cat > totp.py <<'PY'
import hmac, hashlib, struct, base64, sys, time
s = sys.argv[1].replace('-','').replace(' ','').upper()
key = base64.b32decode(s + '=' * ((8 - len(s) % 8) % 8))
c = int(time.time()) // 30
h = hmac.new(key, struct.pack('>Q', c), hashlib.sha1).digest()
o = h[19] & 15
print(str((struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000).zfill(6))
PY
$C -X POST -d "token=$TOKEN&user=chef&pw=sehrlangespasswort&pw2=sehrlangespasswort" -o /dev/null "$B/setup"
seite=$($C "$B/login/2fa-neu")
SECRET=$(echo "$seite" | grep -oP '<p class="fp">\K[A-Z2-7-]+' | head -1)
CSRF=$(echo "$seite" | grep -oP 'name="csrf" value="\K[0-9a-f]+' | head -1)
$C -X POST -d "csrf=$CSRF&code=$(python3 totp.py "$SECRET")" -o /dev/null "$B/login/2fa-neu"

CSRF=$($C "$B/tokens" | grep -oP 'name="csrf" value="\K[0-9a-f]+' | head -1)
ADMIN=$($C -X POST -d "csrf=$CSRF&name=verwalten&role=Admin&days=0" "$B/tokens/create" \
        | grep -oP 'Marke angelegt: \Kschleuse_[A-Z2-7]+')
LESEN=$($C -X POST -d "csrf=$CSRF&name=lesen&role=Viewer&days=0" "$B/tokens/create" \
        | grep -oP 'Marke angelegt: \Kschleuse_[A-Z2-7]+')
[ -n "$ADMIN" ] && [ -n "$LESEN" ] && ok "Marken über die Oberfläche angelegt" || bad "Marken angelegt"

A="curl -sk -H 'Authorization: Bearer '"
hole()  { curl -sk -H "Authorization: Bearer $1" "$B/leitung$2"; }
code()  { curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$B/leitung$2"; }
sende() { curl -sk -X POST -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
               -d "$3" "$B/leitung$2"; }
scode() { curl -sk -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $1" \
               -H 'Content-Type: application/json' -d "$3" "$B/leitung$2"; }

# --- Verschwiegenheit --------------------------------------------------------
echo "== Ohne Marke =="
check "Statuspfad ohne Marke: 404"        "$(curl -sk -o /dev/null -w '%{http_code}' "$B/leitung/status")" "404"
check "erfundener Pfad ohne Marke: 404"   "$(curl -sk -o /dev/null -w '%{http_code}' "$B/leitung/gibtsnicht")" "404"
check "Vorsatz allein ohne Marke: 404"    "$(curl -sk -o /dev/null -w '%{http_code}' "$B/leitung")" "404"
n=$(curl -sk -D- -o /dev/null "$B/leitung/status" | grep -ci "www-authenticate")
check "keine Einladung zum Anmelden im Kopf" "$n" "0"
n=$(curl -sk "$B/leitung/status" | wc -c)
check "leerer Rumpf ohne Marke" "$n" "0"
check "falsche Marke: 404"                "$(code schleuse_FALSCHFALSCHFALSCH /status)" "404"
for pfad in /openapi /swagger /swagger.json /openapi.json /.well-known/openapi /docs; do
  c1=$(curl -sk -o /dev/null -w '%{http_code}' "$B/leitung$pfad")
  [ "$c1" = "404" ] || bad "keine Selbstauskunft unter $pfad" "$c1"
done
ok "keine Selbstauskunft (openapi, swagger, docs)"
n=$(hole "$ADMIN" /status | grep -ci "swagger\|openapi\|paths")
check "auch mit Marke kein Verzeichnis der Pfade" "$n" "0"

echo "== Keks gilt nicht als Marke =="
check "angemeldete Browsersitzung erreicht die Schnittstelle nicht" \
      "$($C -o /dev/null -w '%{http_code}' "$B/leitung/status")" "404"

# --- Lesen -------------------------------------------------------------------
echo "== Lesen =="
st=$(hole "$LESEN" /status)
check "Status mit lesender Marke" "$(echo "$st" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ui_enabled"])')" "True"
check "Status nennt den CA-Fingerabdruck" "$(echo "$st" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ca_pin"])')" "$PIN"
for pfad in /devices /pending /clients /users /tokens; do
  c1=$(code "$LESEN" "$pfad")
  [ "$c1" = "200" ] || bad "lesender Zugriff auf $pfad" "$c1"
done
ok "alle Listen lesbar (devices, pending, clients, users, tokens)"
n=$(hole "$LESEN" /tokens | grep -c "$ADMIN")
check "Marken werden nie im Klartext zurückgegeben" "$n" "0"
n=$(hole "$LESEN" /users | grep -ci "password\|pbkdf2\|totp\":\"")
check "Benutzerliste enthält keine Geheimnisse" "$n" "0"

echo "== Lesende Marke darf nichts ändern =="
check "Schreibversuch mit lesender Marke: 403" \
      "$(scode "$LESEN" /devices/save '{"device":"x","note":"y"}')" "403"
check "unbekannter Schreibpfad bleibt 404" \
      "$(scode "$LESEN" /gibtsnicht/save '{}')" "404"

# --- Selbstanmeldung über die Schnittstelle ----------------------------------
echo "== Ganzer Ablauf über die Schnittstelle =="
mkdir geraet
"$SCHLEUSE" enroll -relay localhost:$R -ca-pin "$PIN" -dir geraet -name "api-geraet" \
        -service http=127.0.0.1:$HTTPD -interval 2 > enroll.log 2>&1 & ENROLL=$!; PIDS+=($ENROLL)
sleep 4
ID=$(hole "$ADMIN" /pending | python3 -c 'import json,sys; r=json.load(sys.stdin)["requests"]; print(r[0]["id"] if r else "")')
FP_API=$(hole "$ADMIN" /pending | python3 -c 'import json,sys; r=json.load(sys.stdin)["requests"]; print(r[0]["fingerprint"] if r else "")')
FP_GER=$(grep -oP 'Fingerabdruck\s+\K[A-Z2-7-]+' enroll.log | head -1)
check "Antrag über die Schnittstelle sichtbar, Fingerabdruck stimmt" "$FP_API" "$FP_GER"

out=$(sende "$ADMIN" /pending/approve "{\"id\":\"$ID\",\"device\":\"apiger\",\"note\":\"per API\",\"services\":[\"http\"]}")
n=$(echo "$out" | grep -c '"ok":true')
check "Freigabe über die Schnittstelle" "$n" "1"
for _ in $(seq 20); do kill -0 $ENROLL 2>/dev/null || break; sleep 1; done
[ -f geraet/agent.json ] && ok "das Gerät hat sein Zertifikat abgeholt" || bad "das Gerät hat sein Zertifikat abgeholt"

"$SCHLEUSE" agent -c geraet/agent.json > agent.log 2>&1 & PIDS+=($!)
sleep 3
n=$(hole "$ADMIN" /devices | python3 -c 'import json,sys
d=[x for x in json.load(sys.stdin)["devices"] if x["device"]=="apiger"]
print(1 if d and d[0]["online"] else 0)')
check "Gerät ist online und über die Schnittstelle sichtbar" "$n" "1"

echo "== Ändern über die Schnittstelle =="
sende "$ADMIN" /devices/save '{"device":"apiger","note":"geändert","services":[]}' >/dev/null
n=$(hole "$ADMIN" /devices | python3 -c 'import json,sys
d=[x for x in json.load(sys.stdin)["devices"] if x["device"]=="apiger"][0]
print(d["note"] + "|" + str(d["released"]))')
check "Notiz und Freigabe geändert" "$n" "geändert|[]"

sende "$ADMIN" /clients/save '{"client":"monteur","devices":["werk*"],"services":["ssh"]}' >/dev/null
n=$(hole "$ADMIN" /clients | grep -c "monteur")
check "Zugang angelegt" "$n" "1"
sende "$ADMIN" /clients/delete '{"client":"monteur"}' >/dev/null
n=$(hole "$ADMIN" /clients | grep -c "monteur")
check "Zugang entfernt" "$n" "0"

out=$(sende "$ADMIN" /users/add '{"user":"neuer","role":"viewer"}')
PW=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("secret",""))')
[ -n "$PW" ] && ok "Benutzer angelegt, Anfangspasswort einmalig zurückgegeben" || bad "Benutzer angelegt"
sende "$ADMIN" /users/delete '{"user":"neuer"}' >/dev/null
n=$(hole "$ADMIN" /users | grep -c "neuer")
check "Benutzer entfernt" "$n" "0"

out=$(sende "$ADMIN" /tokens/create '{"name":"kurzlebig","role":"viewer","days":1}')
NEU=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("secret",""))')
check "neue Marke funktioniert sofort" "$(code "$NEU" /status)" "200"
NID=$(hole "$ADMIN" /tokens | python3 -c 'import json,sys
print([t["id"] for t in json.load(sys.stdin)["tokens"] if t["name"]=="kurzlebig"][0])')
sende "$ADMIN" /tokens/delete "{\"id\":\"$NID\"}" >/dev/null
check "zurückgezogene Marke wirkt sofort nicht mehr" "$(code "$NEU" /status)" "404"

echo "== Eingaben werden begrenzt =="
LANG_NOTE=$(python3 -c "print('A'*5000)")
sende "$ADMIN" /devices/save "{\"device\":\"apiger\",\"note\":\"$LANG_NOTE\"}" >/dev/null
n=$(hole "$ADMIN" /devices | python3 -c 'import json,sys
d=[x for x in json.load(sys.stdin)["devices"] if x["device"]=="apiger"][0]
print(len(d["note"] or ""))')
check "überlange Notiz wird gekürzt" "$n" "200"

sende "$ADMIN" /devices/save '{"device":"apiger","note":"mit
Zeilenumbruch"}' >/dev/null
n=$(hole "$ADMIN" /devices | python3 -c 'import json,sys
d=[x for x in json.load(sys.stdin)["devices"] if x["device"]=="apiger"][0]
print("ja" if "\n" in (d["note"] or "") else "nein")')
check "Steuerzeichen werden entschärft" "$n" "nein"

sende "$ADMIN" /clients/save '{"client":"pruef","devices":["gut-*","<böse>","a b c"],"services":["ssh"]}' >/dev/null
n=$(hole "$ADMIN" /clients | python3 -c 'import json,sys
c=[x for x in json.load(sys.stdin)["clients"] if x["client"]=="pruef"][0]
print(",".join(c["devices"]))')
check "unbrauchbare Muster werden verworfen" "$n" "gut-*"
sende "$ADMIN" /clients/delete '{"client":"pruef"}' >/dev/null

# --- Gleichzeitige Änderungen -------------------------------------------------
echo "== Gleichzeitige Änderungen =="
# Zwanzig Geräte gleichzeitig eintragen. Ohne Schloss um Lesen-Ändern-Schreiben
# überschreiben sich die Aufrufe gegenseitig und es kommen weniger an.
seq 1 20 | xargs -P20 -I{} curl -sk -o /dev/null -X POST \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"device":"gleich{}","note":"parallel"}' "$B/leitung/devices/save"
n=$(hole "$ADMIN" /devices | python3 -c 'import json,sys
print(sum(1 for x in json.load(sys.stdin)["devices"] if x["device"].startswith("gleich")))')
check "alle zwanzig gleichzeitigen Änderungen sind angekommen" "$n" "20"
for i in $(seq 1 20); do sende "$ADMIN" /devices/delete "{\"device\":\"gleich$i\"}" >/dev/null; done

# --- Zertifikatswechsel im Betrieb -------------------------------------------
echo "== Zertifikatswechsel =="
python3 - <<'PY2'
import json
c = json.load(open('relay.json'))
c['web']['cert'] = 'web.crt'; c['web']['key'] = 'web.key'
json.dump(c, open('relay.json','w'), indent=2)
PY2
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout web.key -out web.crt >/dev/null 2>&1
kill $RELAY 2>/dev/null; sleep 1
"$SCHLEUSE" relay -c relay.json >> relay.log 2>&1 & RELAY=$!; PIDS+=($RELAY)
sleep 3
ALT=$(echo | openssl s_client -connect 127.0.0.1:$WEB 2>/dev/null | openssl x509 -noout -serial)
sleep 1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 60 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout web.key -out web.crt >/dev/null 2>&1
sleep 62   # die Pruefung laeuft hoechstens einmal je Minute
NEU=$(echo | openssl s_client -connect 127.0.0.1:$WEB 2>/dev/null | openssl x509 -noout -serial)
if [ -n "$ALT" ] && [ -n "$NEU" ] && [ "$ALT" != "$NEU" ]; then
  ok "erneuertes Zertifikat wird ohne Neustart übernommen"
else
  bad "erneuertes Zertifikat wird ohne Neustart übernommen" "vorher=$ALT nachher=$NEU"
fi
n=$(grep -c "Zertifikat erneuert" relay.log)
[ "$n" -ge 1 ] && ok "der Wechsel wird protokolliert" || bad "der Wechsel wird protokolliert"

echo "== Fehlerbehandlung =="
check "fehlendes Pflichtfeld: 400" "$(scode "$ADMIN" /devices/delete '{}')" "400"
check "kaputtes JSON: 400"         "$(scode "$ADMIN" /devices/save 'kein json')" "400"
n=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $ADMIN" \
     -d 'x=1' "$B/leitung/devices/save")
check "falscher Content-Type: 400" "$n" "400"

# --- Oberfläche schalten ------------------------------------------------------
echo "== Oberfläche ab- und einschalten =="
check "Oberfläche antwortet noch" "$(curl -sk -o /dev/null -w '%{http_code}' "$B/login")" "200"
sende "$ADMIN" /ui '{"enabled":false}' >/dev/null
check "abgeschaltet: Anmeldeseite verschwindet" "$(curl -sk -o /dev/null -w '%{http_code}' "$B/login")" "404"
check "abgeschaltet: Wurzel verschwindet"       "$(curl -sk -o /dev/null -w '%{http_code}' "$B/")" "404"
check "Schnittstelle bleibt erreichbar"         "$(code "$ADMIN" /status)" "200"
n=$(hole "$ADMIN" /status | python3 -c 'import json,sys; print(json.load(sys.stdin)["ui_enabled"])')
check "Status meldet die Abschaltung" "$n" "False"

echo "== Notausgang auf dem Relay =="
n=$("$SCHLEUSE" ui -c relay.json | head -1)
check "schleuse ui zeigt den Zustand" "$n" "Weboberfläche: abgeschaltet"
"$SCHLEUSE" ui -c relay.json -on >/dev/null
kill -HUP $RELAY; sleep 2
check "nach schleuse ui -on und reload ist sie wieder da" \
      "$(curl -sk -o /dev/null -w '%{http_code}' "$B/login")" "200"

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[ "$fail" -eq 0 ]
