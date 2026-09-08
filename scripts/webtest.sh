#!/bin/bash
# webtest.sh [pfad/zu/schleuse] - Weboberflaeche und Selbstanmeldung von Anfang bis Ende.
#
# Spielt den ganzen Weg durch: Ersteinrichtung des ersten Verwalters, zweiter
# Faktor, Anmeldung, ein Geraet meldet sich selbst an, landet in der
# Warteschlange, wird freigegeben, holt sein Zertifikat ab und traegt danach
# einen SSH-Zugang. Dazwischen die Absicherungen der Oberflaeche.

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

R=42443; WEB=42444; HTTPD=42080; FWD=42081
for p in $R $WEB $HTTPD $FWD; do
  ss -lntH "sport = :$p" 2>/dev/null | grep -q . && { echo "Port $p belegt"; exit 1; }
done

echo "schleuse-Webtest  ($SCHLEUSE)"
cd "$W"
P() { SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" "$@" >/dev/null; }
P init; P device-ca; P relay localhost; P client chef

cat > relay.json <<EOF
{ "listen": "127.0.0.1:$R", "ca": "pki/ca.crt", "cert": "pki/relay.crt", "key": "pki/relay.key",
  "acl": "acl.json", "allow_unlisted_devices": true,
  "enrollment": { "ca": "pki/device-ca.crt", "key": "pki/device-ca.key", "queue": "pending.json" },
  "web": { "listen": "127.0.0.1:$WEB", "users": "users.json" } }
EOF
echo '{"devices":{},"clients":{"chef":{"devices":["*"],"services":["*"]}},"revoked":[]}' > acl.json
echo '{ "relay":"localhost:'$R'","ca":"pki/ca.crt","cert":"pki/client-chef.crt","key":"pki/client-chef.key" }' > client.json
mkdir www && echo "hallo vom geraet" > www/i
python3 -m http.server $HTTPD --bind 127.0.0.1 --directory www >/dev/null 2>&1 & PIDS+=($!)

"$SCHLEUSE" relay -c relay.json > relay.log 2>&1 & RELAY=$!; PIDS+=($RELAY)
sleep 3
TOKEN=$(grep -oP 'Kennwort: \K\S+' relay.log)
PIN=$(grep -oP "schleuse enroll': \K\S+" relay.log)
[ -n "$TOKEN" ] && ok "Ersteinrichtung wird angeboten" || bad "Ersteinrichtung wird angeboten"

C="curl -sk -c $W/jar -b $W/jar"
holen() { $C "https://127.0.0.1:$WEB$1"; }
csrf()  { grep -oP 'name="csrf" value="\K[0-9a-f]+' | head -1; }

cat > totp.py <<'PY'
import hmac, hashlib, struct, base64, sys, time
s = sys.argv[1].replace('-','').replace(' ','').upper()
key = base64.b32decode(s + '=' * ((8 - len(s) % 8) % 8))
c = int(time.time()) // 30
h = hmac.new(key, struct.pack('>Q', c), hashlib.sha1).digest()
o = h[19] & 15
print(str((struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000).zfill(6))
PY

# --- Absicherung vor der Anmeldung ------------------------------------------
echo "== Vor der Anmeldung =="
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$WEB/users")
check "geschützte Seite leitet zur Anmeldung" "$code" "302"
out=$(curl -sk -X POST -d "csrf=x&user=y" "https://127.0.0.1:$WEB/users/add" -o /dev/null -w '%{http_code}')
check "Änderung ohne Sitzung wird abgewiesen" "$out" "302"
out=$(holen /setup | grep -c "<h1>Initial setup")
check "Ersteinrichtung erreichbar" "$out" "1"
out=$(curl -sk -X POST -d "token=FALSCH&user=x&pw=abcdefghijkl&pw2=abcdefghijkl" \
      "https://127.0.0.1:$WEB/setup" | grep -c "setup password is not correct")
check "falsches Einrichtungskennwort wird abgewiesen" "$out" "1"

# --- Ersteinrichtung ---------------------------------------------------------
echo "== Ersteinrichtung =="
$C -X POST -d "token=$TOKEN&user=chef&pw=sehrlangespasswort&pw2=sehrlangespasswort" \
   -o /dev/null "https://127.0.0.1:$WEB/setup"
seite=$(holen /login/2fa-neu)
SECRET=$(echo "$seite" | grep -oP '<p class="fp">\K[A-Z2-7-]+' | head -1)
CSRF=$(echo "$seite" | csrf)
[ -n "$SECRET" ] && ok "Geheimnis für den zweiten Faktor wird angezeigt" || bad "Geheimnis für den zweiten Faktor wird angezeigt"

# Der QR-Code steht als SVG im Dokument, nicht als nachgeladenes Bild. Dass der
# Kodierer richtig rechnet, prueft "schleuse verify-crypto" gegen 80 Rasterpruef-
# summen; hier geht es nur darum, dass er auch wirklich auf der Seite landet.
# Die Kante ist Module plus zweimal vier Ruhezone, jede Fassung hat 4v+17.
KANTE=$(echo "$seite" | grep -oP '<svg[^>]*viewBox="0 0 \K[0-9]+' | head -1)
if [ -n "$KANTE" ] && [ "$KANTE" -ge 29 ] && [ $(( (KANTE - 25) % 4 )) -eq 0 ] \
   && echo "$seite" | grep -q '<path d="M'; then
	ok "QR-Code für den zweiten Faktor steht auf der Seite (Fassung $(( (KANTE - 25) / 4 )))"
else
	bad "QR-Code für den zweiten Faktor steht auf der Seite" "viewBox-Kante '$KANTE'"
fi

out=$($C -X POST -d "csrf=$CSRF&code=000000" "https://127.0.0.1:$WEB/login/2fa-neu" | grep -c "not correct")
check "falscher Code wird abgewiesen" "$out" "1"

CODE=$(python3 totp.py "$SECRET")
$C -X POST -d "csrf=$CSRF&code=$CODE" -o /dev/null "https://127.0.0.1:$WEB/login/2fa-neu"
konto=$(holen /account)
n=$(echo "$konto" | grep -c "Recovery codes")
[ "$n" -ge 1 ] && ok "zweiter Faktor eingerichtet, Codes angezeigt" || bad "zweiter Faktor eingerichtet, Codes angezeigt"
RECOVERY=$(echo "$konto" | grep -oP '<li>\K[A-Z2-7-]+' | head -1)
[ -n "$RECOVERY" ] && ok "Wiederherstellungscodes vorhanden" || bad "Wiederherstellungscodes vorhanden"
n=$(holen /account | grep -c "Recovery codes</h2>")
check "Codes werden nur einmal gezeigt" "$n" "0"

# --- Absicherung nach der Anmeldung -----------------------------------------
echo "== Absicherung =="
CSRF=$(holen /users | csrf)
out=$($C -X POST -d "csrf=falsch&user=neu&role=Viewer" -o /dev/null -w '%{http_code}' \
      "https://127.0.0.1:$WEB/users/add")
check "Formular mit falschem Merkmal wird abgewiesen" "$out" "400"
n=$(holen /users | grep -c 'class="mono">chef<')
check "Benutzerliste zeigt den Verwalter" "$n" "1"

# --- Selbstanmeldung eines Geraets ------------------------------------------
echo "== Selbstanmeldung =="
n=$(holen /pending | grep -c "Nothing is waiting right now")
check "Warteschlange ist zunächst leer" "$n" "1"

mkdir geraet
"$SCHLEUSE" enroll -relay localhost:$R -ca-pin "$PIN" -dir geraet -name "werk9-hmi.halle3" \
        -service http=127.0.0.1:$HTTPD -interval 2 > enroll.log 2>&1 & ENROLL=$!; PIDS+=($ENROLL)
sleep 4

FP_GERAET=$(grep -oP 'Fingerabdruck\s+\K[A-Z2-7-]+' enroll.log | head -1)
seite=$(holen /pending)
FP_WEB=$(echo "$seite" | grep -oP '<p class="fp">\K[A-Z2-7-]+' | head -1)
[ -n "$FP_GERAET" ] && ok "das Gerät zeigt seinen Fingerabdruck an" || bad "das Gerät zeigt seinen Fingerabdruck an"
check "Fingerabdruck in der Oberfläche stimmt mit dem des Geräts überein" "$FP_WEB" "$FP_GERAET"
n=$(echo "$seite" | grep -c "werk9-hmi.halle3")
check "Selbstauskunft des Geräts wird angezeigt" "$n" "1"
n=$(echo "$seite" | grep -c 'value="werk9-hmi"')
check "Name wird aus der Selbstauskunft vorgeschlagen" "$n" "1"

# Solange nicht freigegeben, ist das Geraet nirgends
n=$(grep -c "online" relay.log || true)
check "wartendes Gerät ist nicht angemeldet" "$n" "0"
out=$(timeout 10 "$SCHLEUSE" client -c client.json -device werk9 -service http -stdio 2>&1 | tail -1)
case "$out" in *"nicht online"*) ok "wartendes Gerät ist nicht erreichbar";;
  *) bad "wartendes Gerät ist nicht erreichbar" "$out";; esac

# --- Freigabe ---------------------------------------------------------------
echo "== Freigabe =="
ID=$(echo "$seite" | grep -oP 'name="id" value="\K[0-9a-f]+' | head -1)
CSRF=$(echo "$seite" | csrf)
$C -X POST -d "csrf=$CSRF&id=$ID&device=werk9&note=Halle+3&svc=http" \
   -o freigabe.html "https://127.0.0.1:$WEB/pending/approve"
n=$(grep -c "is approved" freigabe.html)
check "Freigabe bestätigt" "$n" "1"
n=$(holen /devices | grep -c "werk9")
[ "$n" -ge 1 ] && ok "Gerät steht jetzt in der Geräteliste" || bad "Gerät steht jetzt in der Geräteliste"

for _ in $(seq 20); do kill -0 $ENROLL 2>/dev/null || break; sleep 1; done
for f in ca.crt device.crt device.key agent.json; do
  [ -f "geraet/$f" ] || bad "geraet/$f wurde geschrieben"
done
[ -f geraet/agent.json ] && ok "Zertifikat und Konfiguration auf dem Gerät" || true
check "Schlüssel ist nur für den Besitzer lesbar" "$(stat -c%a geraet/device.key)" "600"
n=$(grep -c "BEGIN CERTIFICATE" geraet/device.crt)
check "Zertifikatskette enthält die Zwischen-CA" "$n" "2"
n=$(openssl x509 -in geraet/device.crt -noout -subject | grep -c "device:werk9")
check "Zertifikat lautet auf den vergebenen Namen" "$n" "1"

# --- Betrieb ----------------------------------------------------------------
echo "== Betrieb =="
"$SCHLEUSE" agent -c geraet/agent.json > agent.log 2>&1 & PIDS+=($!)
sleep 3
n=$(grep -c "werk9: online" relay.log)
check "das Gerät ist nach der Freigabe angemeldet" "$n" "1"

check "der lokale Dienst des Geräts antwortet" \
      "$(curl -s --max-time 10 http://127.0.0.1:$HTTPD/i)" "hallo vom geraet"
"$SCHLEUSE" client -c client.json -device werk9 -service http -listen 127.0.0.1:$FWD > cl.log 2>&1 & PIDS+=($!)
sleep 2
check "Tunnel zum selbst angemeldeten Gerät" \
      "$(curl -s --max-time 10 http://127.0.0.1:$FWD/i)" "hallo vom geraet"

# --- Zentrale Freigabe der Dienste ------------------------------------------
echo "== Dienstfreigabe =="
seite=$(holen /devices)
CSRF=$(echo "$seite" | csrf)
$C -X POST -d "csrf=$CSRF&device=werk9&note=Halle+3" -o /dev/null "https://127.0.0.1:$WEB/devices/save"
sleep 1
out=$(timeout 10 "$SCHLEUSE" client -c client.json -device werk9 -service http -stdio 2>&1 | tail -1)
case "$out" in *"nicht freigegeben"*) ok "abgewählter Dienst ist gesperrt";;
  *) bad "abgewählter Dienst ist gesperrt" "$out";; esac

$C -X POST -d "csrf=$CSRF&device=werk9&note=Halle+3&svc=http" -o /dev/null "https://127.0.0.1:$WEB/devices/save"
sleep 1
check "wieder freigegeben" "$(curl -s --max-time 10 http://127.0.0.1:$FWD/i)" "hallo vom geraet"

# --- Sperre ------------------------------------------------------------------
echo "== Sperre =="
$C -X POST -d "csrf=$CSRF&device=werk9&note=Halle+3&svc=http&revoked=on" -o /dev/null \
   "https://127.0.0.1:$WEB/devices/save"
sleep 2
n=$(grep -c "gesperrt, Anmeldung wird beendet" relay.log)
[ "$n" -ge 1 ] && ok "Sperre trennt das Gerät sofort" || bad "Sperre trennt das Gerät sofort"

# --- Rolle "nur lesen" -------------------------------------------------------
echo "== Rollen =="
seite=$(holen /users); CSRF=$(echo "$seite" | csrf)
$C -X POST -d "csrf=$CSRF&user=gast&role=Viewer" -o neu.html "https://127.0.0.1:$WEB/users/add"
GASTPW=$(grep -oP 'Initial password: \K[A-Z2-7-]+' neu.html | head -1)
[ -n "$GASTPW" ] && ok "Anfangspasswort wird einmalig angezeigt" || bad "Anfangspasswort wird einmalig angezeigt"

G="curl -sk -c $W/gastjar -b $W/gastjar"
$G -X POST -d "user=gast&pw=$GASTPW" -o /dev/null "https://127.0.0.1:$WEB/login"
seite=$($G "https://127.0.0.1:$WEB/login/2fa-neu")
GSECRET=$(echo "$seite" | grep -oP '<p class="fp">\K[A-Z2-7-]+' | head -1)
GCSRF=$(echo "$seite" | csrf)
$G -X POST -d "csrf=$GCSRF&code=$(python3 totp.py "$GSECRET")" -o /dev/null "https://127.0.0.1:$WEB/login/2fa-neu"
n=$($G "https://127.0.0.1:$WEB/devices" | grep -c "read only")
[ "$n" -ge 1 ] && ok "Gast ist angemeldet und als nur-lesend gekennzeichnet" || bad "Gast ist angemeldet"

GCSRF=$($G "https://127.0.0.1:$WEB/devices" | csrf)
n=$($G -X POST -d "csrf=$GCSRF&device=werk9&note=verstellt" \
      "https://127.0.0.1:$WEB/devices/save" | grep -c "<h1>Not allowed")
check "Gast darf nichts ändern" "$n" "1"
n=$(holen /devices | grep -c "verstellt")
check "die Änderung des Gasts kam nicht durch" "$n" "0"

# --- Durchprobieren ----------------------------------------------------------
echo "== Durchprobieren =="
for i in 1 2 3 4 5 6; do
  curl -sk -o /dev/null -X POST -d "user=gast&pw=falsch$i" "https://127.0.0.1:$WEB/login"
done
out=$(curl -sk -X POST -d "user=gast&pw=$GASTPW" "https://127.0.0.1:$WEB/login" | grep -c "locked until")
check "nach fünf Fehlversuchen wird der Zugang gesperrt" "$out" "1"
n=$(grep -c "Anmeldung fehlgeschlagen" relay.log)
[ "$n" -ge 6 ] && ok "Fehlversuche werden protokolliert" || bad "Fehlversuche werden protokolliert" "$n"

# --- Abmelden ----------------------------------------------------------------
echo "== Abmelden =="
CSRF=$(holen /account | csrf)
$C -X POST -d "csrf=$CSRF" -o /dev/null "https://127.0.0.1:$WEB/logout"
code=$(curl -sk -b $W/jar -o /dev/null -w '%{http_code}' "https://127.0.0.1:$WEB/users")
check "nach dem Abmelden ist die Sitzung ungültig" "$code" "302"

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[ "$fail" -eq 0 ]
