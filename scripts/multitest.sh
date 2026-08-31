#!/bin/bash
# multitest.sh [pfad/zu/schleuse] - mehrere Geraete, mehrere Dienste, alles parallel.
#
# Prueft, dass drei Geraete mit je mehreren Protokollen gleichzeitig bedient
# werden, dass unter Last nichts zwischen ihnen verrutscht, dass ein Bediener
# nur sieht und erreicht, was ihm zusteht, und dass weder ein ausgefallenes
# Geraet noch ein einzelner Bediener die uebrigen beeintraechtigt.

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

R=37443
declare -A HTTP=( [werk1]=37101 [werk2]=37102 [werk3]=37103 )   # lokale Dienste je Geraet
declare -A ECHO=( [werk1]=37201 [werk2]=37202 [werk3]=37203 )
declare -A FH=(   [werk1]=38101 [werk2]=38102 [werk3]=38103 )   # Weiterleitungen beim Bediener
declare -A FE=(   [werk1]=38201 [werk2]=38202 [werk3]=38203 )
for p in $R "${HTTP[@]}" "${ECHO[@]}" "${FH[@]}" "${FE[@]}"; do
	ss -lntH "sport = :$p" 2>/dev/null | grep -q . && { echo "Port $p belegt"; exit 1; }
done

echo "schleuse-Mehrgeraetetest  ($SCHLEUSE)"
cd "$W"
P() { SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" "$@" >/dev/null; }
P init; P relay localhost
for d in werk1 werk2 werk3; do P device $d; done
P client chef; P client monteur; P client nur3

# --- Relay: enge Budgets, damit die Trennung pruefbar wird ------------------
cat > relay.json <<EOF
{ "listen": "127.0.0.1:$R", "ca": "pki/ca.crt", "cert": "pki/relay.crt",
  "key": "pki/relay.key", "acl": "acl.json", "allow_unlisted_devices": true,
  "max_streams_per_device": 12, "max_streams_per_client": 3,
  "stream_open_timeout_sec": 5, "ping_interval_sec": 5, "ping_timeout_sec": 20 }
EOF
cat > acl.json <<'EOF'
{ "clients": {
    "chef":    { "devices": ["*"],     "services": ["*"] },
    "monteur": { "devices": ["werk1"], "services": ["http"] },
    "nur3":    { "devices": ["werk3"], "services": ["http", "echo"] } },
  "revoked": [] }
EOF
"$SCHLEUSE" relay -c relay.json > relay.log 2>&1 & RELAY=$!; PIDS+=($RELAY)

# --- Drei Geraete, je zwei Dienste, jedes mit eigener Kennung ---------------
cat > echo_srv.py <<'PY'
import socket, sys, threading
port, name = int(sys.argv[1]), sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(16)
def h(c):
    n = 0
    while True:
        b = c.recv(65536)
        if not b: break
        n += len(b)
    c.sendall(("%s:%d\n" % (name, n)).encode())
    c.shutdown(socket.SHUT_WR); c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
declare -A APID
for d in werk1 werk2 werk3; do
	mkdir -p www-$d
	echo "ich bin $d" > www-$d/i
	head -c 400000 /dev/urandom > www-$d/blob.bin
	python3 -m http.server "${HTTP[$d]}" --bind 127.0.0.1 --directory www-$d >/dev/null 2>&1 & PIDS+=($!)
	python3 echo_srv.py "${ECHO[$d]}" "$d" >/dev/null 2>&1 & PIDS+=($!)
	cat > agent-$d.json <<EOF
{ "relay": "localhost:$R", "ca": "pki/ca.crt", "cert": "pki/device-$d.crt",
  "key": "pki/device-$d.key",
  "services": { "http": "127.0.0.1:${HTTP[$d]}", "echo": "127.0.0.1:${ECHO[$d]}" },
  "max_streams": 12, "reconnect_min_sec": 1, "reconnect_max_sec": 2 }
EOF
	"$SCHLEUSE" agent -c agent-$d.json > agent-$d.log 2>&1 & APID[$d]=$!; PIDS+=(${APID[$d]})
done
mkc() { cat > "client-$1.json" <<EOF
{ "relay": "localhost:$R", "ca": "pki/ca.crt", "cert": "pki/client-$1.crt", "key": "pki/client-$1.key" }
EOF
}
mkc chef; mkc monteur; mkc nur3
sleep 3
check "drei Geraete gleichzeitig angemeldet" "$(grep -c ': online' relay.log)" "3"

# --- Ein Bediener-Prozess fuer sechs Weiterleitungen ------------------------
"$SCHLEUSE" client -c client-chef.json \
	-forward werk1/http=127.0.0.1:${FH[werk1]} -forward werk1/echo=127.0.0.1:${FE[werk1]} \
	-forward werk2/http=127.0.0.1:${FH[werk2]} -forward werk2/echo=127.0.0.1:${FE[werk2]} \
	-forward werk3/http=127.0.0.1:${FH[werk3]} -forward werk3/echo=127.0.0.1:${FE[werk3]} \
	> client-chef.log 2>&1 & PIDS+=($!)
sleep 2
n=$(grep -c ' -> werk' client-chef.log)
check "sechs Weiterleitungen in einem Prozess" "$n" "6"

echo "== Parallelbetrieb =="
falsch=0
for d in werk1 werk2 werk3; do
	got=$(curl -s --max-time 10 "http://127.0.0.1:${FH[$d]}/i")
	[ "$got" = "ich bin $d" ] || { falsch=$((falsch+1)); echo "        $d lieferte '$got'"; }
done
check "jede Weiterleitung trifft ihr eigenes Geraet" "$falsch" "0"

# Last ueber alle Geraete gleichzeitig: jede Antwort muss zum Port passen.
cat > kreuz.sh <<EOF
#!/bin/bash
d=\$1; p=\$2
got=\$(curl -s --max-time 25 "http://127.0.0.1:\$p/i")
[ "\$got" = "ich bin \$d" ] || echo "KREUZ \$d <- '\$got'"
EOF
chmod +x kreuz.sh
for i in $(seq 30); do
	for d in werk1 werk2 werk3; do echo "$d ${FH[$d]}"; done
done | xargs -P18 -n2 ./kreuz.sh > kreuz.out 2>&1
check "90 parallele Anfragen ohne Verwechslung" "$(grep -c KREUZ kreuz.out || true)" "0"

# Gleichzeitig grosse Uebertragungen von allen drei Geraeten
DL=()
for d in werk1 werk2 werk3; do
	curl -s --max-time 60 -o dl-$d.bin "http://127.0.0.1:${FH[$d]}/blob.bin" & DL+=($!)
done
wait "${DL[@]}" 2>/dev/null
falsch=0
for d in werk1 werk2 werk3; do cmp -s dl-$d.bin www-$d/blob.bin || falsch=$((falsch+1)); done
check "drei gleichzeitige Downloads je 400 kB unveraendert" "$falsch" "0"

# Zweites Protokoll parallel zum ersten
cat > echo_cli.py <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
s.sendall(b"x" * 1000); s.shutdown(socket.SHUT_WR)
out = b""
while True:
    b = s.recv(4096)
    if not b: break
    out += b
print(out.decode().strip())
PY
falsch=0
for d in werk1 werk2 werk3; do
	got=$(timeout 30 python3 echo_cli.py "${FE[$d]}")
	[ "$got" = "$d:1000" ] || { falsch=$((falsch+1)); echo "        echo $d lieferte '$got'"; }
done
check "zweites Protokoll je Geraet parallel nutzbar" "$falsch" "0"

# --- Trennung der Bediener --------------------------------------------------
echo "== Trennung der Bediener =="
liste_chef=$("$SCHLEUSE" client -c client-chef.json -list 2>&1 | tail -n +2 | awk '{print $1}' | sort | tr '\n' ' ')
check "chef sieht alle drei Geraete" "$liste_chef" "werk1 werk2 werk3 "
liste_m=$("$SCHLEUSE" client -c client-monteur.json -list 2>&1 | tail -n +2)
check "monteur sieht nur werk1"        "$(echo "$liste_m" | awk '{print $1}')" "werk1"
check "monteur sieht nur den Dienst http" "$(echo "$liste_m" | awk '{print $2}')" "http"
liste_3=$("$SCHLEUSE" client -c client-nur3.json -list 2>&1 | tail -n +2 | awk '{print $1}')
check "nur3 sieht nur werk3" "$liste_3" "werk3"

verweigert() { local name="$1" pat="$2"; shift 2
	local out; out="$("$@" 2>&1)"
	case "$out" in *"$pat"*) ok "$name";; *) bad "$name" "'$pat' fehlt in: $(echo "$out" | tail -1)";; esac
}
verweigert "monteur kommt nicht an werk2" "nicht berechtigt" \
	timeout 15 "$SCHLEUSE" client -c client-monteur.json -device werk2 -service http -stdio
verweigert "monteur kommt nicht an werk1/echo" "nicht berechtigt" \
	timeout 15 "$SCHLEUSE" client -c client-monteur.json -device werk1 -service echo -stdio
verweigert "nur3 kommt nicht an werk1" "nicht berechtigt" \
	timeout 15 "$SCHLEUSE" client -c client-nur3.json -device werk1 -service http -stdio

# --- Ein Bediener darf ein Geraet nicht dichtmachen -------------------------
echo "== Budget je Bediener =="
"$SCHLEUSE" client -c client-monteur.json -forward werk1/http=127.0.0.1:38301 >client-monteur.log 2>&1 & PIDS+=($!)
sleep 1.5
cat > halten.py <<'PY'
import socket, sys, time
h = []
for _ in range(int(sys.argv[2])):
    try: h.append(socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5))
    except OSError: pass
time.sleep(float(sys.argv[3]))
PY
# chef belegt sein eigenes Budget auf werk1 voll (max_streams_per_client = 3)
python3 halten.py ${FE[werk1]} 6 8 & HOLD=$!; PIDS+=($HOLD)
sleep 3
code=$(curl -s --max-time 15 -o /dev/null -w "%{http_code}" "http://127.0.0.1:38301/i")
check "monteur kommt durch, waehrend chef sein Budget ausschoepft" "$code" "200"
grep -q "je Bediener erreicht" relay.log && ok "Budgetgrenze wird protokolliert" || bad "Budgetgrenze wird protokolliert"
wait $HOLD 2>/dev/null

# --- Ein ausgefallenes Geraet zieht die anderen nicht mit -------------------
echo "== Ausfall eines Geraets =="
kill ${APID[werk2]} 2>/dev/null; sleep 2
verweigert "werk2 ist als offline erkennbar" "nicht online" \
	timeout 15 "$SCHLEUSE" client -c client-chef.json -device werk2 -service http -stdio
falsch=0
for d in werk1 werk3; do
	got=$(curl -s --max-time 15 "http://127.0.0.1:${FH[$d]}/i")
	[ "$got" = "ich bin $d" ] || falsch=$((falsch+1))
done
check "werk1 und werk3 laufen unbeirrt weiter" "$falsch" "0"
check "Uebersicht zeigt nur noch zwei Geraete" \
	"$("$SCHLEUSE" client -c client-chef.json -list 2>&1 | tail -n +2 | wc -l)" "2"

"$SCHLEUSE" agent -c agent-werk2.json > agent-werk2b.log 2>&1 & PIDS+=($!)
sleep 3
check "werk2 ist nach Neustart wieder da" \
	"$(curl -s --max-time 15 "http://127.0.0.1:${FH[werk2]}/i")" "ich bin werk2"

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[ "$fail" -eq 0 ]
