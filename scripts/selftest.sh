#!/bin/bash
# selftest.sh [pfad/zu/schleuse] - End-to-End-Test in einem temporaeren Verzeichnis.
#
# Baut eine vollstaendige Aufstellung aus CA, Relay, Agent und Bediener auf und
# prueft Funktion und Abweisungsverhalten. Braucht openssl und python3;
# die SSH-Tests werden uebersprungen, wenn kein sshd vorhanden ist.

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

W="$(mktemp -d)"
PIDS=()
pass=0; fail=0
cleanup() {
	for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
	if [ -n "${KEEP:-}" ]; then echo "Arbeitsverzeichnis behalten: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

ok()   { pass=$((pass+1)); printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \033[31mFEHL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && echo "        $2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "erwartet '$3', bekommen '$2'"; fi; }
# grep im Ergebnis eines Kommandos
expect_out() { local name="$1" pat="$2"; shift 2
	local out; out="$("$@" 2>&1)"
	case "$out" in *"$pat"*) ok "$name";; *) bad "$name" "'$pat' fehlt in: $(echo "$out"|tail -1)";; esac
}

echo "schleuse-Selbsttest  ($SCHLEUSE)"
echo "Arbeitsverzeichnis: $W"
cd "$W"

# --- Aufbau ---------------------------------------------------------------
echo "== Aufbau =="
SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" init      >/dev/null
SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" relay localhost >/dev/null
SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" device werk1    >/dev/null
SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" client chef     >/dev/null
SCHLEUSE_PKI="$W/pki" "$ROOT/scripts/schleuse-pki.sh" client gast     >/dev/null
SCHLEUSE_PKI="$W/fremd" "$ROOT/scripts/schleuse-pki.sh" init          >/dev/null
SCHLEUSE_PKI="$W/fremd" "$ROOT/scripts/schleuse-pki.sh" client boese  >/dev/null
ok "CA und Zertifikate erzeugt"

P_RELAY=17443; P_HTTP=17080; P_ECHO=17099; P_SSH=17022
P_FWD=18080; P_FWDECHO=18099; P_FWDSSH=12222
belegt=""
for p in $P_RELAY $P_HTTP $P_ECHO $P_SSH $P_FWD $P_FWDECHO $P_FWDSSH; do
	ss -lntH "sport = :$p" 2>/dev/null | grep -q . && belegt="$belegt $p"
done
[ -z "$belegt" ] || { echo "Ports schon belegt:$belegt - Test waere nicht aussagekraeftig"; exit 1; }
cat > relay.json <<EOF
{ "listen": "127.0.0.1:$P_RELAY", "ca": "pki/ca.crt", "cert": "pki/relay.crt",
  "key": "pki/relay.key", "acl": "acl.json", "allow_unlisted_devices": true,
  "ping_interval_sec": 3, "ping_timeout_sec": 12, "max_streams_per_device": 8 }
EOF
cat > acl.json <<'EOF'
{ "clients": { "chef": { "devices": ["*"], "services": ["*"] },
               "gast": { "devices": ["buero-*"], "services": ["http"] } },
  "revoked": [] }
EOF
cat > agent.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt",
  "cert": "pki/device-werk1.crt", "key": "pki/device-werk1.key",
  "services": { "http": "127.0.0.1:$P_HTTP", "echo": "127.0.0.1:$P_ECHO",
                "ssh": "127.0.0.1:$P_SSH", "tot": "127.0.0.1:1" },
  "control_timeout_sec": 20, "max_streams": 8 }
EOF
for n in chef gast; do cat > client-$n.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt",
  "cert": "pki/client-$n.crt", "key": "pki/client-$n.key" }
EOF
done
cat > client-fremd.json <<EOF
{ "relay": "localhost:$P_RELAY", "ca": "pki/ca.crt",
  "cert": "fremd/client-boese.crt", "key": "fremd/client-boese.key" }
EOF

mkdir www && echo "hallo aus werk1" > www/index.html
head -c 2000000 /dev/urandom > www/gross.bin
python3 -m http.server $P_HTTP --bind 127.0.0.1 --directory www >/dev/null 2>&1 & PIDS+=($!)

cat > echo_srv.py <<PY
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $P_ECHO)); s.listen(8)
def h(c):
    n = 0
    while True:
        b = c.recv(65536)
        if not b: break
        n += len(b)
    c.sendall(b"empfangen:%d\n" % n); c.shutdown(socket.SHUT_WR); c.close()
while True:
    c,_ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 echo_srv.py >/dev/null 2>&1 & PIDS+=($!)

"$SCHLEUSE" relay -c relay.json > relay.log 2>&1 & RELAY_PID=$!; PIDS+=($RELAY_PID)
sleep 1
"$SCHLEUSE" agent -c agent.json > agent.log 2>&1 & AGENT_PID=$!; PIDS+=($AGENT_PID)
sleep 2
grep -q "online" relay.log && ok "Agent angemeldet" || bad "Agent angemeldet" "$(tail -2 relay.log)"

"$SCHLEUSE" client -c client-chef.json -device werk1 -service http -listen 127.0.0.1:$P_FWD >client-http.log 2>&1 & PIDS+=($!)
sleep 1.5

# --- Funktion --------------------------------------------------------------
echo "== Funktion =="
check "HTTP durch den Tunnel" "$(curl -s --max-time 10 http://127.0.0.1:$P_FWD/index.html)" "hallo aus werk1"

curl -s --max-time 30 -o dl.bin http://127.0.0.1:$P_FWD/gross.bin
if cmp -s dl.bin www/gross.bin; then ok "2 MB unveraendert uebertragen"; else bad "2 MB unveraendert uebertragen"; fi

codes=$(seq 6 | xargs -P6 -I{} curl -s --max-time 20 -o /dev/null -w "%{http_code}" http://127.0.0.1:$P_FWD/index.html)
check "6 gleichzeitige Anfragen" "$codes" "$(printf '200%.0s' $(seq 6))"

cat > halb.py <<PY
import socket, sys
d = bytes(range(256)) * 2048
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
s.sendall(d); s.shutdown(socket.SHUT_WR)
out = b""
while True:
    b = s.recv(4096)
    if not b: break
    out += b
print(out.decode().strip())
PY
"$SCHLEUSE" client -c client-chef.json -device werk1 -service echo -listen 127.0.0.1:$P_FWDECHO >client-echo.log 2>&1 & PIDS+=($!)
sleep 1.5
check "Halb-Schliessung durchgereicht" "$(timeout 30 python3 halb.py $P_FWDECHO)" "empfangen:524288"

# Grenze der gleichzeitigen Sitzungen: 20 Verbindungen gegen ein Limit von 8.
# Erwartet wird eine saubere und schnelle Abweisung, kein Haenger.
cat > limit.py <<'PY2'
import socket, sys, time
socks = []
for _ in range(20):
    try:
        s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
        s.settimeout(10); socks.append(s)
    except OSError:
        pass
time.sleep(2)
gut = 0
for s in socks:
    try:
        s.sendall(b"x"); s.shutdown(socket.SHUT_WR)
        if s.recv(64).startswith(b"empfangen:"): gut += 1
    except OSError:
        pass
    finally:
        s.close()
print(gut)
PY2
t0=$(date +%s)
durch=$(timeout 60 python3 limit.py $P_FWDECHO)
dauer=$(( $(date +%s) - t0 ))
if [ "$durch" -ge 1 ] && [ "$durch" -le 8 ]; then ok "Sitzungsgrenze haelt ($durch von 20 durchgelassen, Limit 8)"
else bad "Sitzungsgrenze haelt" "$durch von 20 durchgelassen, Limit 8"; fi
if [ "$dauer" -le 20 ]; then ok "ueberzaehlige Sitzungen werden schnell abgewiesen (${dauer}s)"
else bad "ueberzaehlige Sitzungen werden schnell abgewiesen" "${dauer}s"; fi
grep -qi "grenze" agent.log relay.log && ok "Grenze wird protokolliert" || bad "Grenze wird protokolliert"

# --- Abweisung -------------------------------------------------------------
echo "== Abweisung =="
expect_out "fremde CA wird abgewiesen" "Zertifikat abgelehnt" \
	timeout 15 "$SCHLEUSE" client -c client-fremd.json -device werk1 -service http -stdio
expect_out "ACL: gast darf nicht auf werk1" "nicht berechtigt" \
	timeout 15 "$SCHLEUSE" client -c client-gast.json -device werk1 -service http -stdio
expect_out "nicht angebotener Dienst" "bietet 'telnet' nicht an" \
	timeout 15 "$SCHLEUSE" client -c client-chef.json -device werk1 -service telnet -stdio
expect_out "unbekanntes Geraet" "nicht online" \
	timeout 15 "$SCHLEUSE" client -c client-chef.json -device gibtsnicht -service http -stdio
expect_out "toter lokaler Dienst wird gemeldet" "nicht erreichbar" \
	timeout 20 "$SCHLEUSE" client -c client-chef.json -device werk1 -service tot -stdio

python3 - <<'PY'
import json; a=json.load(open('acl.json')); a['revoked']=['client:chef']; json.dump(a,open('acl.json','w'))
PY
kill -HUP $RELAY_PID; sleep 1
expect_out "Sperre per acl.json wirkt nach reload" "gesperrt" \
	timeout 15 "$SCHLEUSE" client -c client-chef.json -device werk1 -service http -stdio
python3 - <<'PY'
import json; a=json.load(open('acl.json')); a['revoked']=[]; json.dump(a,open('acl.json','w'))
PY
kill -HUP $RELAY_PID; sleep 1
check "nach Entsperrung wieder erlaubt" "$(curl -s --max-time 10 http://127.0.0.1:$P_FWD/index.html)" "hallo aus werk1"

# --- Wiederanlauf ----------------------------------------------------------
echo "== Wiederanlauf =="
kill $RELAY_PID; sleep 1
"$SCHLEUSE" relay -c relay.json >> relay.log 2>&1 & RELAY_PID=$!; PIDS+=($RELAY_PID)
sleep 12
check "Agent findet nach Relay-Neustart zurueck" "$(curl -s --max-time 15 http://127.0.0.1:$P_FWD/index.html)" "hallo aus werk1"

# --- SSH -------------------------------------------------------------------
if [ -x /usr/sbin/sshd ] && command -v ssh >/dev/null; then
	echo "== SSH =="
	mkdir sshd
	ssh-keygen -q -t ed25519 -N '' -f sshd/hostkey </dev/null >/dev/null 2>&1
	ssh-keygen -q -t ed25519 -N '' -f sshd/id      </dev/null >/dev/null 2>&1
	cp sshd/id.pub sshd/authorized_keys; chmod 600 sshd/authorized_keys sshd/hostkey
	cat > sshd/config <<EOF
Port $P_SSH
ListenAddress 127.0.0.1
HostKey $W/sshd/hostkey
PidFile $W/sshd/pid
AuthorizedKeysFile $W/sshd/authorized_keys
PasswordAuthentication no
UsePAM no
StrictModes no
Subsystem sftp internal-sftp
EOF
	if /usr/sbin/sshd -f "$W/sshd/config" -E "$W/sshd/log" 2>/dev/null; then
		sleep 1; PIDS+=("$(cat sshd/pid 2>/dev/null || echo 0)")
		O="-i $W/sshd/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
		PC="$SCHLEUSE client -c $W/client-chef.json -device werk1 -service ssh -stdio"
		check "ssh ueber ProxyCommand" \
			"$(timeout 30 ssh $O -o "ProxyCommand=$PC" "$USER@werk1" 'echo lebt' 2>&1)" "lebt"

		"$SCHLEUSE" client -c client-chef.json -device werk1 -service ssh -listen 127.0.0.1:$P_FWDSSH >client-ssh.log 2>&1 & PIDS+=($!)
		sleep 1.5
		check "ssh ueber lokalen Port" \
			"$(timeout 30 ssh $O -p $P_FWDSSH "$USER@127.0.0.1" 'echo lebt' 2>&1)" "lebt"

		head -c 300000 /dev/urandom > up.bin
		timeout 30 scp $O -P $P_FWDSSH -q up.bin "$USER@127.0.0.1:$W/up-scp.bin" 2>/dev/null
		if cmp -s up.bin up-scp.bin; then ok "scp 300 kB unveraendert"; else bad "scp 300 kB unveraendert"; fi

		echo "put up.bin $W/up-sftp.bin" > sftp.cmd
		timeout 30 sftp $O -P $P_FWDSSH -b sftp.cmd "$USER@127.0.0.1" >/dev/null 2>&1
		if cmp -s up.bin up-sftp.bin; then ok "sftp unveraendert"; else bad "sftp unveraendert"; fi

		timeout 30 ssh $O -p $P_FWDSSH "$USER@127.0.0.1" "cat > $W/up-stdin.bin" < up.bin
		if cmp -s up.bin up-stdin.bin; then ok "stdin-Upload (EOF durch den Tunnel)"; else bad "stdin-Upload (EOF durch den Tunnel)"; fi
	else
		echo "  (sshd liess sich nicht starten - SSH-Tests uebersprungen)"
	fi
else
	echo "  (kein sshd - SSH-Tests uebersprungen)"
fi

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[ "$fail" -eq 0 ]
