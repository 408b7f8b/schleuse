#!/bin/sh
# build.sh [rid ...]  - baut schleuse als natives Binary nach out/<rid>/schleuse
#
# Vorgabe ist die Architektur des Buildhosts. Native AOT unterstuetzt unter
# Linux: linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64.
# Fuer 32-bit-ARM (linux-arm) gibt es kein AOT - dort greift automatisch das
# self-contained Single-File-Bundle (groesser, aber ebenfalls ohne
# vorinstallierte .NET-Runtime lauffaehig).

set -eu
cd "$(dirname "$0")"

EIGEN="linux-$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/;s/armv7l/arm/')"
RIDS="${*:-$EIGEN}"

# Native AOT braucht zum Querbauen clang samt passender Zielumgebung; gcc
# versteht dessen --target nicht. Fehlt das, weicht der Bau auf ein
# self-contained Single-File-Bundle aus: groesser, aber es laeuft ebenso ohne
# vorinstallierte .NET-Runtime und braucht keinerlei Toolchain.
aot_moeglich() {
	[ "$1" = "linux-arm" ] && return 1          # fuer 32-bit-ARM gibt es kein AOT
	[ "$1" = "$EIGEN" ] && return 0             # eigene Architektur: gcc genuegt
	command -v clang >/dev/null                 # querbauen nur mit clang
}

for rid in $RIDS; do
	out="out/$rid"
	rm -rf "$out"
	if ! aot_moeglich "$rid"; then
		if [ "$rid" = "linux-arm" ]; then
			echo "== $rid: kein AOT verfuegbar, baue Single-File-Bundle =="
		else
			echo "== $rid: querbauen ohne clang, baue Single-File-Bundle =="
			echo "   (fuer ein natives Binary: apt install clang lld, oder auf $rid selbst bauen)"
		fi
		dotnet publish -c Release -r "$rid" --self-contained true \
			-p:PublishAot=false -p:PublishTrimmed=true -p:PublishSingleFile=true \
			-o "$out" --nologo
		rm -f "$out"/*.dbg "$out"/*.pdb
		# Die Betriebsart festhalten: ein Bundle bringt den JIT mit und braucht
		# beschreibbaren ausfuehrbaren Speicher. Die systemd-Einheit verbietet
		# genau das - wer beides nicht aufeinander abstimmt, bekommt einen
		# Absturz beim Start und keine Erklaerung dazu.
		echo singlefile > "$out/BUILD-MODE"
		printf '%s: ' "$out/schleuse"; ls -lh "$out/schleuse" | awk '{print $5}'
		continue
	fi
	case "$rid" in
	__nie__)
		echo "unerreichbar"
		dotnet publish -c Release -r "$rid" --self-contained true \
			-p:PublishAot=false -p:PublishTrimmed=true -p:PublishSingleFile=true \
			-o "$out" --nologo
		;;
	*)
		echo "== $rid: Native AOT =="
		dotnet publish -c Release -r "$rid" -o "$out" --nologo
		;;
	esac
	rm -f "$out"/*.dbg "$out"/*.pdb
	echo aot > "$out/BUILD-MODE"
	printf '%s: ' "$out/schleuse"; ls -lh "$out/schleuse" | awk '{print $5}'
done
