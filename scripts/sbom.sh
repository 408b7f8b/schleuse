#!/bin/bash
# sbom.sh [ausgabedatei] - erzeugt eine Stueckliste im CycloneDX-Format.
#
# Der Cyber Resilience Act verlangt eine maschinenlesbare Stueckliste, die
# mindestens die obersten Abhaengigkeiten enthaelt (Anhang I Teil II Nummer 1).
# Sie wird aus dem tatsaechlichen Wiederherstellungsgraphen erzeugt, nicht von
# Hand gepflegt - eine gepflegte Liste waere nach dem ersten Update falsch.
#
# Aufruf nach jedem Release, Ergebnis mit dem Binary zusammen veroeffentlichen.

set -eu
cd "$(dirname "$0")/.."
AUS="${1:-sbom.cdx.json}"

command -v dotnet >/dev/null || { echo "dotnet fehlt"; exit 1; }
dotnet restore --nologo >/dev/null

VERSION=$(grep -oP '<Version>\K[^<]+' schleuse.csproj 2>/dev/null || grep -oP 'const string Version = "\K[^"]+' src/Program.cs)
SDK=$(dotnet --version)

python3 - "$AUS" "$VERSION" "$SDK" <<'PY'
import json, subprocess, sys, uuid, datetime, os

aus, version, sdk = sys.argv[1], sys.argv[2], sys.argv[3]
assets = json.load(open('obj/project.assets.json'))

# Alle Pakete aus allen Zielen, ohne Dubletten.
pakete = {}
for ziel in assets.get('targets', {}).values():
    for name_version in ziel:
        name, _, v = name_version.partition('/')
        pakete[(name, v)] = None

komponenten = [{
    "type": "framework",
    "name": "Microsoft.NETCore.App",
    "version": sdk,
    "purl": f"pkg:nuget/Microsoft.NETCore.App@{sdk}",
    "description": "Laufzeit und Basisbibliothek, statisch in das Binary uebersetzt",
    "licenses": [{"license": {"id": "MIT"}}],
}, {
    "type": "framework",
    "name": "Microsoft.AspNetCore.App",
    "version": sdk,
    "purl": f"pkg:nuget/Microsoft.AspNetCore.App@{sdk}",
    "description": "Kestrel als HTTP-Server fuer Weboberflaeche und Schnittstelle",
    "licenses": [{"license": {"id": "MIT"}}],
}]

for (name, v) in sorted(pakete):
    komponenten.append({
        "type": "library",
        "name": name,
        "version": v,
        "purl": f"pkg:nuget/{name}@{v}",
        "scope": "excluded",          # nur zur Bauzeit, nicht im Erzeugnis
        "description": "Werkzeug der Uebersetzung, nicht Bestandteil des Binarys",
        "licenses": [{"license": {"id": "MIT"}}],
    })

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        "component": {
            "type": "application",
            "bom-ref": f"schleuse@{version}",
            "name": "schleuse",
            "version": version,
            "description": "Reverse-Tunnel fuer Linux-Geraete mit Relay, Selbstanmeldung und Verwaltung",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        "tools": {"components": [{"type": "application", "name": "scripts/sbom.sh", "version": "1"}]},
    },
    "components": komponenten,
}
json.dump(bom, open(aus, 'w'), indent=2, ensure_ascii=False)
print(f"{aus}: {len(komponenten)} Bestandteile")
PY
