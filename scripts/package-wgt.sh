#!/usr/bin/env bash
# Build an UNSIGNED TizenTubeCobalt.wgt from this fork (Apps2Samsung signs it on install).
# Usage: scripts/package-wgt.sh [outdir]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/release}
VER=$(sed -n 's/.*<widget[^>]* version="\([^"]*\)".*/\1/p' "$ROOT/standalone/config.xml")

(cd "$ROOT/service" && npm install --no-audit --no-fund >/dev/null && npx rollup -c rollup.config.js >/dev/null 2>&1)
# Dependency versions of the official v2.1.1 build (upstream doesn't commit lockfiles).
cp "$ROOT/scripts/standalone-service.package-lock.v2.1.1.json" "$ROOT/standalone/service/package-lock.json"
(cd "$ROOT/standalone/service" && { [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null; } && npm run build >/dev/null)

STAGE=$(mktemp -d)
mkdir -p "$STAGE/service/dist" "$STAGE/service/utils" "$OUT"
cp "$ROOT"/standalone/{config.xml,index.html,icon.png,icon_16b9.png} "$STAGE/"
cp "$ROOT"/standalone/service/{index.js,package.json,package-lock.json,babel.config.json,build-service.js} "$STAGE/service/"
cp "$ROOT"/standalone/service/utils/*.js "$STAGE/service/utils/"
cp "$ROOT"/standalone/service/dist/index.js "$STAGE/service/dist/"
rm -f "$OUT/TizenTubeCobalt-$VER.wgt"
(cd "$STAGE" && zip -q -r -X "$OUT/TizenTubeCobalt-$VER.wgt" .)
rm -rf "$STAGE"
echo "$OUT/TizenTubeCobalt-$VER.wgt"
