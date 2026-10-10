#!/bin/sh
# Compile logsentry en WebAssembly et prépare le dossier web/ pour la mise en ligne.
# Usage : sh web/build.sh
set -e
cd "$(dirname "$0")/.."
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/logsentry.wasm .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
mkdir -p web/samples
cp testdata/auth.log testdata/access.log web/samples/
echo "web/ prêt : $(du -h web/logsentry.wasm | cut -f1) de WebAssembly"
