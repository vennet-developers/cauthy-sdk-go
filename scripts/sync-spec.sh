#!/bin/sh
# Copies what the SDK is tested against from a cauthy-sdk-spec checkout into
# internal/spec/testdata, and records the commit. cauthy-key.json is pinned by
# its sha256 in cauthykey/key_test.go too: update the pin with the file. Run it when the spec moves,
# then commit testdata with the code that meets it.
#
#   SPEC_DIR=../cauthy-sdk-spec sh scripts/sync-spec.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
test -f "$spec/protocol/routes.yaml" || { echo "cauthy-sdk-spec not found at $spec (set SPEC_DIR)" >&2; exit 2; }
out=$root/internal/spec/testdata
mkdir -p "$out"
cp "$spec/vectors/tokens.json" "$spec/vectors/jwks.json" "$spec/vectors/cauthy-key.json" "$spec/protocol/routes.yaml" "$out/"
git -C "$spec" rev-parse HEAD > "$out/SPEC_COMMIT"
echo "synced from $(cat "$out/SPEC_COMMIT")"
