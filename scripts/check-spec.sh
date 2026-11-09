#!/bin/sh
# Fails when internal/spec/testdata is not what the pinned spec commit holds.
#
#   SPEC_DIR=spec sh scripts/check-spec.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
out=$root/internal/spec/testdata
want=$(cat "$out/SPEC_COMMIT")
got=$(git -C "$spec" rev-parse HEAD)
test "$want" = "$got" || { echo "testdata is from $want, the spec checkout is $got" >&2; exit 1; }
diff -u "$spec/vectors/tokens.json" "$out/tokens.json"
diff -u "$spec/vectors/jwks.json" "$out/jwks.json"
diff -u "$spec/vectors/cauthy-key.json" "$out/cauthy-key.json"
diff -u "$spec/protocol/routes.yaml" "$out/routes.yaml"
echo "testdata matches cauthy-sdk-spec $want"
