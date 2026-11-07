#!/bin/sh
# Runs the auth-bff conformance suite of cauthy-sdk-spec against Acme CRM on
# the in-memory Cauthy (examples/acme-crm/cmd/conformance-target). The exit
# code is the runner's: 0 passed and complete, 1 a check failed, 2 usage or
# setup, 3 incomplete.
#
#   SPEC_DIR=../cauthy-sdk-spec LEVEL=strict sh scripts/conformance.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
level=${LEVEL:-strict}
port=${CONFORMANCE_PORT:-3999}
report=${REPORT:-$root/conformance-report.json}

test -f "$spec/protocol/routes.yaml" || { echo "cauthy-sdk-spec not found at $spec (set SPEC_DIR)" >&2; exit 2; }
mkdir -p "$root/.conformance"
runner=$root/.conformance/cauthy-conformance
target=$root/.conformance/conformance-target
(cd "$spec/conformance" && GOWORK=off go build -o "$runner" ./cmd/cauthy-conformance) || { echo "could not build the runner" >&2; exit 2; }
(cd "$root/examples/acme-crm" && go build -o "$target" ./cmd/conformance-target) || { echo "could not build the target" >&2; exit 2; }
if curl -s -m 2 -o /dev/null "http://localhost:$port/" 2>/dev/null; then
  echo "port $port is in use: stop what listens there or set CONFORMANCE_PORT" >&2
  exit 2
fi

# A password made for this run; the target and the runner read it from the environment only.
CONFORMANCE_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
CONFORMANCE_PORT=$port
export CONFORMANCE_PASSWORD CONFORMANCE_PORT

"$target" &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT INT TERM

i=0
until curl -s -m 1 -o /dev/null "http://localhost:$port/api/auth/session"; do
  i=$((i + 1))
  if [ $i -gt 100 ] || ! kill -0 $pid 2>/dev/null; then
    echo "the target did not start" >&2
    exit 2
  fi
  sleep 0.2
done

set +e
"$runner" --target "http://localhost:$port/api/auth" --origin "http://localhost:$port" \
  --email member@example.com --level "$level" --table "$spec/protocol/routes.yaml" --json "$report"
code=$?
set -e
exit $code
