#!/bin/sh
# Runs the auth-bff conformance suite of cauthy-sdk-spec against Acme CRM on
# the in-memory Cauthy (examples/acme-crm/cmd/conformance-target), built on
# this checkout's core and cauthytest (a go.work in .conformance, not the
# published module the example requires). The exit code is the runner's:
# 0 passed and complete, 1 a check failed, 2 usage or setup, 3 incomplete.
#
#   SPEC_DIR=../cauthy-sdk-spec LEVEL=strict sh scripts/conformance.sh
#   SPEC_DIR=../cauthy-sdk-spec LEVEL=switches sh scripts/conformance.sh
#
# The target runs on CAUTHY_KEY alone, issued by its in-memory Cauthy (served
# on CONFORMANCE_CAUTHY_PORT, default the target's port + 1); the runner reads
# the key from CONFORMANCE_KEY (--key-env) and adds the key.* checks. At
# LEVEL=switches the in-memory Cauthy also serves its admin API there and the
# runner flips the tenant's dashboard switches through it.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
level=${LEVEL:-strict}
port=${CONFORMANCE_PORT:-3999}
cauthy_port=${CONFORMANCE_CAUTHY_PORT:-$((port + 1))}
report=${REPORT:-$root/conformance-report.json}

test -f "$spec/protocol/routes.yaml" || { echo "cauthy-sdk-spec not found at $spec (set SPEC_DIR)" >&2; exit 2; }
mkdir -p "$root/.conformance"
runner=$root/.conformance/cauthy-conformance
target=$root/.conformance/conformance-target
work=$root/.conformance/go.work
printf 'go 1.24\n\nuse (\n\t%s\n\t%s\n)\n' "$root" "$root/examples/acme-crm" > "$work"
(cd "$spec/conformance" && GOWORK=off go build -o "$runner" ./cmd/cauthy-conformance) || { echo "could not build the runner" >&2; exit 2; }
(cd "$root/examples/acme-crm" && GOWORK="$work" go build -o "$target" ./cmd/conformance-target) || { echo "could not build the target" >&2; exit 2; }
for p in "$port" "$cauthy_port"; do
  if curl -s -m 2 -o /dev/null "http://localhost:$p/" 2>/dev/null; then
    echo "port $p is in use: stop what listens there or set CONFORMANCE_PORT / CONFORMANCE_CAUTHY_PORT" >&2
    exit 2
  fi
done

# A password made for this run; the target and the runner read it from the environment only.
CONFORMANCE_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
CONFORMANCE_PORT=$port
CONFORMANCE_CAUTHY_PORT=$cauthy_port
export CONFORMANCE_PASSWORD CONFORMANCE_PORT CONFORMANCE_CAUTHY_PORT
switches=""
if [ "$level" = switches ]; then
  # The in-memory Cauthy's admin token, made for this run, like the password.
  CONFORMANCE_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
  export CONFORMANCE_ADMIN_TOKEN
  switches="--cauthy http://127.0.0.1:$cauthy_port --admin-token-env CONFORMANCE_ADMIN_TOKEN --tenant acme --client-id acme-crm"
fi

# The key the target runs on, written by it (0600) and never printed.
CONFORMANCE_KEY_FILE=$root/.conformance/key
rm -f "$CONFORMANCE_KEY_FILE"
export CONFORMANCE_KEY_FILE

"$target" &
pid=$!
trap 'kill $pid 2>/dev/null || true; rm -f "$CONFORMANCE_KEY_FILE"' EXIT INT TERM

i=0
until curl -s -m 1 -o /dev/null "http://localhost:$port/api/auth/session"; do
  i=$((i + 1))
  if [ $i -gt 100 ] || ! kill -0 $pid 2>/dev/null; then
    echo "the target did not start" >&2
    exit 2
  fi
  sleep 0.2
done

test -s "$CONFORMANCE_KEY_FILE" || { echo "the target wrote no key" >&2; exit 2; }
CONFORMANCE_KEY=$(cat "$CONFORMANCE_KEY_FILE")
export CONFORMANCE_KEY

set +e
# $switches is split into its flags on purpose.
# shellcheck disable=SC2086
"$runner" --target "http://localhost:$port/api/auth" --origin "http://localhost:$port" \
  --email member@example.com --level "$level" --table "$spec/protocol/routes.yaml" --json "$report" \
  --key-env CONFORMANCE_KEY $switches
code=$?
set -e
exit $code
