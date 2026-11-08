# Every check CI runs, runnable on a laptop. SPEC_DIR is a cauthy-sdk-spec
# checkout (default ../cauthy-sdk-spec) at the pinned commit (2f79a74fef1e1f31e72fd359ae7d96c32dbc7e28, conformance/v0.3.0).
SPEC_DIR ?= ../cauthy-sdk-spec
MODULES := . ./examples/acme-crm ./gin ./echo ./fiber ./internal/pgtest
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: all fmt vet lint vulncheck test vectors spec conformance tidy pgtest

all: fmt vet lint vulncheck test vectors conformance

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }

vet:
	@for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

lint:
	@for m in $(MODULES); do (cd $$m && go run $(STATICCHECK) ./...) || exit 1; done

# No module ships with a known advisory, called or not.
vulncheck:
	@for m in $(MODULES); do (cd $$m && go run $(GOVULNCHECK) -scan module) || exit 1; done

# internal/pgtest skips without CAUTHY_TEST_POSTGRES_DSN (see pgtest).
test:
	@for m in $(MODULES); do (cd $$m && go test -race -count=1 ./...) || exit 1; done

# The last lines only, and the tests' own exit status: a pipe into tail would
# hide a failure (and make 3.81 has no .SHELLFLAGS for pipefail).
vectors:
	@out=$$(go test -count=1 -run 'TestVectors|TestEveryRouteOfTheTableIsServed' -v . 2>&1); status=$$?; printf '%s\n' "$$out" | tail -3; exit $$status

spec:
	SPEC_DIR=$(SPEC_DIR) sh scripts/check-spec.sh

conformance:
	SPEC_DIR=$(SPEC_DIR) LEVEL=switches sh scripts/conformance.sh

tidy:
	@for m in $(MODULES); do (cd $$m && go mod tidy) || exit 1; done

# The Postgres key store on a real Postgres; skipped without
# CAUTHY_TEST_POSTGRES_DSN (CI's postgres job sets it).
pgtest:
	cd internal/pgtest && go vet ./... && go test -race -count=1 ./...
