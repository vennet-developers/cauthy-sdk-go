# Every check CI runs, runnable on a laptop. SPEC_DIR is a cauthy-sdk-spec
# checkout (default ../cauthy-sdk-spec). Plan 4B extends it to every module.
SPEC_DIR ?= ../cauthy-sdk-spec
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2

.PHONY: all fmt vet lint test vectors spec pgtest

all: fmt vet lint test vectors

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }

vet:
	go vet ./...

lint:
	go run $(STATICCHECK) ./...

test:
	go test -race -count=1 ./...

vectors:
	go test -count=1 -run TestVectors -v . | tail -3

spec:
	SPEC_DIR=$(SPEC_DIR) sh scripts/check-spec.sh

# The Postgres key store on a real Postgres; skipped without
# CAUTHY_TEST_POSTGRES_DSN (CI's postgres job sets it).
pgtest:
	cd internal/pgtest && go vet ./... && go test -race -count=1 ./...
