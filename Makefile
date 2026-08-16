SHELL := /bin/bash
GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
BIN := bin

.PHONY: all
all: build

.PHONY: build
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/cgdns ./cmd/cgdns

.PHONY: test
test:
	$(GO) test ./...

# Race is mandatory before merging: this is a heavily concurrent daemon and a
# data race that only shows under production load is not something you want to
# find under production load.
.PHONY: race
race:
	$(GO) test -race -count=1 ./...

.PHONY: integration
integration:
	$(GO) test -tags=integration ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: fmtcheck
fmtcheck:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: vuln
vuln:
	govulncheck ./...

# Hot-path benchmarks. Compare against main before merging any resolver or
# cache change — see CLAUDE.md.
.PHONY: bench
bench:
	$(GO) test -run=XXX -bench=. -benchmem ./internal/resolver/... ./internal/cache/... ./internal/prefixmap/...

.PHONY: check
check: fmtcheck vet test

.PHONY: run
run: build
	./$(BIN)/cgdns -config deploy/dev/cgdns.yaml -log-level=debug

.PHONY: checkconfig
checkconfig: build
	./$(BIN)/cgdns -config deploy/dev/cgdns.yaml -check

.PHONY: clean
clean:
	rm -rf $(BIN) dist run
