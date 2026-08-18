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
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/cgdnsctl ./cmd/cgdnsctl
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/cgdns-routed ./cmd/cgdns-routed
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/cgdns-probe ./cmd/cgdns-probe
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/cgdnsdiff ./cmd/cgdnsdiff

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
# Includes the wiring tests, which start the real binary with a real config and
# assert the effect that exists only if a feature is actually connected. Every
# unit test here can pass while a feature does nothing at all — that is how
# prefetch once shipped as a no-op and denial validation as dead code.
integration:
	$(GO) test -tags=integration -count=1 -timeout 15m ./...

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

# nfpm builds both formats in pure Go, so no dpkg-dev or rpmbuild is needed.
# PKG_VERSION must not carry a leading "v" or a "-dirty" suffix: deb and rpm
# both reject them.
PKG_VERSION ?= $(shell v=$$(git describe --tags --abbrev=0 2>/dev/null); [ -n "$$v" ] && echo "$${v#v}" || echo 0.0.0)
PKG_ARCH ?= amd64
DIST := dist

.PHONY: fuzz
# Fuzz every target for a bounded time. Everything on the wire is
# attacker-controlled, so these cover the paths that turn bytes into decisions:
# denial proofs, the aggressive store, feed and hints parsing, and the query
# acceptance path each listener applies before the resolver is involved.
#
# FUZZTIME can be raised for a longer soak; the corpus persists in the build
# cache between runs, so successive runs go deeper.
FUZZTIME ?= 60s
fuzz:
	@set -e; \
	for spec in \
	  "./internal/dnssec/:FuzzDenialProofs" \
	  "./internal/dnssec/:FuzzParseAnchors" \
	  "./internal/aggressive/:FuzzStore" \
	  "./internal/transport/:FuzzQueryAcceptance" \
	  "./internal/transport/:FuzzDoHReadQuery" \
	  "./internal/transport/:FuzzDoHReadBody" \
	  "./internal/policy/:FuzzParseRPZ" \
	  "./internal/policy/:FuzzParseDomainList" \
	  "./internal/resolver/roothints/:FuzzParse" ; do \
	  pkg=$${spec%%:*}; target=$${spec##*:}; \
	  printf '%-28s %s\n' "$$target" "$$pkg"; \
	  go test -run XXX -fuzz "$$target" -fuzztime $(FUZZTIME) "$$pkg" | tail -2 | head -1; \
	done

.PHONY: package
package: build
	@command -v nfpm >/dev/null || { echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	mkdir -p $(DIST)
	PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$(PKG_ARCH) nfpm package -f deploy/nfpm.yaml -p deb -t $(DIST)
	PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$(PKG_ARCH) nfpm package -f deploy/nfpm.yaml -p rpm -t $(DIST)
	@ls -1 $(DIST)

.PHONY: package-clean
package-clean:
	rm -rf $(DIST)
