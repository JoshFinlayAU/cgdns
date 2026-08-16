# Carrier DNS Cluster — software spoke

A carrier grade recursive DNS server with clustering.

Inherits the hub's global rules (see `../../CLAUDE.md`). This file adds spoke-specific context.

## Stack

| Layer | Choice |
|---|---|
| Language | Go (toolchain pinned in `go.mod`; single module, no vendor dir) |
| DNS wire/protocol | `github.com/miekg/dns` — recursion engine is **ours**, natively in Go. No Unbound/BIND/PowerDNS wrapping. |
| Cluster config/policy | Embedded `github.com/hashicorp/raft` (+ `raft-boltdb` for log/stable store) |
| Membership/failure detection | `github.com/hashicorp/memberlist` gossip |
| Transports | UDP + TCP (53), DoT (853, `crypto/tls`), DoH (443, `net/http` HTTP/2, RFC 8484) — all dual-stack IPv4 + IPv6 |
| Security | DNSSEC validation (RFC 4035 + 5155 NSEC3), trust anchor via RFC 5011 rollover |
| Policy | RPZ-style subscriber policy (per-subscriber zones, response rewriting) |
| Deployment | Bare metal / VM · systemd unit · `.deb` + `.rpm` (nfpm) · anycast advertised by FRR or BIRD |
| Metrics/traces | Prometheus `/metrics`, structured logs via `log/slog` |

### Repo layout

```
cmd/cdnsd/          # resolver daemon (the only long-running binary)
cmd/cdnsctl/        # operator CLI: cluster join/leave, policy push, cache ops
internal/resolver/  # recursion: delegation walk, QNAME minimisation, glue handling
internal/cache/     # RRset cache + negative cache + infra/RTT cache
internal/dnssec/    # validator, trust anchors, DS/DNSKEY chain
internal/transport/ # udp, tcp, dot, doh listeners (one file each)
internal/cluster/   # raft FSM, memberlist, leader election, snapshots
internal/policy/    # RPZ ingest, subscriber→policy mapping, rewrite engine
internal/health/    # health scoring that drives BGP advertise/withdraw
deploy/             # systemd units, nfpm.yaml, FRR/BIRD example configs
testdata/           # golden wire captures, RPZ fixtures, signed test zones
```

## How to run / build / test

Run these before claiming a change works.

```bash
# build
go build ./...
go build -trimpath -ldflags "-X main.version=$(git describe --tags --always)" -o bin/cdnsd ./cmd/cdnsd

# unit + race (race is mandatory — this is a heavily concurrent daemon)
go test ./...
go test -race -count=1 ./...

# integration: spins up a 3-node raft/gossip cluster on loopback, no root needed
go test -tags=integration ./internal/cluster/... ./test/e2e/...

# lint + vuln
golangci-lint run ./...
go vet ./...
govulncheck ./...

# hot-path benchmarks — compare against main before merging resolver/cache changes
go test -run=XXX -bench=. -benchmem ./internal/resolver/... ./internal/cache/...
```

### Local single node

```bash
sudo setcap 'cap_net_bind_service=+ep' bin/cdnsd      # or run on 5353 in dev
./bin/cdnsd -config deploy/dev/cdnsd.yaml -log-level=debug
```

### Local 3-node cluster (dev)

```bash
make cluster-up      # 3 cdnsd on 127.0.0.1{1,2,3}, raft bootstrapped, gossip joined
./bin/cdnsctl cluster status
./bin/cdnsctl policy push testdata/rpz/blocklist.rpz --subscriber-class=default
make cluster-down
```

### Query it

```bash
dig @::1 -p 5353 example.com A +dnssec
dig @127.0.0.1 -p 5353 dnssec-failed.org A +dnssec        # must return SERVFAIL, AD unset
kdig @127.0.0.1 +tls-ca +tls-host=resolver.test example.com   # DoT
curl -H 'accept: application/dns-message' \
  'https://127.0.0.1/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'   # DoH
```

### Packaging

```bash
make package          # nfpm → dist/*.deb dist/*.rpm, includes deploy/systemd/cdnsd.service
```

Installing or restarting a package on any shared/lab node touches live state — ask first.

## Conventions

**Resolver hot path**
- Zero allocations per query where achievable. Reuse `dns.Msg` buffers via `sync.Pool`; never retain a pooled message past the handler.
- Every outbound query carries a `context.Context` with a deadline derived from the client's budget. No unbounded waits, ever. Total client budget defaults to 5s; hard cap on delegation depth (16) and total outbound queries per client query (32) to kill loops.
- No `panic` in packet-handling code. Recover at the transport boundary, count it, SERVFAIL, keep serving.
- Never log or metric-label the full QNAME at info level — subscriber privacy. Hash or truncate to the registrable domain.

**DNS correctness**
- Parse defensively: everything on the wire is attacker-controlled. Reject compression loops, oversized RDATA, and malformed EDNS0 before touching resolver logic.
- Cache is strictly bailiwick-checked. Never accept out-of-bailiwick glue or additional records into cache.
- QNAME minimisation (RFC 9156) on by default; 0x20 mixed-case encoding on by default; both need a config escape hatch for broken authoritatives.
- Enforce EDNS0 buffer size 1232 for UDP; set TC and honour TCP fallback correctly. Test both paths.
- DNSSEC failure = SERVFAIL with EDE (RFC 8914) set. Never downgrade to insecure silently. `AD` only when the chain actually validated.
- Every protocol behaviour change references the RFC and section in the commit message and a comment.

**Clustering**
- Raft is the control plane only — config, policy, subscriber mappings, ACLs. **Never** put per-query state, cache, or anything write-heavy through raft.
- The query path must keep serving from last-known-good state when raft has no leader or gossip is partitioned. Loss of quorum degrades management, not resolution. There is a test for this; keep it passing.
- FSM `Apply` must be deterministic and side-effect free apart from state mutation — no I/O, no clocks, no maps iterated in order.
- FSM changes are versioned. Adding a command type requires a snapshot/restore compatibility test against the previous version.
- memberlist tells us who's alive; raft tells us what's true. Don't conflate them.

**Anycast / health**
- `internal/health` owns the single decision "should this node be in the anycast set". FRR/BIRD reads it via the health check script in `deploy/`; the daemon never runs `vtysh` or `birdc` itself.
- Withdrawal must be fast and re-advertisement slow (dampened) — flapping a prefix is worse than one dead node.

**Go style**
- Standard `gofmt`; errors wrapped with `%w` and context ("resolving DS for %s: %w"). Sentinel errors in the package that owns them.
- Interfaces defined by the consumer, not the producer. Keep them small.
- `internal/` is the default; only promote a package to public if something outside the repo genuinely needs it.
- Table-driven tests. New protocol behaviour gets a golden wire-format fixture in `testdata/`.
- Config: one struct, one YAML file, validated fully at startup — fail loudly on bad config rather than defaulting.

**Comments**
- **Don't comment code unless it is absolutely necessary.** No comment is the default. Names carry the meaning — if a block needs explaining, first try renaming it or pulling it into a well-named function. A comment that restates what the code already says is noise, and it rots the moment the code moves.
- "Necessary" means a reader genuinely cannot recover it from the code: a non-obvious **why**, the RFC + section required by the DNS-correctness rules above, a deliberate deviation from the obvious approach, or a real trap that will bite the next person.
- **Never write a comment about the code's own history.** No "previously…", "changed from…", "this used to…", "faster than the old…", no naming an approach this one replaced, no justifying a decision by contrast with the one before it. A comment describes what is true now, as if the code had always been this way. Change belongs in git history and the commit message, not in the source.
- Same rule applies to the RFC references: cite the standard because it constrains the current behaviour, not to narrate how the behaviour got there.

**Git**
- Branches `feat/`, `fix/`, `chore/`; conventional-commit subjects. Small, reviewable commits.
- Don't merge resolver or cache changes without the benchmark comparison in the PR body.

## Gotchas

- **IPv6 is not an afterthought.** Every listener, every outbound path, and every test runs both families. A resolver that only walks the delegation over v4 will silently work in the lab and fail on v6-only auths.
- `net.ListenPacket` on a wildcard address loses the destination IP — use `SO_REUSEPORT` + per-address sockets, or `oob`/`ipv6.PacketConn` control messages, so anycast replies leave from the anycast source. Getting this wrong breaks anycast subtly and only under load.
- Raft snapshots on a large policy set can stall; snapshot thresholds are tuned in config, don't lower them casually.
- DoH behind an L7 proxy loses the client IP — trust the proxy header only from configured trusted sources, otherwise subscriber policy can be spoofed.
- Trust anchor expiry: RFC 5011 state lives on disk. Wiping a node's state dir is not harmless; it re-bootstraps the anchor.
- Root hints and the trust anchor are shipped in the package, but a node that has been down for months will need both refreshed before it validates.

## Notes

- Private memory: `memory/` · Spoke skills: `skills/`
- Confirm before destructive git ops (force-push, reset --hard, branch deletes).

## Installed skills

Reach for these when the task matches — they're installed in `.claude/skills/`:

- **golang-testing** — Production-ready Golang tests — table-driven tests, testify suites and mocks, parallel tests, fuzzing, fixtures, goroutine leak detection with goleak, snapshot testing, code coverage, integration tests, idiomatic test naming. Use when writing or reviewing Go tests, choosing a testing approach, setting up Go test CI, or debugging flaky/slow tests. For testify-specific APIs see `samber/cc-skills-golang@golang-stretchr-testify`; for measurement methodology see `samber/cc-skills-golang@golang-benchmark`.  _(skills.sh: samber/cc-skills-golang)_
- **golang-performance** — Golang performance optimization patterns and methodology - if X bottleneck, then apply Y. Covers allocation reduction, CPU efficiency, memory layout, GC tuning, pooling, caching, and hot-path optimization. Use when profiling or benchmarks have identified a bottleneck and you need the right optimization pattern to fix it. Also use when performing performance code review to suggest improvements or benchmarks that could help identify quick performance gains. Not for measurement methodology (→ See `samber/cc-skills-golang@golang-benchmark` skill) or debugging workflow (→ See `samber/cc-skills-golang@golang-troubleshooting` skill).  _(skills.sh: samber/cc-skills-golang)_
- **golang-benchmark** — Golang benchmarking, profiling, and performance measurement. Use when writing, running, or comparing Go benchmarks, profiling hot paths with pprof, interpreting CPU/memory/trace profiles, analyzing results with benchstat, setting up CI benchmark regression detection, or investigating production performance with Prometheus runtime metrics. Also use when the developer needs deep analysis on a specific performance indicator - this skill provides the measurement methodology, while `samber/cc-skills-golang@golang-performance` provides the optimization patterns.  _(skills.sh: samber/cc-skills-golang)_

