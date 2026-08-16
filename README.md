# cgdns

A carrier-grade recursive DNS resolver in Go, with per-subscriber policy and
anycast health management.

The recursion engine is its own — it walks the delegation chain from the root
rather than wrapping Unbound, BIND or PowerDNS.

## What it does

- **Recursion** — delegation walk from the root, QNAME minimisation (RFC 9156),
  0x20 mixed-case encoding, strict bailiwick checking. Forwarding mode is also
  available.
- **DNSSEC validation** — full chain of trust, NSEC and NSEC3 denial of
  existence, IANA root anchors embedded. A broken chain is SERVFAIL with an
  RFC 8914 extended error, never a silent downgrade. `AD` is set only on a chain
  this resolver verified itself.
- **Transports** — UDP, TCP, DoT (RFC 7858) and DoH (RFC 8484 over HTTP/2), all
  dual-stack.
- **Subscriber policy** — RPZ and domain-list feed ingest, per-class rule sets,
  and per-subscriber allow/block overrides that take precedence over shared
  feeds.
- **Anycast health** — the node decides whether it belongs in the anycast set
  and drives GoBGP over gRPC. Withdrawal is fast, re-advertisement is dampened.

## Design constraints

A few rules the code holds to, because they are the ones that bite in
production:

- **The query path does no I/O beyond resolution.** Policy and subscriber
  lookups are lock-free reads of atomically swapped structures.
- **Nothing trusts a server beyond its authority.** Out-of-bailiwick glue is
  discarded rather than distrusted; a referral must move toward the QNAME and
  stay inside the referring zone.
- **Budgets are load-bearing.** A wall-clock budget, a delegation depth cap and
  an outbound query cap bound every client query — the last is what stops one
  query becoming an amplification lever.
- **IPv6 is not optional.** Every listener and every outbound path is
  dual-stack, and the test suite runs both families.
- **Subscriber privacy.** Full QNAMEs are never logged or used as metric labels
  above debug level.

## Building

```sh
make build          # ./bin/cgdns
make check          # gofmt + vet + tests
make race           # tests under -race
make bench          # hot-path benchmarks
```

Go 1.26 or newer.

## Running

```sh
./bin/cgdns -config deploy/dev/cgdns-recursive.yaml -check   # validate config
./bin/cgdns -config deploy/dev/cgdns-recursive.yaml
```

Configuration is a single YAML file, validated in full at startup: a bad config
fails the boot rather than starting a resolver that behaves differently to the
one the operator described.

See `deploy/systemd/cgdns.service` for a hardened unit. It uses ambient
capabilities rather than `setcap`, so binding port 53 survives an upgrade
replacing the binary.

## Status

Working and deployed in a lab: recursion, DNSSEC, all four transports, policy,
and health-driven anycast with BGP failover.

Not yet built: the node-pair link (config replication and cache sharing between
the two resolvers in a POP), the operator CLI, the management API and WebUI,
packaging, and DoQ.

## Licence

Not yet chosen.
