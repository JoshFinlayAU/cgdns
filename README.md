# cgdns

Carrier-grade recursive DNS resolver. Anycast-served, DNSSEC-validating, with per-subscriber policy.

The recursion engine is its own - it walks the delegation chain from the root rather than wrapping Unbound, BIND or PowerDNS.

## Deployment model

Two resolvers per POP, each announce their anycast IP.

```
POP (per state / region)

  ns1 ──────── pair link ──────── ns2        config replication + cache sync
   │                               │
   └── eBGP /30 ── router ── eBGP ─┘         each announces the anycast /32 + /128
```

Subscribers are handed the anycast addresses; BGP routes them to the nearest POP. A node that fails withdraws its prefix and traffic moves to its pair, or to the next POP if both are gone.

**Cache is shared only within a POP, never between them.** CDN and cloud resolvers return geographically specific answers based on where the *resolver* sits, so replicating a Sydney cache entry to Perth would hand Perth subscribers Sydney endpoints. This is a correctness constraint as much as it realistically is a performance choice.

### Interfaces per node

| Interface | Carries |
|---|---|
| management | operator API, metrics, SSH |
| pair link | config replication and cache sharing to the sibling node |
| p2p /30 | eBGP session to the nearest BGP router (to announce its loopback) |
| `anycast0` | the shared service address - DNS listeners bind here (read below) |
| `loopback0` | unique per node - this is where the anycast address lives that we announce |

The anycast0 dummy interface was a trial by fire decision that was settled on to work in basically the same way and reason that "nameserver 127.0.0.53" does in most Linux distros these days. We just need somewhere to bind to that never goes down (and that is not attached to anything and is never gonna ARP), then we let the kernel do the routing from there on.

## Implemented

**Recursion** - delegation walk from the root. QNAME minimisation (RFC 9156) and 0x20 mixed-case encoding on by default, both with config escape hatches. Strict jurisdiction checking: out-of-jurisdiction glue is discarded, and a referral must stay inside the referring zone *and* move toward the QNAME. Forwarding mode is available behind the same interface. Per-nameserver RTT and health drive server selection.

**DNSSEC validation** - full chain of trust with IANA root anchors embedded. NSEC and NSEC3 denial of existence, NSEC3 iteration limits per RFC 9276. A broken chain is SERVFAIL with an RFC 8914 extended error; there is no silent downgrade. A stripped DS is *bogus*, not insecure - an unproven insecure delegation is a downgrade attack. `AD` is set only on a chain verified locally.

**Transports** - UDP, TCP, DoT (RFC 7858), DoH (RFC 8484 over HTTP/2). All dual-stack. UDP uses `SO_REUSEPORT` per-address sockets so replies leave with the correct anycast source. DoH ignores forwarding headers unless the peer is a configured trusted proxy, because the client address selects subscriber policy.

**Subscriber policy** - RPZ zones and plain domain lists, compiled per subscriber class with specificity-ordered matching. Per-subscriber allow and block overrides take precedence over shared class feeds, so one customer can be unblocked without editing a feed you may not own. Blocked answers carry EDE 15 so clients can distinguish policy from a genuine NXDOMAIN. A feed that fails to load leaves the previous rules serving - filtering goes stale, resolution does not.

**Anycast health** - the node owns the decision on whether it belongs in the anycast set, and drives GoBGP (it just made sense.. go project.. gRPC..) over its gRPC API. `gobgpd` runs as a separate unit; cgdns never shells out to a CLI and never embeds BGP in-process, so a resolver restart does not drop the session. Checks run through the real serving path. Withdrawal is fast; re-advertisement is dampened, and the penalty decays on stable serving time rather than on recovery. SIGTERM withdraws before the
listeners stop, so a planned restart moves traffic away first.

## Not yet implemented

| | Status |
|---|---|
| **Pair link** | Config replication semantics exist (`internal/control`: last-write-wins with Lamport ordering, tombstones, anti-entropy digests, drift hash). The wire protocol does not. |
| **Cache synchronisation** | Designed, not built. Push on fill to keep the sibling hot, pull on miss before going upstream, TTL decremented in transit. POP-local only. |
| `cgdnsctl` | Operator CLI. |
| Management API / WebUI | Operator-only, manageable from either node in a pair. |
| Packaging | `.deb` / `.rpm` via nfpm. |
| DoQ | RFC 9250. |
| Serve-stale, aggressive NSEC, prefetch, RRL | RFC 8767 / RFC 8198. RRL matters most - random-subdomain floods are what carriers actually get hit with. |

## Design constraints

- **The query path does no I/O beyond resolution.** Policy and subscriber
  lookups are lock-free reads of atomically swapped structures. A policy push
  never pauses resolution.
- **Budgets bound every query.** Wall clock, delegation depth, and a total
  outbound query cap - the last is what stops one client query becoming an
  amplification lever.
- **Nothing trusts a server beyond its authority.** See jurisdiction handling.
- **IPv6 is not optional.** Every listener and outbound path is dual-stack, and
  the test suite runs both families with no skips.
- **Subscriber privacy.** Full QNAMEs never appear in logs or metric labels
  above debug level; log lines carry the registrable domain.
- **Fail loudly at startup.** Config is validated in full and every socket bound
  before the daemon reports ready. A resolver that starts half-configured is
  worse than one that does not start, because anycast routes traffic to it
  regardless.

## Performance

Measured on a Xeon Gold 6140, hot path, zero allocations:

| | |
|---|---|
| Subscriber prefix lookup (v4 / v6) | 3.6 ns / 7.0 ns |
| Cache hit | 344 ns |
| Cache miss | 262 ns |

## Configuration

One struct, one YAML file, validated in full at startup. Notable rules the
validator enforces rather than documents:

- Listen addresses must be explicit. A wildcard bind loses the destination
  address and breaks anycast source selection.
- `listen.allow_query` is default-deny and required. An open recursive resolver
  is an amplification source.
- The management plane may not share a non-loopback address with a DNS
  listener - those are anycast, and the admin plane must not follow an anycast
  route to an arbitrary node.
- Management off loopback requires both TLS and a source ACL.

See `deploy/dev/` for worked examples.

## Building and running

Go 1.26 or newer.

```sh
make build                                              # ./bin/cgdns
make check                                              # fmt, vet, tests
make race                                               # tests under -race
make bench                                              # hot-path benchmarks

./bin/cgdns -config /etc/cgdns/cgdns.yaml -check        # validate and exit
./bin/cgdns -config /etc/cgdns/cgdns.yaml
```

`deploy/systemd/cgdns.service` is a hardened unit. It grants
`CAP_NET_BIND_SERVICE` as an ambient capability rather than via `setcap`:
`NoNewPrivileges` strips file capabilities, and ambient capabilities survive
replacing the binary on upgrade, so deployment needs no `setcap` step.
`StartLimitBurst` caps restart flapping - health dampening lives in process
memory, so a crash loop would otherwise flap the anycast prefix.

## Observability

Prometheus metrics on a separate management address, behind a source ACL. The
series worth alerting on:

| Metric | Meaning |
|---|---|
| `cgdns_anycast_advertised` | 1 when this node is taking traffic |
| `cgdns_anycast_flaps_total` | rising means dampening is escalating |
| `cgdns_dnssec_bogus_total` | broken zone, or an attack |
| `cgdns_recursion_case_mismatch_total` | non-zero means off-path spoofing attempts |
| `cgdns_policy_override_allowed_total` | per-subscriber whitelist hits |

## Licence

Not yet chosen.
