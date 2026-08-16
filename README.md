# cgdns

Carrier-grade recursive DNS resolver. Anycast-served, DNSSEC-validating, with per-subscriber policy.

The recursion engine is its own - it walks the delegation chain from the root rather than wrapping Unbound, BIND or PowerDNS.

..before you say it, I know per-subscriber policy doesn't sound very carrier, and it isn't until some sales guy somewhere sells someone that "filtered DNS product" that we have.. now its just an ACL. You don't have to use it, and you probably won't... until you do.

## Side note

I don't want this to be a repo/product that gets lots of feature ideas from the home labbers, its recursive DNS at carrier scale.. lets just make it fast as f*ck, simple to spin up, easy to pull telemetry out of and bug free?

## LOUIS

Louis read this before you comment. [[docs/LOUIS.md]]

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

**Pair link** - one mutually authenticated TLS connection between the two nodes in a POP, carrying two payloads with deliberately different guarantees. Config replication is reliable and converging: writes are acknowledged and any gap is repaired by an anti-entropy exchange when the link returns, so a change made while the sibling was down lands when it rejoins. Cache sharing is best-effort, because losing a push is a cache miss the sibling resolves for itself and that is never worth blocking a query for. There is no quorum and nothing to lose: a partitioned pair keeps resolving on both sides, and the link reconnects on its own.

**Config replication** - write to either node and both converge. Last-write-wins ordered by a Lamport counter with the node ID as tiebreak, so the two agree without depending on synchronised clocks. Deletes are tombstones held for seven days - without them, a node that was down during a delete resurrects the record on rejoin, because from its side the record simply still exists. `cgdnsctl drift` compares the store hash across the pair; that hash is the only drift detector a pair has, so it is the thing to alert on.

**Cache sharing** - push on fill to keep the sibling hot, pull on miss before going upstream, TTLs decremented in transit so a shared entry never outlives its own expiry. The pull is bounded by `peer.fetch_timeout` (150 ms by default): going upstream costs tens of milliseconds, so waiting longer than that for a sibling makes the pair link a pessimisation. A peer that is slow, gone or wrong is indistinguishable from a cache miss - the resolver just proceeds upstream, which is what it would have done without a pair at all. Entries arriving *from* the peer are never offered back, which is what stops a push loop. POP-local only, for the reason above.

**Management API** - REST, bound only to the management addresses, behind a default-deny source ACL enforced at accept, TLS mandatory unless every listener is loopback. Tokens carry read/write/admin scopes and are stored as a hash, so replicating them to the sibling - which is what lets you manage the pair from either node - never moves a secret. A node holding no token at all mints one to a root-only file; a node that already has one, including one adopted from its sibling, never does. Records are canonicalised on write, so what the API returns is what the resolver is actually enforcing.

**`cgdnsctl`** - operator CLI, and a plain client of that API with no privileged state of its own, so anything it does your provisioning system can do over HTTP. Because the pair replicates its control plane, pointing it at either node is equivalent - that is the "manage from any node" behaviour, achieved by replication rather than by a cluster-wide API.

## Not yet implemented

| | Status |
|---|---|
| WebUI | The API it sits on is done. The UI is not, and it needs local users and TOTP - unlike API tokens, human passwords want a slow KDF. |
| Packaging | `.deb` / `.rpm` via nfpm. |
| `resolver.outbound_source` | Egress source address is currently whatever the route picks. |
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
- The pair link requires mutual TLS with a CA - the sibling is trusted to insert
  into this node's cache, so an unauthenticated peer could poison it.
- `peer.fetch_timeout` may not exceed `resolver.query_timeout`, because asking
  the sibling would then cost more than just resolving upstream.

See `deploy/dev/` for worked examples.

## Building and running

Go 1.26 or newer.

```sh
make build                                              # ./bin/cgdns, ./bin/cgdnsctl
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

## Operating a pair

`cgdnsctl` reads its token from `-token`, `CGDNS_TOKEN`, or `-token-file`
(default `/var/lib/cgdns/bootstrap.token`), so on the node itself it needs no
configuration. A bare `host:port` is HTTPS - defaulting to plaintext would put
the token on the wire in the clear the first time someone left the scheme off.

```sh
cgdnsctl status                                  # health, pair link, store hash
cgdnsctl subscriber set '{"prefix":"203.0.113.0/24","id":"acme","class":"filtered"}'
cgdnsctl allow acme example.com                  # per-subscriber whitelist
cgdnsctl token create provisioning write         # shown once, never recoverable
cgdnsctl drift ns1.pop:8443 ns2.pop:8443         # do the two nodes agree?
```

Write to either node; the sibling converges. `drift` exits non-zero when the
nodes disagree, so it drives monitoring directly - and it refuses to report "in
step" when fewer than two nodes answered, because one node agreeing with itself
proves nothing during exactly the outage you built the check for.

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
| `cgdns_peer_outbound_up` / `_inbound_up` | 0 means the pair is split and each node is on its own |
| `cgdns_peer_cache_fetch_hits_total` | work the sibling saved this node |

The store hash is not a metric - compare it with `cgdnsctl drift`, and alert on
a disagreement that persists past a sync interval. A brief difference just means
a write has not propagated yet.

## Licence

Not yet chosen.
