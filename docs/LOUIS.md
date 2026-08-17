# cgdns — the decision record

*Every significant choice in this project, what else was on the table, and why we
landed where we did. Written to be picked apart.*

---

## How to read this

Each entry follows the same shape:

> **Decision** — what we do.
> **Alternatives** — what else was considered.
> **Why this one** — the reasoning.
> **What it costs** — the honest downside. Every decision has one.
> **Enforced / proven by** — the test, the validator rule, or the lab run that
> keeps it true.

Where a decision was *changed*, the entry says so and says what triggered it.
Where a limitation is *accepted* rather than solved, it is listed as accepted —
[§17, Accepted risk register](#17-accepted-risk-register) collects all of them in
one place so nothing has to be dug out.

Claims of "verified" in this document mean one of three things, and the entry
says which: a unit/integration test in the repo, a live run against the real
internet, or a run on the two-node lab POP.

**Current state, verified at the time of writing:** `go build ./...` clean,
`go test ./...` green across all 22 packages, **zero skipped tests**, 343 test /
benchmark / fuzz functions.

---

## Contents

1. [The shape of the thing](#1-the-shape-of-the-thing)
2. [Foundational choices — language, libraries, engine](#2-foundational-choices--language-libraries-engine)
3. [Deployment architecture — why pairs, not a cluster](#3-deployment-architecture--why-pairs-not-a-cluster)
4. [Anycast, routing and health](#4-anycast-routing-and-health)
5. [The control plane — replication without consensus](#5-the-control-plane--replication-without-consensus)
6. [The pair link](#6-the-pair-link)
7. [Recursion correctness and security](#7-recursion-correctness-and-security)
8. [DNSSEC](#8-dnssec)
9. [Transports](#9-transports)
10. [Subscriber policy and filtering](#10-subscriber-policy-and-filtering)
11. [Rate limiting](#11-rate-limiting)
12. [Serve-stale and prefetch](#12-serve-stale-and-prefetch)
13. [The management plane](#13-the-management-plane)
14. [Configuration philosophy](#14-configuration-philosophy)
15. [Packaging and deployment](#15-packaging-and-deployment)
16. [Performance and the query path](#16-performance-and-the-query-path)
17. [Accepted risk register](#17-accepted-risk-register)
18. [Not built yet, and why that order](#18-not-built-yet-and-why-that-order)
19. [Questions you are going to ask](#19-questions-you-are-going-to-ask)
20. [Decisions still open](#20-decisions-still-open)

---

## 1. The shape of the thing

cgdns is a recursive DNS resolver for a carrier network. One long-running daemon
(`cgdns`), one operator CLI (`cgdnsctl`), one YAML config file, one management
REST API that the CLI and the embedded operator console both sit on.

It is deployed as **two independent nodes per POP**. There are **two anycast
service addresses** — the ns1 address and the ns2 address, which is what a
subscriber receives as their primary and secondary resolver over DHCP/PPPoE.
**Each node announces one of them, and every POP repeats the same pattern.**
There is no cluster spanning POPs and no quorum anywhere. Failure handling is
routing: a sick node withdraws its prefix, and that address is then served by
the node holding the same role in the next-closest POP.

```
POP (BNE, SYD, MEL, …) — every POP identical

  ns1 ──────── pair link ──────── ns2      config replication + POP-local cache sharing
   │                               │
   │  announces ANY-A              │  announces ANY-B
   │  (/32 + /128)                 │  (/32 + /128)
   │                               │
   └── eBGP /30 ── router ── eBGP ─┘

  Subscriber gets:  primary = ANY-A,  secondary = ANY-B

Between POPs: nothing at all.
```

**Why one address each rather than both on both.** A subscriber's primary and
secondary then always resolve to **different physical machines**. A node-level
fault that is not a full failure — a bad build, a policy bug, a wedged process
still passing its own health checks — cannot take out both of a subscriber's
configured resolvers at once. Putting both addresses on both nodes would allow
the router to land both on the same box, which quietly turns two configured
resolvers into one point of failure.

**What it costs, and this is the trade to be clear about.** A single node
failure is **not** absorbed inside the POP. When BNE ns1 withdraws ANY-A, BNE
subscribers' *primary* is served by SYD ns1 — a cross-state path — while their
secondary stays local on BNE ns2. So a single node loss means: added latency on
one of the subscriber's two resolvers, and the remote same-role node carrying
two states' primary load until the local node returns. That is the accepted
price of never having both addresses on one box.

Everything else in this document is a consequence of that shape, or of the rule
that **the query path must keep serving when every other part of the system is
broken**.

---

## 2. Foundational choices — language, libraries, engine

### 2.1 We wrote our own recursion engine rather than wrapping Unbound, BIND, Knot Resolver or PowerDNS

**Decision.** `internal/resolver` walks the delegation chain from the root
itself: it asks a root server, follows referrals, handles glue, chases CNAMEs,
and validates DNSSEC — all in our process.

**Alternatives considered.**

| Option | Why not |
|---|---|
| Wrap **Unbound** in a supervisor and drive its control socket | The product's value is per-subscriber policy, pair replication and the anycast health decision. All three would become "shell out and hope": policy via generated config files and a reload, health via parsing `unbound-control stats`, cache sharing not possible at all. Unbound's cache is not addressable from outside the process. |
| Wrap **BIND 9** | Same problem, plus a much larger attack surface and a config language we would be generating rather than validating. |
| **PowerDNS Recursor** with Lua policy hooks | The closest fit — Lua hooks could express per-subscriber policy. Rejected because it puts a scripting language on the hot path of a carrier resolver, and because the deployment story becomes "our daemon plus their daemon plus a Lua bundle", with two failure domains to reason about during an incident. |
| **Knot Resolver** with its module system | Same shape of objection as PowerDNS, smaller operator community here. |

**Why this one.** Three things we need are *inside* the resolver, not beside it:

1. **Per-subscriber policy on the query path with zero I/O.** Our enforcer reads
   an atomically-swapped in-memory structure. A wrapped resolver would need a
   config regeneration and reload per policy change, on a box taking production
   traffic.
2. **Cache sharing between the pair.** `internal/peer` pushes a filled RRset to
   the sibling and pulls on a miss. That requires addressing the cache directly.
3. **The health decision.** `internal/health` probes through the *real serving
   path* — the same handler chain a subscriber's query traverses — and that
   result is what drives BGP. Probing a third-party daemon over a control socket
   tests the control socket.

**What it costs.** This is the single most expensive decision in the project. We
now own DNS correctness: bailiwick rules, EDNS negotiation, TCP fallback, CNAME
chasing, DNSSEC chain building, NSEC/NSEC3 proofs. Unbound has had two decades
of hostile input; we have not. This is why §7 and §8 are as long as they are,
why every protocol behaviour cites its RFC section in the source, and why
security invariants have named regression tests rather than being "handled".

**Enforced / proven by.** `internal/resolver` and `internal/dnssec` carry the
largest test surface in the repo. Verified live against the real root servers
(cold 1.1 s, warm 156 ms, cross-TLD CNAME chains, glueless delegations, NXDOMAIN
with SOA, both address families) and against `dnssec-failed.org` (SERVFAIL, EDE
9, `AD` unset).

### 2.2 Go

**Decision.** Go 1.26, single module, no vendor directory, no cgo.

**Alternatives.** C or C++ (what the incumbents use), Rust.

**Why this one.** A resolver is an exercise in bounded concurrency over
untrusted input. Go gives us goroutine-per-query cheaply, `context` deadlines
that thread the client's wall-clock budget through every outbound query for
free, memory safety on parsing attacker-controlled packets, and a static binary
that packages trivially. `-race` in CI is a real safety net for a daemon this
concurrent. Rust would give better tail latency and the same safety; it would
also mean a smaller pool of people here who can maintain it, and the GC has not
shown up as a problem at the volumes measured.

**What it costs.** GC pauses are a real risk at very high query rates. The
answer is not to change language but to not allocate: the hot path is
zero-allocation, buffers come from a `sync.Pool`, and cache keys are comparable
structs so a map lookup needs no string concatenation. Measured numbers are in
§16.

### 2.3 `github.com/miekg/dns` for wire format only

**Decision.** We use miekg/dns for packing/unpacking messages, RR types, name
compression and signature verification primitives. We do **not** use its
`dns.Server` or any resolution helper.

**Why.** It is the de-facto Go DNS library, well tested on parsing, and reusing
it for the wire format means our peer link can encode a cache entry as a DNS
message rather than inventing a format (§6.4). Our own listeners exist because
we need `SO_REUSEPORT` per-address sockets, bounded worker pools, an ACL
enforced before any work, and per-query budgets — none of which its server
gives us.

### 2.4 Dependency list is deliberately short

`go.mod` direct dependencies, in full:

| Dependency | For | Why not something else |
|---|---|---|
| `miekg/dns` | DNS wire format | See above |
| `osrg/gobgp/v4` | BGP advertise/withdraw over gRPC | §4.3 |
| `golang.org/x/crypto` | argon2id | Standard library has no argon2 |
| `golang.org/x/net` | HTTP/2 for DoH | |
| `golang.org/x/sys` | `SO_REUSEPORT` | |
| `golang.org/x/term` | Password prompt in `cgdnsctl` | So a password is never a shell argument |
| `google.golang.org/grpc` | Transport for the gobgp client | |
| `gopkg.in/yaml.v3` | Config parsing | Needed for `KnownFields(true)` — §14.1 |

There is no web framework, no ORM, no logging library (stdlib `log/slog`), no
metrics client library (the Prometheus exposition format is written directly in
`internal/metrics`), and no test framework beyond stdlib `testing`. Every
dependency is a thing we would otherwise have to write and get wrong; nothing is
there for convenience.

---

## 3. Deployment architecture — why pairs, not a cluster

### 3.1 Two independent nodes per POP; no cross-POP cluster

**Decision.** Each POP holds ns1 and ns2. They share config and cache with each
other. They share **nothing** with any other POP. There is no VIP between them,
no primary, no quorum.

**Alternatives considered.**

- **One cluster spanning all POPs**, with consensus on config and a globally
  shared cache. This was the original assumption in the project spec, and it was
  abandoned on 2026-08-16.
- **A VIP inside each POP** with keepalived/VRRP, so one node is active.
- **N-node clusters per POP** (3 or 5), so quorum survives a single loss.

**Why this one.**

*Against a global cluster:* it makes every POP's control plane depend on WAN
links between POPs. A partition between Brisbane and Perth would then be a
management-plane outage in both, for no operational benefit — the two POPs do
not need to agree about anything in real time. Worse, it invites a shared cache,
which is a correctness bug (§3.2).

*Against a VIP:* a VIP inside a POP solves a problem anycast already solves, and
introduces a second failover mechanism with its own split-brain modes. With
anycast, both nodes are active and a failure is a routing event.

*Against 3+ nodes per POP:* two nodes per POP is what the traffic needs, and
adding a third purely so a consensus protocol has a quorum is letting the
software dictate the rack layout.

**What it costs.** No POP can be authoritative about another POP's state. If a
provisioning push reaches Sydney and not Melbourne, nothing in the system
notices automatically — which is exactly why `cgdnsctl drift` and the store hash
exist (§5.4), and why they are the thing to alert on.

**Failure behaviour, stated plainly.**

| Failure | What happens |
|---|---|
| One node (say BNE ns1) | ANY-A withdraws from BNE. Subscribers' primary is served by SYD ns1; their secondary stays local on BNE ns2. Added latency on one of their two resolvers; SYD ns1 carries two states' primary load |
| Both nodes in a POP | Both addresses withdraw. Every subscriber of that POP is served by the next-closest POP, on both resolvers |
| A whole POP dark (power, transit) | Same as above — BGP withdraws and subscribers route to the next-closest POP |

None of these is an outage. They are latency changes and load shifts, and that
is the accepted design.

### 3.2 Cache is shared within a POP and never between POPs

**Decision.** `internal/peer` shares cache entries between ns1 and ns2 only.

**Why — and this is a correctness argument, not a performance preference.** CDN
and cloud authoritatives (Cloudflare, Akamai, Google) return geographically
specific answers based on where the *resolver* sits. A `www.example.com` filled
in Sydney holds Sydney-region endpoints. Replicating that entry to Perth would
hand Perth subscribers Sydney endpoints for as long as the TTL lasts. That is
not a slow answer, it is a wrong one, and it would be invisible in every metric
we have.

**What it costs.** Each POP pays its own cache-fill cost. Accepted.

**Enforced by.** Architectural — there is no code path that carries a cache
entry off-POP. The pair link is point-to-point between two configured addresses
(`peer.listen` / `peer.remote`), so there is nowhere else for an entry to go.

### 3.3 Raft and memberlist were built, then deleted

**Decision.** `internal/cluster` — an embedded HashiCorp raft FSM with
raft-boltdb, plus memberlist gossip, roughly 830 lines, working and tested — was
removed on 2026-08-16.

**Why.** A two-node raft has a quorum of 2 of 2. A single node failure freezes
the control plane completely. That is **strictly worse than having no consensus
protocol at all**, because with LWW replication a surviving node keeps accepting
writes and reconciles on rejoin. Raft was solving a problem the architecture no
longer had.

**What replaced it.** `internal/control` keeps the record types and the
publisher; replication became last-write-wins with tombstones (§5).

**What it costs.** We gave up linearisable writes. The cost is a real, named,
accepted limitation — see §5.5.

**Note for the archive.** The raft implementation is shelved rather than lost.
If a cross-site *management* cluster is ever wanted (which would be a different
thing from a resolution cluster), it is a starting point.

### 3.4 Two loopback interfaces per node, and a `dummy` device for anycast

**Decision.** Each node carries:

| Interface | Role |
|---|---|
| `anycast0` (a netplan dummy device) | **this node's** anycast /32 + /128 — ANY-A on ns1, ANY-B on ns2. DNS listeners bind here |
| `loopback0` | unique per node — outbound recursion sources from here |
| pair VLAN | pair link + management API |
| p2p /30 | eBGP session to the nearest router, nothing else |

**Why two loopbacks.** If outbound recursion sourced from the *anycast* address,
the authoritative's reply would be routed to whichever node the return path
picks — and since every POP announces that same address from its own same-role
node, the reply can land on **a different POP's node entirely**, which has no
matching outstanding query. That produces intermittent, load-dependent failures
that only appear in production. Sourcing from a unique per-node address makes
replies come home, and gives upstream filters a single address to permit.

### 3.4a Where the lab differs from the production model — stated, not glossed

**The lab runs a single shared anycast address, on both nodes.** `deploy/lab/ns1.yaml`
and `ns2.yaml` are byte-identical in their listeners:

```yaml
listen:
  # The anycast address, identical on both nodes.
  udp:
    - "10.255.0.53:53"
    - "[fd51:13:53::53]:53"
```

That is **not** the two-address model in §1. It was built to prove recursion,
DNSSEC validation, health-driven withdraw/advertise, anycast failover and the
pair link — all of which it proved. But the failover it demonstrated was
*within* the POP (withdrawing ns1 moved the router's active gateway to ns2 for
the same address), which is precisely the behaviour the production model does
**not** have.

**What this means concretely:** the properties in §1 that follow from one address
per node — a subscriber's two resolvers never landing on one box, and a single
node failure moving one address to the next POP — have been reasoned about but
**not exercised end to end.** Two things need proving before the first
production POP:

1. A second anycast address, with each node announcing only its own, and the
   router selecting correctly for both.
2. That withdrawing one node moves *only* its address, out of the POP, while the
   sibling's address stays put and keeps serving.

Nothing in the daemon blocks this — `health.anycast_prefixes` is a list and each
node reads its own config — but "nothing blocks it" is not the same as "it has
been run".

**Why a `dummy` device and not `lo`.** We need an address that never goes down,
is not attached to a physical link, and never ARPs — the same trick
`127.0.0.53` plays in modern Linux distributions. Putting it on a dummy device
rather than `lo` keeps it addressable and manageable without touching loopback,
and keeps `lo` semantics untouched. This was arrived at by trial in the lab.

**Related constraint.** The v6 anycast address stays ULA (`fd51:13:53::53`) in
the lab. A public v6 /128 taken out of the connected `2402:3820:1194::/64` would
sit inside a connected subnet, so the router would attempt neighbour discovery
for it on the wrong interface. A public v6 anycast address needs a separately
routed prefix.

**Enforced by.** `resolver.outbound_source_v4` / `_v6` are validated to *not* be
inside `health.anycast_prefixes`, and an address this node cannot bind fails at
**startup** rather than failing every query later
(`internal/config/config.go:938-965`). Lab-verified by packet capture on ns2: v4
left from `10.255.0.2`, v6 from `fd51:13::2`, source ports varying, 0x20
randomisation intact.

---

## 4. Anycast, routing and health

### 4.1 One component owns the advertise/withdraw decision

**Decision.** `internal/health` is the only thing in the system that decides
whether this node belongs in the anycast set.

**Why.** If two components could independently withdraw or advertise, the node's
routing state becomes a function of several opinions, and the failure mode of
that is a prefix flapping between two components disagreeing. Concentrating it
means there is one place to read, one place to test, and one metric
(`cgdns_anycast_advertised`) that is the truth.

### 4.2 Health checks run through the real serving path

**Decision.** Checks call the handler chain a subscriber's query would traverse
(`health.RootCheck(handler, probeClient)` in `cmd/cgdns/main.go:419`), not a
private code path.

**Why.** A probe that tests a private code path proves the probe works. This is
not theoretical: the health check as written **found a real resolver bug**.
Probing `. NS` cached the root NS RRset from the answer section, but the root
server addresses arrive in the *additional* section and were not being cached.
`bestDelegation` then returned an address-less delegation instead of falling
back to root hints, and the next `DNSKEY .` fetch tried to resolve
`a.root-servers.net` — which needs the root — and nested until the budget died.

**Fixed two ways:** a cached delegation is only usable if some nameserver has a
known address (`hasAddress`, `internal/resolver/recursive.go:685-710`), and
in-bailiwick addresses from an answer's additional section are now cached.
Regression test: `TestRecursive_AddresslessDelegationFallsBackToHints`.

### 4.3 GoBGP, driven over gRPC, running as a separate systemd unit

**Decision.** `gobgpd` is its own service. cgdns talks to it over its gRPC API.
cgdns never shells out to the `gobgp` CLI, and never embeds a BGP speaker
in-process.

**Alternatives.**

| Option | Why not |
|---|---|
| **Embed BGP in cgdns** (gobgp as a library) | Every cgdns restart — including a routine upgrade — would drop the BGP session and blackhole the prefix until it re-established. |
| **Shell out to `vtysh` / `birdc` / `gobgp`** | Explicitly forbidden by the project's own rules. Parsing CLI output is brittle, and it makes the daemon's routing behaviour depend on a text format nobody versions. |
| **FRR or BIRD instead of GoBGP** | Both are fine and the packaged example configs still support the health-check-script style of integration. GoBGP won for the in-process integration because it is a Go project with a first-class gRPC API — we get a typed client, not a scraped CLI. |

**What it costs.** A second daemon to run and monitor. Accepted; it is the same
trade every anycast deployment makes.

**Lab-verified.** `systemctl stop cgdns` on ns1 withdraws the prefix gracefully
on SIGTERM, the router moves the active gateway to ns2, queries never fail, and
ns1 re-advertises on restart.

**Two traps found, worth knowing before anyone repeats them:**

1. **GoBGP's global `default-import-policy = "reject-route"` rejects locally
   originated routes**, not just peer-received ones. `gobgp global rib add`
   returns exit 0 and the prefix silently never enters the RIB — the session
   establishes and nothing is ever advertised. Do not set it.
2. **Debian trixie-backports `gobgpd` 4.7.0 ships a broken systemd unit** — it
   passes `--syslog yes`, a flag the 4.x binary no longer accepts, so the
   service fails instantly. Worked around with a drop-in overriding `ExecStart`.
   Worth reporting upstream.

### 4.4 Withdrawal is fast; re-advertisement is dampened

**Decision.** `failure_threshold` 2, `success_threshold` 3, `min_hold` 30 s,
`max_hold` 5 min, penalty doubling on each flap.

**Why asymmetric.** Withdrawing is cheap *relative to serving badly*: the
address is picked up by the same-role node in the next-closest POP, so
subscribers keep resolving on it, just further away — and their secondary is
untouched and still local. A flapping prefix is expensive to *every* POP that
carries the address, because each withdrawal reconverges the path and in-flight
queries are lost, and each move shifts a state's worth of primary load onto a
remote node. So: fail fast, recover slowly.

**Note that withdrawal is not free here**, and it is more costly than it would be
if both nodes carried both addresses (§1). A withdrawal always leaves the POP.
That is an argument for withdrawing on genuine failure and not on noise —
which is what `failure_threshold` 2 and the check design in §4.2 are for — not
an argument for withdrawing slowly.

**Enforced.** Config validation refuses `success_threshold < failure_threshold`
with the reason in the message: *"recovery must be harder than failure, or the
node flaps"* (`internal/config/config.go:1114`).

### 4.5 `stable_after` — why dampening needs a memory

**Decision.** A node that has served cleanly for `stable_after` (default 5 min)
before failing has its hold reset to `min_hold`. A node that fails again sooner
has its hold doubled.

**Why.** Without this, dampening never escalates: a node that recovers cleanly
each time resets its own penalty and can oscillate indefinitely. The distinction
is between a one-off failure after a long clean run, and a node that is sick.

### 4.6 Dampening state is in memory — and that is why the unit caps restarts

**Known gap, handled at the systemd layer.** Flap history lives in process
memory. A crash loop would therefore start with no history each time and flap
the prefix regardless of dampening.

`deploy/systemd/cgdns.service` sets `StartLimitIntervalSec=300` and
`StartLimitBurst=5`. After five failures in five minutes systemd gives up and
leaves the node withdrawn — which is the correct outcome for a node that cannot
stay up.

**Operational note.** This will bite during hands-on work: `Job for
cgdns.service failed because start of the service was attempted too often`.
Recover with `systemctl reset-failed cgdns && systemctl start cgdns`.

### 4.7 Graceful shutdown withdraws before the listeners stop

**Decision.** On SIGTERM the prefix is withdrawn *first*, with its own 3-second
timeout (the parent context is already cancelled), and only then do listeners
close (`internal/health/health.go:206-225`).

**Why.** A planned restart should move traffic away before the node stops
answering. Doing it the other way round drops the queries in flight during the
gap.

### 4.8 BGP only — no IGP on the resolvers

**Decision.** The nodes speak eBGP to the adjacent router and nothing else. No
IS-IS, no OSPF.

**Why.** Running an IGP on a resolver makes it a routing participant, where a
sick node can affect SPF for the whole area. BGP is also what carries the health
signal — withdraw when unhealthy. The carrier's routers may well redistribute
the anycast /32 into IS-IS — that is the routers' concern, and it is what gives
nearest-node selection.

**Precision, since it would otherwise be overclaimed:** the maintenance path
does a **plain withdraw** on SIGTERM (§4.7), not an RFC 8326 `GRACEFUL_SHUTDOWN`
community. The community would let the adjacent router de-preference the session
*before* routes disappear, draining in-flight traffic more smoothly than a
withdraw does. It is a worthwhile addition and is listed in §20 as open, not
claimed as done.

---

## 5. The control plane — replication without consensus

Configuration (subscriber prefix mappings, per-subscriber overrides, feed
metadata, class definitions, API token hashes, operator accounts) lives in
`internal/control` and replicates between the pair.

### 5.1 Last-write-wins ordered by a Lamport counter with node ID as tiebreak

**Decision.** Every record carries `Lamport` and `Origin`. A write sets
`Lamport = max(seen) + 1`; on a tie, the higher node ID wins
(`internal/control/store.go:78-85`).

**Alternatives.**

| Option | Why not |
|---|---|
| **Wall-clock timestamps** | Requires synchronised clocks between the pair. NTP skew or a step would silently reorder writes, and the failure is invisible. |
| **Vector clocks** | Correctly detect concurrent writes — but then *something* must resolve the conflict, and with no human in the loop that means picking a winner anyway. The extra machinery buys detection we cannot act on. |
| **Raft** | See §3.3. Pathological at N=2. |
| **Designate ns1 as config primary** | Rejected on requirement: writes must land on either node. A primary also means a provisioning system needs to know which node is primary, and needs to handle the primary being down. |

**Why this one.** Both nodes converge on the same winner without depending on
synchronised clocks, deterministically, with no coordination round trip. Write
to either node; both end up the same.

### 5.2 Deletes are tombstones, retained 7 days

**Decision.** A delete writes a tombstone rather than removing the record.
`TombstoneTTL = 7 * 24 * time.Hour` (`internal/control/store.go`).

**Why.** Without tombstones, a peer that was down during a delete **resurrects
the record on rejoin** — from its side, the record simply still exists and it
has no way to know a delete happened. The TTL has to outlive any realistic
outage; a week covers a node out for a long hardware replacement.

**What it costs.** Deleted records occupy space for a week, and a node down for
longer than a week can resurrect a record. That second case is real and
accepted — see §17.

### 5.3 Rejoin is anti-entropy over digests

**Decision.** On reconnect the nodes exchange `(kind, key, lamport, origin)`
digests, diff them, and pull only the payloads where the peer is newer
(`Store.Missing`).

**Why.** Sending the whole store on every reconnect would be wasteful and would
scale badly with the subscriber count. Digests are small and the diff is exact.

**Record kinds are numbered and never renumbered.** `RecordKind` values are
persisted and replicated, so changing one would make a node read every existing
record of that kind as something else.

**This bought a real mixed-version property, observed rather than assumed.** When
operator accounts (`KindUser`, 6) were added, ns2 ran the new build and ns1 ran a
build that predated the record kind entirely. ns1 **stored the unknown record
faithfully, rendered it as "unknown", and still agreed on the store hash.** That
is the behaviour a rolling upgrade across a pair needs: an older node must not
drop, mangle or diverge on a record type it does not understand.

### 5.4 `Store.Hash()` is the drift detector that replaces consensus

**Decision.** Both nodes in a POP hash their store contents. Equal hashes mean
they agree. `cgdnsctl drift ns1:8443 ns2:8443` compares them and exits non-zero
on disagreement.

**Why this exists.** With no consensus protocol, nothing else can tell you that
a provisioning write reached one node and not the other. This is *the* alert to
build. A brief difference just means a write has not propagated yet; a
disagreement persisting past a sync interval (30 s) is a real fault.

**Two subtleties that were bugs first:**

1. **The hash compacts JSON payloads before hashing.** Otherwise formatting
   differences — an indented file, a peer that encodes slightly differently —
   produce a permanent false drift alarm. Caught by
   `TestStore_PersistsAcrossRestart`.
2. **Records are canonicalised at the door** (`control.Canonical`). The publish
   path lowercases and sorts, so storing exactly what an operator typed left the
   store disagreeing with the policy actually in force — and the same rule
   entered as `Example.COM` on one node and `example.com` on the other would
   have reported drift forever.

**`drift` refuses to report "in step" when fewer than two nodes answered.** One
node agreeing with itself proves nothing, and reporting agreement would be a lie
of omission during exactly the outage the check exists for.

### 5.5 Accepted limitation: concurrent edits during a pair-link partition

**The scenario.** The pair link drops while both nodes stay up. The *same
record* is edited on both. When the link returns, one edit is superseded.

**Why we accept it.** It is deterministic and never corrupting — a record is
always one of the two values written, never a mixture. Different records edited
on each side both survive. The provisioning system (OSS/BSS) is normally the
only writer, so the window for two conflicting edits is small. The alternative
was designating a primary, which was rejected on requirement (§5.1).

### 5.6 Durability: atomic rename, and flush-before-wait

**Decision.** `Store` persists by writing a temp file and renaming, so a crash
mid-write leaves the previous file intact. `Store.RunFlusher` persists on change
and once more on shutdown.

**Two bugs this area produced, both silent:**

1. **The store never reached disk at all.** It was configured with a path and
   looked durable, but nothing called `Flush` — every control change, *including
   the bootstrap admin token*, was lost on restart.
2. **`RunFlusher` must flush *before* waiting.** A wait-first loop reads the
   version then blocks for the *next* change, so anything written during startup
   — which is exactly when the bootstrap token is minted — sat unflushed until
   some later change happened to arrive.

Both are listed here because they are the kind of thing that passes every test
and fails in production, and because "it looked durable" is not evidence.

### 5.7 Feed *content* is never replicated

**Decision.** The control store holds feed **metadata**: URL, version, content
hash, and which classes subscribe. Each node fetches the content itself and
verifies the hash.

**Why.** RPZ/RBL feeds run to millions of rows. Pushing content through the
replication path would dominate it, and would mean two copies of a large blob
crossing the pair VLAN on every update. Metadata is tiny.

**Sizing the state that *is* replicated:** the subscriber→class prefix map plus
per-subscriber overrides. Realistically 1–2 % of subscribers ever have an
override, a handful of entries each — roughly **4 MB at 500 k subscribers**.

**Feed fetch failure fails open.** A feed that will not load must never take
resolution down; see §10.5.

---

## 6. The pair link

### 6.1 One mutually-authenticated TLS connection carrying two payloads

**Decision.** `internal/peer` opens one mTLS TCP connection between ns1 and ns2
(lab: `100.127.255.0/30`, port 8853) carrying config replication *and* cache
sharing, with deliberately different delivery guarantees:

- **Config replication is reliable and converging.** Losing a config update is a
  bug.
- **Cache sharing is best-effort and lossy by design.** Losing a cache push is a
  cache miss, which the sibling resolves for itself.

**Why one connection.** Two connections would double the failure modes and the
partition states to reason about, for no benefit — the payloads are small and do
not contend.

### 6.2 Custom length-prefixed framing rather than gRPC

**Decision.** A 5-byte header (1 type byte + 4-byte big-endian length) then a
JSON or DNS-wire payload. `maxFrame` 8 MiB.

**Alternatives.** gRPC (we already have the dependency, for GoBGP), HTTP/2, or
a message queue.

**Why this one.** The link is point-to-point between two processes we control
and version together. gRPC would bring protobuf schema management, a service
definition, and a code-generation step for a protocol with eleven message types
— and would still need the same versioning discipline. The framing here is
about 40 lines and can be read in one sitting.

**What bounds the damage.** `maxFrame` caps what a hostile or broken peer can
make the other side allocate; config sync sends records in batches rather than
one enormous frame.

**Version handling.** `ProtocolVersion = 1`. A peer announcing a higher version
is **refused rather than guessed at** — two nodes disagreeing about the format
would silently diverge their config, which is worse than not linking.

### 6.3 Cache: push on fill, pull on miss

**Decision.** After resolving, hand the RRset to the sibling so it stays hot.
Before going upstream on a miss, ask the sibling first
(`peer.pull_on_miss`, default true).

**Why.** A pair-link RTT is well under a millisecond (0.7 ms measured in the
lab) against 20–50 ms upstream.

**The invariant that keeps it honest.** Config validation refuses
`peer.fetch_timeout > resolver.query_timeout`, because consulting the sibling
would then cost more than just resolving upstream
(`internal/config/config.go:1073`). Default `fetch_timeout` is 150 ms.

**A peer that is slow, gone or wrong is indistinguishable from a cache miss** —
the resolver just proceeds upstream, which is what it would have done without a
pair at all.

**Loop prevention.** An entry received from the peer must never be pushed back.
Lab-verified: the receiving node's `push_sent` stays 0.

### 6.4 A shared cache entry is encoded as a DNS message, with TTL decremented in transit

**Decision.** `encodeEntry` packs the entry as a `dns.Msg` with TTLs written as
the time **remaining**, never the original.

**Why the wire format.** The RRs are already in the form both sides need, the
packing code is already tested, and it avoids inventing an encoding.

**Why remaining TTL.** An entry carrying its original TTL would be resurrected
on the peer and outlive its own expiry. Decoding refuses an entry that arrives
already expired.

### 6.5 Accepted risk: peer entries are trusted, not re-validated

**Decision.** An entry from the sibling is inserted into cache as-is, and the
DNSSEC status (`AD`) travels with it.

**Why.** The pair is one trust domain, authenticated by mutual TLS with a
per-POP CA. Re-validating every received entry would put public-key
cryptography on the receive path and roughly double the validation cost of the
pair for no additional assurance against any attacker who is not already inside
the trust boundary.

**The accepted consequence, stated plainly: a compromised ns1 can poison ns2's
cache.** This was considered and accepted on cost. It is in the risk register
(§17). The mitigation is that the link requires mutual TLS with a CA —
validation refuses `peer.enabled` without `peer.ca_file`, with the reason in the
error message.

### 6.6 Two bugs the pair link produced, and the general lesson

1. **`Server.Close()` originally closed only the listener**, so an established
   peer did not notice shutdown until its 2-minute idle timeout — delaying
   failover by minutes. It now tracks and drops connections.
2. **The server tracked attachment with a `bool`**, which a reconnect breaks: the
   replacement connection serves while the old one waits out its idle timeout,
   and the dying connection's deferred clear reported a live link as down. It is
   a **counter** now.

**The general rule:** any "is something attached" flag on a component that can
have overlapping instances wants a count, not a bool.

### 6.7 Known: detection latency on an idle link is up to 30 s

There is no keepalive. A link carrying queries detects failure within
`peer.fetch_timeout`; an idle link is bounded by the 30 s sync tick. That means
`cgdns_peer_outbound_up` can read stale for up to 30 s on a quiet pair.

Acceptable for a control-plane link — nothing on the query path waits on it —
but it is a documented limitation, not an oversight.

### 6.8 Partition behaviour, lab-verified

With `iptables` DROP on tcp/8853 in both directions: **both halves report the
link down, both nodes keep resolving, and both stay in the anycast set.** The
link re-establishes on heal within the 2 s redial tick and sharing resumes.

This is the property that matters most: **loss of the pair degrades management
and cache warmth, never resolution.**

---

## 7. Recursion correctness and security

These are the invariants that stop the resolver being turned into a weapon or a
cache-poisoning target. Each has a test. If one starts failing it is a real
hole, not a flaky test.

### 7.1 Bailiwick — a server may only tell us about names it has authority over

Implemented in `internal/resolver/bailiwick.go`.

| Rule | What it stops |
|---|---|
| Glue is kept only if its owner name is inside the delegated zone (`filterGlue`) | The classic cache-poisoning vector: a delegation for `example.com` volunteering an address for `www.yourbank.com`. Out-of-bailiwick glue is **discarded, never cached** — not merely distrusted. |
| A referral must delegate **strictly below** the current zone **and** be a suffix of the QNAME (`referralZone`) | Self-delegation (infinite loop), sideways delegation and upward delegation — each would loop or walk us into a zone the server cannot vouch for. |
| A referral naming more than one cut point is rejected | An ambiguous referral is not a referral. |
| Answer records outside the CNAME chain being followed are dropped (`answersFor`) | An authoritative answering one name has no business also volunteering records for another. |

### 7.2 Budgets — the amplification limit

**Decision.** Every client query gets one `queryState`, threaded through
*everything* including the side-quests that resolve glueless nameserver names.

| Budget | Default | Purpose |
|---|---|---|
| Client wall-clock budget | 5 s | Context deadline; every outbound query derives its deadline from what remains |
| `max_delegation_depth` | 16 | Kills referral loops |
| `max_outbound_per_query` | 32 | **The amplification limit** |
| `max_cname_chain` | 8 | Kills CNAME loops |
| Nameserver-resolution nesting | 4 | Guards mutual recursion — a zone whose nameserver lives in the zone its own nameserver needs resolved |

**The critical detail:** giving glueless-nameserver resolution a *fresh* budget
would make the caps meaningless — an attacker crafts a hierarchy where each
lookup spawns more lookups, each with a full allowance. One budget per inbound
query, shared by everything it triggers, is what makes 32 mean 32.

**Why 32 specifically.** It is comfortably above what any legitimate deep
delegation needs (a cold cross-TLD CNAME chase measured well under it) and low
enough that one query cannot be turned into a meaningful outbound flood.

### 7.3 QNAME minimisation is a privacy control, not an optimisation

**Decision.** On by default (RFC 9156), with a config escape hatch.

**Why.** The root must never learn a subscriber's full query. Sending
`www.internal-thing.example.com` to a root server tells a third party more about
our subscribers than they need.

**Two details that are easy to get wrong:**

- Intermediate probes use **QTYPE A** (RFC 9156 §2.3), not the real type.
- **An intermediate NXDOMAIN is not trusted for the full name.** Some
  authoritatives wrongly return NXDOMAIN for empty non-terminals. The engine
  falls back to asking for the full QNAME and counts it
  (`cgdns_..._minimise_fallback`). This is `internal/resolver/recursive.go:505-513`.

### 7.4 0x20 mixed-case encoding

**Decision.** On by default. Case is randomised outbound; the response must echo
it exactly or the response is discarded as a possible spoof, and
`cgdns_recursion_case_mismatch_total` increments.

**Why.** It adds entropy an off-path attacker must guess alongside the query ID
and source port, which is cheap insurance against blind spoofing.

**Two consequences that were bugs before they were rules:**

1. **Cache keys MUST be canonicalised.** Otherwise every response misses the
   cache forever, because the key would carry the random case pattern.
   `cache.NewKey` canonicalises — "this is not optional" is in the source.
2. **The pattern MUST be stripped before anything downstream sees it**
   (`normaliseCase`). It leaked once, in owner names *and* — via DNS name
   compression pointing back at the question — into RDATA such as CNAME targets
   and SOA fields. That both discloses the anti-spoofing entropy and breaks stub
   resolvers that compare answer names byte-for-byte. There is a regression test.

**Ordering rule:** DNSSEC validation runs **before** `normaliseCase`, because
signature verification depends on names exactly as they arrived on the wire.

### 7.5 Source port stays kernel-assigned

**Decision.** `resolver.outbound_source_v4/_v6` pin the source *address*. The
source *port* is deliberately left to the kernel.

**Why.** Pinning the port too would leave an off-path attacker only the query ID
(16 bits) to guess. Random source port is a load-bearing part of spoofing
resistance.

### 7.6 We never ask an authoritative to recurse

`m.RecursionDesired = false` on every outbound query. Asking an authoritative to
recurse would be asking it to act as an open resolver on our behalf.

### 7.7 EDNS: 1232 bytes, downgrade on failure, TCP fallback

- **`udp_buffer_size` 1232** — avoids fragmentation on paths with a 1280-byte
  IPv6 MTU (DNS Flag Day 2020). Validation constrains it to 512–4096 and
  recommends 1232 in the error message.
- **EDNS downgrade:** a FORMERR or NOTIMP response to an EDNS query marks the
  server as EDNS-broken in the infra cache and retries plain. This is memory —
  we do not re-learn it per query.
- **TCP fallback** on TC=1, and the TCP path is tested independently
  (`TestTCP_DoesNotTruncateLargeResponse`, `TestUDP_TruncatesOversizedResponse`).

### 7.8 The infrastructure cache — what we know about servers, not their data

**Decision.** `internal/cache/infra.go` holds per-nameserver RTT, health and
EDNS quirks, separate from the RRset cache. Candidates are ordered fastest-first
and unhealthy servers are skipped with a capped backoff (`max_backoff` 30 s).

**Why separate.** It has a completely different lifetime and eviction profile
from cached records, and mixing them would mean an RRset eviction could forget
that a server is broken.

### 7.9 A DS query must start its walk at the *parent*

**The trap.** A DS record lives in the **parent** zone. Walking into the child
returns nothing, which is **indistinguishable from an unsigned zone**. This
broke every validation attempt until it was found, and `walkFrom(…, startAt)`
exists specifically for it (`internal/resolver/recursive.go:352-365`).

There is a second case: the parent may *refer* us to the child rather than
answering. A referral for a signed child carries the DS in its authority
section, so `finishDSReferral` takes it from there rather than descending and
asking the child about its own delegation.

### 7.10 Forwarding mode is kept, behind the same interface

**Decision.** `internal/resolver/forward.go` implements upstream forwarding
against the same handler interface as full recursion.

**Why keep it.** It is useful in a lab, at the edge of a migration, and for
nodes that must sit behind a corporate resolver. It is not the production mode.

**Validation guard:** `resolver.upstreams` must be **empty** in recursive mode.
The config *rejects* it rather than silently ignoring it, because an operator
who lists upstreams and gets recursion believes traffic is forwarded when it is
not.

**Both modes strip `AD` unless this resolver validated the chain itself.** There
are tests asserting this. It must never be "fixed" by trusting an upstream's AD
bit.

### 7.11 Root hints are embedded, and overridable

**Decision.** IANA's `named.root` is embedded in the binary
(`internal/resolver/roothints/`) and parsed as a real zone file, not a hardcoded
list. `resolver.root_hints_file` overrides it.

**Why both.** Embedded means a fresh install works with no external fetch. The
override exists because a node that has been down for months may need a fresher
copy — same reasoning as the trust anchor.

---

## 8. DNSSEC

### 8.1 We validate locally and never trust anyone else's `AD` bit

`AD` is set on a response **only** when this resolver built and verified the
chain itself (`internal/resolver/recursive.go:283`). A forwarded answer's AD bit
is someone else's claim.

### 8.2 A failed chain is SERVFAIL with an extended error — never a downgrade

**Decision.** Bogus → SERVFAIL, with an RFC 8914 Extended DNS Error naming the
cause. `dnssec.ExtendedError` maps each failure to its code: signature expired,
bogus, RRSIGs missing, DNSKEY missing, unsupported algorithm, NSEC missing.

**Why.** Silently downgrading to an unvalidated answer defeats the entire point
of validating. Telling the client *why* means a subscriber's support call has an
answer in it.

### 8.3 A stripped DS is **bogus**, not insecure

**Decision.** A zone with no DS in its parent is Insecure **only if the parent
proved the absence**. An unproven absence is Bogus
(`internal/dnssec/validator.go:304-311`).

**Why this is the single most important DNSSEC decision here.** Without the
proof, an attacker who strips the DS from a delegation looks *exactly* like an
unsigned zone. Treating "no DS, no proof" as insecure would make DNSSEC
trivially bypassable by anyone on path.

A related case: a DS naming **only algorithms we refuse** leaves the zone
unvalidatable. Treating that as Insecure would also be a downgrade, so it is
Bogus (`validator.go:321-332`).

### 8.4 Algorithm policy: SHA-1 off by default

**Decision.** Accepted: RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384,
ED25519, ED448. RSASHA1 and RSASHA1NSEC3SHA1 only when `accept_sha1` is set.

**Why.** SHA-1 is no longer collision resistant; a validator that accepts it
undermines the guarantee it exists to provide. The escape hatch exists because
some zones are still behind, and an operator should be able to make that call
knowingly.

**Validation detail:** `accept_sha1` with `dnssec: false` is a config *error*,
not a no-op — it means the operator believes something about their configuration
that is not true.

### 8.5 Cheap acceptance checks before any cryptography

`VerifyRRset` performs the RFC 4035 §5.3.1 checks before spending a
verification: type covered matches, signer is at or above the owner name, label
count is sane, algorithm is permitted, validity period covers now, key tag and
algorithm match, and the key has the **ZONE flag** set (RFC 4034 §2.1.1).

**Why.** Public-key verification is the expensive operation. A malformed or
mismatched signature should cost a handful of comparisons, not a verification —
otherwise "send garbage signatures" becomes a CPU exhaustion attack.

### 8.6 Denial validation — the gap that was there all along

**What was wrong.** `ProveNXDOMAIN` and `ProveNODATA` were **implemented,
tested, and never called by the resolver.** Only `ProveNoDS` was wired in, for
insecure-delegation proofs. So client-facing denials were not DNSSEC-validated
at all: a forged NXDOMAIN passed unchecked, and `AD` was never set on one. The
resolver validated what exists and took on faith what does not.

**Why it matters.** An unvalidated NXDOMAIN is an assertion that a name does not
exist. Taking one on trust lets anyone who can answer for a zone **erase a name**
for as long as it stays cached.

**The lesson, kept deliberately:** a package can be complete, correct and well
tested and still be dead code. Grep for callers, not just for the function.

**Three traps hit while fixing it:**

1. **A delegation's NS records are legitimately unsigned in the parent zone.**
   Verifying every RRset in the authority section turned ordinary referrals into
   validation failures. Only SOA/NSEC/NSEC3 and the RRSIGs covering them are
   proof records (`verifyDenialSignatures`, `validator.go:350-379`).
2. **A cached denial no longer carries its proof.** RFC 2308 negative caching
   keeps only the SOA, so re-validating a cached denial failed for want of
   evidence deliberately not kept — every cached NXDOMAIN from a signed zone
   became SERVFAIL. **Fix: validate once on insert, then cache the denial as
   `authenticated`**, exactly as a validated answer is
   (`cacheValidatedDenial`, `recursive.go:289-309`).
3. **A stale process on the port** made a fixed build show the old failures. Wait
   for the socket to clear before concluding anything.

### 8.7 Validate once on insert, trust on hit

**Decision.** A cache entry marked `Authenticated` is served as Secure without
re-verifying.

**Why.** Re-verifying on every hit would put public-key cryptography on the hot
path for no added assurance — the entry has not changed since we verified it,
and the cache is node-local memory.

### 8.8 Aggressive NSEC (RFC 8198)

**Decision.** A validated signed denial says "nothing exists between these two
names", so one denial answers for every name in the gap. `internal/aggressive`
stores those ranges and synthesises denials from them. On by default.

**Why.** Against a random-subdomain (water-torture) flood aimed at a **signed**
zone this is the strongest defence available — the flood never leaves this node.
Measured on the live internet: **100 made-up names produced 99 synthesised
denials and zero outbound queries.**

**Safety properties that must not regress:**

- **Only validated denials are stored.** An unvalidated NSEC is an attacker's
  claim about what does not exist. Config validation refuses
  `aggressive_nsec` without `dnssec`, with that reasoning in the error message.
- **An NSEC is filed under the zone its own SOA names**, and only used for names
  inside that zone — otherwise any signed zone could erase names it does not own.
- **The wildcard must be denied too**: a name no NSEC covers may still be
  synthesised by one.
- The proof returned includes the SOA and RRSIGs, so a DO client can validate it
  itself.
- **NSEC3 is not handled** and falls through to a normal lookup — see §18.

Bounded by `aggressive_nsec_max_zones` (10 000) and
`aggressive_nsec_max_records_per_zone` (512).

**Relationship to rate limiting:** RRL caps what a flood costs *us* to answer;
aggressive NSEC stops it reaching the authoritative at all. They are
complementary, not alternatives.

### 8.9 NSEC3 iteration limits (RFC 9276)

NSEC3 proofs with excessive iteration counts are refused rather than computed.
An unbounded iteration count is a CPU-exhaustion vector aimed at validators.

### 8.10 Trust anchors: IANA's, embedded, with RFC 5011 state on disk

**Decision.** The IANA root anchors ship embedded
(`internal/dnssec/root-anchors.xml`). RFC 5011 rollover state lives in
`node.state_dir`. `resolver.trust_anchor_file` overrides.

**The operational trap, documented in three places:** wiping a node's state
directory is **not harmless** — it re-bootstraps the trust anchor. This is why
the `.deb`/`.rpm` `purge` removes `/var/lib/cgdns` but a plain `remove` does
not (§15.3), and why a node that has been down for months needs both root hints
and the anchor refreshed before it validates.

---

## 9. Transports

### 9.1 All four, all dual-stack: UDP, TCP, DoT, DoH

| Transport | RFC | Note |
|---|---|---|
| UDP | 1035 | `SO_REUSEPORT`, one socket per CPU per address |
| TCP | 7766 | Multiple queries per connection, idle timeout |
| DoT | 7858 | Reuses the TCP connection loop under a TLS listener — the framing is identical |
| DoH | 8484 | HTTP/2, GET and POST |

**DoT reusing the TCP loop** is a deliberate simplification: DNS-over-TLS is
DNS-over-TCP inside TLS, with the same 2-byte length prefix. Writing a second
framing implementation would have been two places to get it wrong.

### 9.2 `SO_REUSEPORT` per-address sockets, and *not* `SO_REUSEADDR`

**Decision.** One socket per CPU per listen address, with `SO_REUSEPORT` so the
kernel load-balances datagrams across them. Wildcard binds are rejected by config
validation.

**Why not a wildcard bind.** `net.ListenPacket` on a wildcard address **loses the
destination IP**. Under anycast that means replies can leave from the wrong
source address — which breaks anycast subtly, and only under load. Binding each
address explicitly keeps the source correct.

**Why `SO_REUSEPORT`.** A single socket's receive queue is the ceiling on a busy
resolver. One socket per CPU, each with its own reader goroutine, spreads wakeups
across cores instead of thundering onto one.

**Why `SO_REUSEADDR` is deliberately NOT set alongside it.** On Linux the two
together would let an **unrelated process silently join the group and steal a
share of production queries**. This is called out in the source
(`internal/transport/sockopt_linux.go`) precisely because adding it looks
harmless.

### 9.3 Bounded worker pools, bounded queues, and panic recovery

- **Workers per socket** (default 32, configurable) bound in-flight queries. Too
  few and the receive queue backs up; too many and a slow upstream becomes a pile
  of goroutines waiting on it.
- **Queue depth** (default 1024) — beyond it, packets are dropped. Dropping a
  packet under overload is correct; growing an unbounded queue turns a load spike
  into an OOM.
- **No `panic` in packet-handling code.** Recovery happens at the transport
  boundary: count it, SERVFAIL, keep serving.
  `TestUDP_HandlerPanicBecomesServfail` pins this.
- **Every socket binds before the daemon reports ready.** A bind failure is a
  startup failure, because anycast routes traffic to an address whether or not it
  is being served.

### 9.4 DoH and the client IP — a security boundary

**Decision.** Forwarding headers (`X-Forwarded-For` and friends) are **ignored
entirely by default**. They are believed only from sources listed in
`listen.doh_trusted_proxies`.

**Why this is not a detail.** The client address selects subscriber policy.
Behind an L7 proxy the TCP peer is the proxy, so **without** the trusted-proxy
list every DoH client classifies as the proxy and gets the wrong filtering.
Believing the header from an untrusted peer is **worse**: any client could then
claim another subscriber's identity and inherit their policy — including their
whitelist.

**Enforced by.** A table-driven test covering all four cases (trusted peer with
header, trusted without, untrusted with, untrusted without):
`TestDoH_ClientAddressResolution`.

### 9.5 DoQ is deferred

RFC 9250 (DNS over QUIC) is not built. It is the lowest-value transport for this
deployment — subscribers reach the resolver over the carrier's own network,
where DoQ's head-of-line-blocking advantage over DoT matters least. It is on the
list (§18).

---

## 10. Subscriber policy and filtering

### 10.1 Why a carrier resolver has per-subscriber policy at all

**The objection, stated fairly:** per-subscriber filtering is not a carrier
resolver feature, and building it risks turning a piece of infrastructure into a
product with a support burden.

**The answer.** It stays off unless someone turns it on (`policy.enabled`), and
when off it is not on the query path at all. It exists because the moment
someone sells a "filtered DNS" or "family safe" product, the alternative is a
second resolver platform. The boundaries in §10.2 are what keep the feature from
compromising the resolver.

### 10.2 Three boundaries that keep filtering off the critical path

These were set deliberately, in priority order:

1. **The query path never does I/O for policy.** Lookups are in-memory and
   lock-free — `policy.Registry` and `subscriber.Classifier` both swap an
   **atomic pointer**, so a policy push never pauses resolution. No database
   read, no network call, no lock, per query.
2. **Replication carries only the small, mutable state** — the subscriber→class
   prefix map and per-subscriber overrides (~4 MB at 500 k subscribers).
3. **Feed content is never replicated** (§5.7).

**Source of truth.** The local control store is authoritative at runtime, but
records are created and edited by the existing OSS/BSS over the management API.
The resolver *consumes* policy and never owns subscriber lifecycle — that is
what keeps CRM concerns (billing sync, customer records, retention) out of it.

### 10.3 Subscriber identity is a longest-prefix match on the source address

**Decision.** `internal/prefixmap` is a v4+v6 longest-prefix trie. It serves both
subscriber classification and the source ACLs.

**Why prefix matching.** Subscribers are handed addresses by DHCP/PPPoE; a
prefix is the durable identifier. Longest-prefix means a /32 exception inside a
/24 works without special-casing.

**Measured:** 3.6 ns (v4) / 7.0 ns (v6) per lookup, zero allocations.

**One deliberate piece of forward planning.** `subscriber.Classify` returns an
**identity (ID + class)**, not a bare class name. Retrofitting identity into the
hot path after the API and replication exist would be painful; keeping the hook
costs nothing now.

### 10.4 Evaluation order is the contract: allow → block → class feeds

**Decision.** `policy.Enforcer` evaluates the subscriber's own allow list first,
then their own block list, then the feeds their class subscribes to
(`internal/policy/enforcer.go:29-37`).

**Why the allow list must be first.** Any curated blocklist eventually
false-positives on some customer's supplier or payment gateway. Without a
per-subscriber unblock the only remedies are editing a shared feed you may not
own, or disabling filtering for that customer and losing the revenue. **The
whitelist is what makes the filtering product supportable** — it is load-bearing,
not scope creep. If the allow list were consulted after class feeds, an unblock
could not override a feed and the feature would not work.

### 10.5 A broken feed degrades filtering, never resolution

**Decision.** A feed or override problem is **fatal at startup** (fail loudly,
per the config ethos) but **non-fatal on reload** — the previously compiled
registry keeps serving.

**Why the asymmetry.** At startup, a node with a broken policy config should not
come up and start taking anycast traffic with filtering the operator did not
intend. At runtime, the node is *already serving subscribers*, and taking
resolution down because a blocklist URL 500'd would be a self-inflicted outage.
Feed fetch failure fails **open**.

### 10.6 Block actions and telling the client why

Actions per class: `nxdomain`, `nodata`, `redirect` (to a walled-garden address
set), `drop`. Blocked answers carry **EDE 15 (Blocked)** so a client can
distinguish policy from a genuine NXDOMAIN.

`redirect` requires `redirect_to` addresses — validation refuses the
combination otherwise, rather than silently behaving as `nxdomain`.

---

## 11. Rate limiting

`internal/ratelimit`, built and verified under a live flood on lab ns2.

### 11.1 We limit *responses*, not queries

**Decision.** Response rate limiting (RRL), not query rate limiting.

**Why.** There are two victims, and they need different things:

- **A third party whose address is being spoofed.** They never sent the query, so
  the only thing that helps them is **us not sending the answer**.
- **The authoritative servers of a zone under a random-subdomain flood**, and our
  own outbound capacity with them.

Limiting queries would drop the flood but would not stop us reflecting at a
spoofed victim, which is the reflection/amplification case that matters.

### 11.2 Denials are grouped by the zone that denied them, never by QNAME

**This is the decision that makes the whole thing work.**

A water-torture flood — `random1.victim.com`, `random2.victim.com`, … — carries a
**fresh QNAME every query**. A bucket keyed on QNAME therefore gives every query
its own bucket and limits precisely nothing.

Denials are keyed on the **SOA owner** from the authority section, so the whole
flood collapses into one bucket.

**Proven both ways:** with zone grouping, a 500-query flood yields 10 answers and
1 bucket. Reverting to QNAME grouping yields 500 answers and 200 buckets.
`TestHandler_RandomSubdomainFloodCollapsesIntoOneBucket` fails if this regresses.

**Fallback** when a response carries no SOA: strip the leftmost label, which
still lands on the target zone.

### 11.3 A new bucket starts with one second of allowance, not a full window

**Decision.** `credit = min(rate, rate * window)` on bucket creation, not
`rate * window`.

**Why.** The window exists so a client that has behaved may burst. **A source we
have never seen has earned nothing.** Starting buckets full gave every fresh
prefix a free burst of 750 responses — and since a spoofing attacker never
reuses a prefix, limiting would effectively never engage.

**How it was found, and this matters:** by **flooding a live daemon**, not by a
unit test. Every unit test passed against the broken version, because they reuse
one bucket. Two of the three bugs in this area were invisible to passing tests
and only appeared watching a real daemon over time.

### 11.4 Answers are unlimited by default; denials 50/s; errors 20/s

**Why.** A real subscriber asks for names that exist. **Limiting the answer class
is how an operator breaks their own customers.** Denials are where the abuse
lives, so that is where the default limit sits.

A rate of 0 means that class is unlimited. Config validation refuses
`rate_limit.enabled: true` with all three rates at 0 — that configuration limits
nothing and the operator plainly believed otherwise.

### 11.5 UDP only

TCP, DoT and DoH complete a handshake, so the source cannot be spoofed and there
is no reflection to prevent. Limiting there would only hurt real clients.

### 11.6 Slip ratio 2 — every second over-limit response is truncated

**Decision.** Rather than dropping every over-limit response, send every Nth as a
small truncated (TC=1) response. Default N=2.

**Why.** A legitimate client sees TC and retries over TCP, where it is not
limited — so real clients survive a limiting event within a couple of retries. A
spoofed victim gets a small packet instead of a large one, which removes the
amplification. 0 always drops; 1 always slips; 2 is the compromise.

### 11.7 The bucket table is bounded and *evicts* rather than refusing

**Decision.** `max_buckets` 100 000, sharded 16 ways, evicting under pressure.

**Why evict rather than refuse.** Refusing to create a bucket when the table is
full would mean **an attacker who fills the table has found a way to switch
limiting off**. Eviction prefers buckets that have recovered their full
allowance (idle clients, free to forget); failing that, it evicts the least
recently seen of a small sample of 8, which keeps eviction O(1) rather than
scanning a shard while holding its lock.

**Why the eviction constants are not configurable.** `idleWindows`, `sweepBatch`
and `evictSample` bound work done while holding a shard lock on the hot path. An
operator tunes rates and table size; they do not tune how long a lock is held.

### 11.8 Bucketing by /24 and /56, not by single address

**Why.** Limiting single addresses would be useless in both directions: an
attacker spoofs across a whole range, and real subscribers share one address
behind CGNAT.

### 11.9 The self-outage risk, and the check that guards it

**The risk, stated plainly: a resolver that rate-limits its own health probe
withdraws itself from anycast and turns an attack into an outage.**

It does not happen here because probes come from loopback (a separate bucket, as
buckets are keyed by client prefix) and are *answers*, not denials. But **any
change to bucketing or to the default rates has to be re-checked against this.**

The live flood test asserts `cgdns_anycast_advertised` stays 1 and
`cgdns_health_check_failures_total` stays 0 throughout.

**Measured on the lab:** 15 000 queries at 500/s against a 50/s denial limit
collapsed to a single bucket, 1 547 answered (the configured rate), node healthy
and in the anycast set throughout. Limiter cost: ~120 ns/op, zero allocations.

**Test-tooling gotcha worth recording:** a raw flood tool that sends no EDNS gets
TC=1 on every signed NXDOMAIN, because the denial proof does not fit in 512
bytes. That looks like "everything was slipped" and is not — check
`cgdns_ratelimit_slipped_total`, not the TC bit.

---

## 12. Serve-stale and prefetch

### 12.1 Serve-stale (RFC 8767)

**Decision.** Expired entries are retained for `max_stale` (1 h default) and used
**only after resolution has already failed**.

**Design points, each with a reason:**

| Decision | Why |
|---|---|
| `Cache.Get` still reports an expired entry as a **miss** | A working authoritative is always preferred; stale is a fallback, never a shortcut |
| `GetStale` counts neither a hit nor a miss | Serving stale is a failure signal, not cache performance — it has its own metrics |
| **Only SERVFAIL triggers it** | NXDOMAIN and NODATA are *answers*: the authoritative was reached and said no. Overriding them would resurrect names their owner deliberately removed |
| Stale answers carry **EDE 3** and **never set AD** | The signatures are as old as the data and may have expired, so the validation claim cannot be stood behind |
| Stamped with `answer_ttl` (30 s), **never 0** | A zero TTL tells every client not to cache, sending them all straight back to a resolver that is already failing |

**Validation invariant:** `answer_ttl` must be shorter than `max_stale` — a
client told to cache a stale answer for longer than we are willing to keep it
would outlast our own copy.

### 12.2 The interaction that matters: health checks must not accept stale

**Decision.** `ResolveCheck.AcceptStale` is **false** by default.

**Why.** Serve-stale exists to keep answering when a node cannot resolve. A probe
that accepted a stale answer would let a node **cut off from the internet pass
its checks forever** on cached root data — holding an anycast prefix it can no
longer serve, while a working POP sits idle.

**Lab-verified:** the isolated node kept answering cached names for subscribers
*and still withdrew*, citing `. NS was answered from expired cache, so this node
is not resolving`.

**Re-check this whenever health checks or the handler chain change.** It is the
mirror image of the rate-limiting self-outage risk in §11.9.

### 12.3 Handler chain order

```
udp → ratelimit → policy → servestale → resolver
```

**Serve-stale sits *inside* policy** so a blocked name stays blocked even when it
is answered from expired data. Rate limiting sits outermost so an over-limit
response costs as little as possible.

### 12.4 Prefetch

**Decision.** When a **read** finds an entry inside the last `threshold` fraction
(0.1) of its original TTL, refresh it in the background.

**Why.** A busy resolver spends much of its latency budget on the unlucky client
whose query arrives the moment a popular entry expires — everyone behind them
waits on one upstream round trip. Prefetch means a name asked for constantly is
answered from cache constantly.

**Four constraints, each with a reason:**

- **Only names being asked for are refreshed.** An idle entry expires normally —
  otherwise the cache becomes a crawler keeping every name it ever saw alive.
- **Denials are never refreshed.** A name that does not exist is not made more
  available by asking again, and a random-subdomain flood would turn into
  outbound traffic of our own.
- **Deduplicated per key and capped** (`max_concurrent` 64). Over the cap it
  **drops** rather than queues — the entry is still live, so the refresh is
  optional. The thing preventing a stampede must not be able to cause one.
- **`Close` cancels in-flight refreshes** rather than awaiting them. Shutdown
  must not be delayed by an optimisation, and the node has already withdrawn.

### 12.5 The prefetch bug worth putting in a decision record

**What happened.** A refresh went through the resolver's ordinary path, which
**consults the cache first** — and the entry being renewed was still live, so it
answered from cache, never contacted the authoritative, and never wrote anything
back. Metrics showed twelve refreshes "triggered" and twelve "completed" while
the TTL ran all the way down to expiry and a client had to resolve it.

**Fix.** `resolver.WithRefresh(ctx)` marks a query as a refresh and skips the
**top-level** cache lookup only (`recursive.go:390`). Delegation and
nameserver-address lookups still use the cache — re-walking from the root to
renew one leaf would cost far more than the refresh saves.

**Regression test:** `TestRefreshBypassesTheCachedAnswer`, verified by reverting
the guard and confirming it fails.

**The lesson kept from it: "the metric says it ran" is not "it did something".**

---

## 13. The management plane

### 13.1 The admin plane may never ride on a service or anycast address

**The requirement:** no carrier wants their DNS server's WebUI reachable from the
world.

**Enforced in layers, by construction, not convention** — all in
`internal/config` validation:

| Rule | Reason |
|---|---|
| Wildcard management/metrics binds are **rejected** | Same as DNS listeners; a wildcard bind is how an admin plane ends up on an address nobody intended |
| A management listener **may not share a non-loopback address with a DNS listener** | DNS addresses are presumed anycast, so the admin plane would follow the anycast route to an arbitrary node and be exposed wherever the prefix is advertised |
| A management or metrics listener **inside `health.anycast_prefixes` is refused**, naming the prefix that caught it | The daemon knows its own anycast prefixes, so it catches an anycast address that is *not* also listed as a DNS listener — which the co-location check alone missed |
| Loopback is exempt from co-location | Loopback is never anycast, and dev configs legitimately put DNS on `:5353` and management on `:8443` on `127.0.0.1` |
| **Default deny, with no allow-all form.** An empty `allow_from` on a non-loopback listener **fails the boot** | An operator who forgets the ACL gets a failed boot, never a world-reachable admin API |
| TLS mandatory off loopback | |
| Proxy headers never trusted by default; `trust_proxy_headers` requires an explicit `trusted_proxies` list | A spoofable client address on the admin plane is a straight ACL bypass — a worse version of the DoH problem in §9.4 |

**Why anycast specifically is the wrong place for an admin plane:** it is the
exact opposite of a management address. The whole internet routes to it and it
*moves between nodes*, so "which node am I administering" becomes a routing
question.

**Lab-verified on ns2:** management and metrics both refused on the anycast v4
and v6 addresses, naming the prefix that caught them.

### 13.2 The ACL is enforced at `Accept`, before the TLS handshake

**Why.** A blocked peer costs no CPU, never reaches TLS or HTTP, and learns
nothing about the box — not even the certificate.

### 13.3 The WebUI adds no listener of its own

**Decision.** `management.ui` cannot open a socket. The UI is served by the
management server or not at all.

**Why.** It therefore inherits the bind address, the TLS requirement and the
source ACL automatically. A UI with its own listener is a second thing to get
wrong, and it would be got wrong eventually.

### 13.3a The operator console: no framework, no build step, embedded

**Decision.** Three files — `index.html`, `app.js`, `style.css` — embedded in the
binary with `go:embed` (`internal/management/ui.go`). No React, no bundler, no
npm, no build step in the release pipeline.

**Alternatives.** A single-page app in a framework, built by a Node toolchain and
shipped as compiled assets; or a separately deployed UI talking to the API.

**Why this one.**

- **Nothing is fetched from a CDN**, so the content-security policy needs no
  exception for one. A management console that pulls script from a third party
  makes that third party an admin of your resolver.
- **Embedded rather than read from disk**: a node has one binary and one config.
  A UI that could be swapped out underneath the management plane would be a way
  to serve attacker script from a privileged origin.
- **No build step** means the release artifact is `go build`, and there is no
  second toolchain to keep patched.

**What it costs.** The console is deliberately plain, and it will stay plain. It
covers status, the resolution and defence counters, and editors for subscribers,
overrides, classes, feeds, tokens and operator accounts. Anything richer than
that is a job for something reading the API, not for this.

### 13.3b `unsafe-inline` is absent, and every value renders with `textContent`

**Decision.** CSP is `default-src 'none'` with `script-src 'self'`,
`style-src 'self'`, `form-action 'none'`, `frame-ancestors 'none'`,
`base-uri 'none'`. The console renders every value with `textContent`, never
`innerHTML`.

**Why the two go together.** `'unsafe-inline'` is what turns an injected record
value into executing script. Because the console never builds markup from data,
it never needs the exception — so the policy can forbid it outright. A subscriber
ID or feed name containing markup is displayed as text, not parsed.

**The other headers, each with a reason:**

| Header | Why |
|---|---|
| `X-Content-Type-Options: nosniff` | Without it, a response the browser decides is HTML — a record value, an error string — could render as a page from this origin |
| `X-Frame-Options: DENY` | The admin plane has nothing to gain from being framed, and being framed is how clickjacking works |
| `Referrer-Policy: no-referrer` | |
| `Cross-Origin-Opener-Policy: same-origin` | |

**These headers apply to API responses too, not just the console.** An error body
is still something a browser could be talked into rendering.

**Enforced by.** `internal/management/ui_test.go` asserts the CSP is present and
each header has its exact expected value.

### 13.3c The console loads without a session; everything behind it does not

**Decision.** `GET /` serves the page unauthenticated, with `Cache-Control:
no-store`. Every API call it then makes requires a session or token.

**Why.** The page holds no data — it is markup, script and stylesheet. Gating it
behind a login would mean the login form itself needs an exemption, which is the
same surface with more moving parts. What matters is that the *data* behind it is
gated, and there is a test for exactly that.

### 13.3d Metrics for the console come through the management listener

**Decision.** The console reads counters via the management listener, not by
reaching across to `metrics.listen`.

**Why.** Those are deliberately separate sockets with separate ACLs (§13.1).
Punching a hole between them so a dashboard could read one from the other would
undo the separation. If the console needs a number, the management API serves it.

### 13.4 API tokens are stored as a plain SHA-256, deliberately not a slow KDF

**Decision.** A token is a 256-bit random secret, presented as `id.secret`, and
stored as SHA-256 of the secret.

**Why not argon2/bcrypt.** A slow KDF exists to make a *dictionary* attack
expensive. There is no dictionary against 256 bits of randomness — an attacker
brute-forcing it is not the threat model, and paying argon2 cost on every API
request would make the management plane slow for no security gain.

**What is done instead:** verification is **constant time**, and an unknown token
ID is compared against a **dummy hash** so a missing token costs the same as a
wrong one. That stops ID enumeration by timing.

**Contrast with operator passwords (§13.7)** — the two are treated differently on
purpose, and the reason is written into the source.

### 13.5 Only the hash replicates

**Decision.** The control store holds the token *hash*; that is what crosses the
pair link.

**Why.** Managing the pair from either node requires the token to be recognised
on both — but it never requires the secret itself to move. So it does not.

### 13.6 Bootstrap: a node with no token at all mints one to a root-only file

**Decision.** A node holding **no token** writes an admin token to
`management.bootstrap_token_file` (mode 0600). A node that already holds a token
— **including one adopted from the sibling** — never mints.

**Alternatives, both worse.**

| Option | Why not |
|---|---|
| A **default credential** | A permanent hole. Someone will not change it. |
| A **manual out-of-band step** | It gets skipped, and then the node is unmanageable or someone invents a worse way in. |

**The "including one adopted from the sibling" clause is the load-bearing part:**
without it, a rejoining node would grow a credential the operator does not know
about.

Set `bootstrap_token_file` empty to refuse bootstrapping entirely.

### 13.7 Operator accounts: argon2id + TOTP

**Decision.** WebUI logins are humans, which is a different problem from an API
token. Passwords get **argon2id** (time 3, memory 64 MiB, threads 4, 32-byte key,
16-byte salt) and a **TOTP** second factor (RFC 6238, verified against the
published test vectors).

**Why costly on purpose.** This runs once per login attempt, where a tenth of a
second is invisible to an operator and ruinous to someone working through a
password list.

**Design decisions inside it:**

- **Enrolment only takes effect once the operator proves they can generate a
  code.** A half-finished setup cannot lock them out. Re-enrolling while
  confirmed is refused, because it would silently invalidate their existing
  authenticator entry.
- **One error for every failed login cause** (`ErrBadCredentials`). Telling a
  caller whether the username existed, the password was wrong or the code was
  wrong hands them a way to enumerate operators. The one exception is
  "TOTP required", which is safe: the password was already correct, so it reveals
  nothing the caller does not already know.
- **The TOTP secret is stored as the secret, not a hash** — verifying a code
  requires computing it, which cannot be done from a digest. That is the
  concession every TOTP implementation makes; what protects it here is the
  store's file mode and the mutually authenticated link it replicates over.
- **Changing a password ends every other session for that account.** Deleting an
  account ends its sessions immediately, not at the next expiry.
- **The last admin account cannot be deleted** — that would leave the pair with
  no way to be managed through the UI at all.
- **The first account is created with the bootstrap token**, so there is no
  default password anywhere:
  `cgdnsctl user create josh admin` — which prompts, never taking the password
  as an argument (that is what `golang.org/x/term` is for).

### 13.8 Sessions: `__Host-` cookie *and* a CSRF token

**Decision.** Session cookie is `__Host-` prefixed, `Secure`, `HttpOnly`,
`SameSite=Strict`. State-changing requests must additionally echo a CSRF token in
`X-CGDNS-CSRF`, returned in the **login response body** rather than a cookie.

**Why both.** `SameSite=Strict` is good but is a browser policy, and browser
policies have exceptions and bugs. The CSRF token is returned in the body
specifically so **a browser will not attach it automatically** — a cross-origin
request cannot produce it whatever the cookie policy does.

### 13.9 A self-signed certificate is generated if none is configured

**Decision.** With `management.ui` on and no certificate configured, the daemon
generates a self-signed cert into `node.state_dir`.

**Why.** The session cookie is `Secure`, so a browser will not store it over
plain HTTP — the UI simply would not work. **Nobody is meant to trust this
certificate.** It exists so the browser will store the cookie; real TLS is
expected to be terminated in front, by a tunnel or a reverse proxy. The WebUI
binds localhost by default for the same reason.

### 13.10 Tenancy is operator-only

**Decision.** No customer self-service portal, therefore no multi-tenant RBAC.
Scopes are `read` / `write` / `admin`, with admin implying write implying read.

**Why.** Multi-tenant RBAC is a large amount of surface to secure and test, and
nothing in the product requires a customer to log in. If a self-service portal is
ever wanted it should be a separate application against this API, not a mode of
the resolver.

**No external IdP dependency.** Local users are the appliance-grade baseline — a
resolver must be manageable during exactly the network events that would make an
external IdP unreachable.

### 13.11 `cgdnsctl` is a thin client with no privileged state

**Decision.** The CLI does everything over the management API. It has no
back-door into the store.

**Why.** Anything the CLI can do, a provisioning system can do over HTTP. There
is one authorisation path to secure and audit, not two. Request/response bodies
live in `internal/management/wire.go` and are **shared by client and server**, so
the two cannot drift apart.

**Because the pair replicates its control plane, pointing `cgdnsctl` at either
node is equivalent** — that is the Proxmox-style "manage from any node"
behaviour, achieved by replication rather than by a cluster-wide API.

**Details that are decisions, not accidents:**

- **A bare `host:port` is treated as HTTPS.** Defaulting to plaintext would put
  the token on the wire in the clear the first time someone omitted the scheme.
- **Token resolution order:** `-token`, then `CGDNS_TOKEN`, then `-token-file`
  (default `/var/lib/cgdns/bootstrap.token`) — so running it on the node itself
  needs no configuration at all.
- **`allow` / `block` re-read after writing** rather than echoing what was sent,
  because the server canonicalises (§5.4). They read-modify-write, so two
  simultaneous operators can lose an edit — the same last-write-wins the control
  plane has everywhere.

---

## 14. Configuration philosophy

### 14.1 One struct, one YAML file, validated in full at startup, unknown keys rejected

**Decision.** `config.Config` is the whole configuration. `Default()` populates
every optional field; the YAML decoder runs with `KnownFields(true)`.

**Why unknown keys are rejected.** A typo'd key (`allow_querry`) in a permissive
parser silently means "default", and for an ACL that means the operator believes
they configured something they did not.

**Why there is no lazily-defaulted state elsewhere.** If a default can be applied
somewhere other than `Default()`, then reading the config file no longer tells
you how the daemon will behave.

### 14.2 Every problem is reported at once

**Decision.** `Validate()` accumulates problems and returns them as one list.

**Why.** An operator fixing a config should see the whole list, not peel them off
one failed boot at a time. On a node that is out of the anycast set, each boot
attempt is a minute of downtime.

### 14.3 Fail loudly rather than default quietly

**Decision.** A bad config fails the boot. `cgdns -check` validates and exits, so
this can be done before a restart.

**Why, specifically for this product:** **a resolver that starts
half-configured is worse than one that does not start, because anycast routes
traffic to it regardless.** A node that fails to boot never advertises and never
takes traffic. A node that boots with an ACL it did not intend takes production
traffic immediately.

### 14.4 Cross-field invariants the validator enforces

These are the ones that encode a design decision rather than a type check:

| Invariant | Reason |
|---|---|
| `query_timeout ≤ client_budget` | Otherwise a single exchange can consume the whole budget |
| `peer.fetch_timeout ≤ resolver.query_timeout` | Asking the sibling would cost more than resolving upstream |
| `serve_stale.answer_ttl < serve_stale.max_stale` | A client would cache it longer than we keep it |
| `health.timeout < health.interval` | Otherwise checks overlap |
| `health.success_threshold ≥ health.failure_threshold` | Recovery must be harder than failure, or the node flaps |
| `cache.shards` power of two, `≤ max_entries` | Lookups mask rather than divide |
| `resolver.upstreams` empty in recursive mode | An operator must not believe traffic is forwarded when it is not |
| `aggressive_nsec` requires `dnssec` | Reusing an unvalidated NSEC lets anyone answering for a zone erase names from it |
| `accept_sha1` requires `dnssec` | Otherwise the setting means nothing and the operator believes otherwise |
| `outbound_source_*` not inside an anycast prefix, and bindable | A shared source invites replies to the sibling; an unbindable one fails every query later instead of now |
| `peer.listen ≠ peer.remote` | A node cannot pair with itself |
| `peer` requires cert, key **and** CA | The sibling writes into this node's cache; an unauthenticated peer could poison it |
| CIDR prefixes must be written **masked** | So nobody writes `10.0.0.5/24` and wonders why the ACL matched more than expected |

### 14.5 Three things that warn loudly rather than fail

Legal, occasionally intended, never something to discover by accident. Each logs
a warning at startup:

- **`listen.allow_query` contains a default route** — this node will answer
  recursive queries from any source and can be used for reflection/amplification.
- **`resolver.use_ipv6` is false** — this node cannot reach IPv6-only
  authoritatives and will SERVFAIL for zones served only over v6.
- **`resolver.dnssec` is false** — answers are unvalidated, `AD` is never set, and
  forged records from a compromised authoritative cannot be detected.

**Why warn rather than refuse.** Each has a legitimate use (a public resolver
service; a temporary v6 workaround; a debugging session). Refusing would push
operators toward worse workarounds.

---

## 15. Packaging and deployment

### 15.1 nfpm, producing both `.deb` and `.rpm`

**Decision.** `make package` runs nfpm.

**Why.** nfpm is pure Go, so building a Debian package needs no `dpkg-dev` and an
RPM needs no `rpmbuild` — both formats build on any machine that can build the
binary, including CI. Alternatives (`fpm`, native tooling per distro) mean
distro-specific build hosts.

### 15.2 Binaries go to `/usr/sbin` and `/usr/bin`, never `/usr/local`

**Why.** `/usr/local` is reserved for locally built software; Debian policy
forbids packages touching it. The unit ships to `/usr/lib/systemd/system`.

**This bit us in the lab before packaging existed:** the systemd unit ran
`/usr/local/sbin/cgdns` while a deploy script copied to `/usr/local/bin`. The old
binary kept running and `systemctl is-active` happily reported `active`. **A
whole verification round was run against stale code.**

**Rule from it: confirm the deployed build with `cgdns -version` (or the
`version=` field in the startup log line) after every deploy — not just the
service state.**

### 15.3 A first install neither enables nor starts the service

**Decision.** Fresh install: package installed, service stopped and not enabled.
The shipped `/etc/cgdns/cgdns.yaml` has no listen addresses and no query ACL, so
the daemon **refuses to start until configured**.

**Why.** Anycast would route production traffic at a node the moment it came up.
A node nobody has configured is not one you want taking queries.

**Upgrade behaviour is different, deliberately:** an upgrade restarts only a node
that was **already running**, and `preremove` skips the stop on upgrade — so the
prefix is withdrawn for the duration of a restart, not for the whole install.

**Purge vs remove:** `purge` removes `/var/lib/cgdns`; a plain `remove` does not.
That directory holds the RFC 5011 trust-anchor state and the control store, so
deleting it on remove would re-bootstrap the anchor and lose the node's config.

**The config is a `config|noreplace` conffile**, so an upgrade keeps a tuned file
and drops the new template beside it as `.dpkg-dist`.

### 15.4 Ambient capabilities, not `setcap`

**Decision.** `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit.

**Why.** `NoNewPrivileges=true` **strips file capabilities** — a `setcap` on the
binary is inert under it and the daemon fails to bind :53. Ambient capabilities
work under `NoNewPrivileges` *and* survive replacing the binary on upgrade, so
deployment needs no `setcap` step at all.

This cost real time to diagnose and is now captured in the shipped unit.

### 15.5 The rest of the systemd hardening

`User=cgdns`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
`ProtectKernelTunables=true`, `ProtectControlGroups=true`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality=true`,
`MemoryDenyWriteExecute=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.

`StateDirectory=cgdns` and `RuntimeDirectory=cgdns` so systemd owns the
directory lifecycle.

### 15.6 The shadowing-unit trap — hit for real

**What happens.** A hand-placed `/etc/systemd/system/cgdns.service` **overrides**
the packaged unit. The node keeps running whatever that file points at, so the
install looks like it took when it did not.

**It gets worse.** Removing that file later leaves
`/etc/systemd/system/multi-user.target.wants/` pointing at a deleted file, and
**`systemctl is-enabled` still reports `enabled`** while the node would silently
not come back from a reboot.

**Rule:** always `systemctl reenable cgdns` after removing a shadowing unit. The
postinstall now warns about this.

---

## 16. Performance and the query path

### 16.1 Measured numbers

Measured on a Xeon Gold 6140, hot path, zero allocations:

| | |
|---|---|
| Subscriber prefix lookup (v4 / v6) | 3.6 ns / 7.0 ns |
| Cache hit | 344 ns |
| Cache miss | 262 ns |
| Rate-limiter decision | ~120 ns |

Live resolution against the real root servers: cold 1.1 s, warm 156 ms.

### 16.2 The rules that keep it there

- **Zero allocations per query where achievable.** `dns.Msg` buffers come from a
  `sync.Pool`; a pooled message is never retained past the handler.
- **Cache keys are comparable structs**, so a map lookup needs no allocation and
  no string concatenation.
- **Shards are powers of two** so the index is a mask, not a division. Cache 256
  shards, infra cache 64, rate limiter 16 (rounded up to a power of two).
- **Rate limits are indexed by class, not keyed by it** — a map lookup per packet
  is not worth paying for three constants.
- **Policy and subscriber lookups are atomic-pointer reads**, so a policy push
  never pauses resolution.
- **Rate-limiter shards are chosen by client prefix**, so all of one client's
  buckets share a shard and a flood from one source contends with nobody else.

### 16.3 The standing rule

Resolver or cache changes are not merged without a benchmark comparison against
`main` in the PR body. `make bench` runs the hot-path set.

**Known outstanding target:** `cache.Entry.RRsAt` (943 ns, 9 allocs) — it copies
RRs to count TTLs down. For contrast, `minimisedName` was cut from 1728 ns / 11
allocs to 633 ns / 3 by slicing the name rather than splitting and joining.

### 16.4 Subscriber privacy on the hot path

**Decision.** Full QNAMEs never appear in logs or metric labels above debug
level. `privacy.Redact` reduces a name to its registrable domain.

**Why.** A resolver log is a record of what subscribers looked at. Metric labels
are worse — they are scraped, stored and retained by default.

---

## 17. Accepted risk register

Everything we chose to live with, in one place.

| # | Risk | Why accepted | Mitigation / detection |
|---|---|---|---|
| 1 | **A compromised ns1 can poison ns2's cache** via the pair link | Re-validating every received entry doubles validation cost against an attacker already inside the trust boundary | Mutual TLS with a per-POP CA, enforced by config validation; the pair is one trust domain by design |
| 2 | **Concurrent edits to the same record during a pair-link partition**: one is superseded on heal | Deterministic, never corrupting; the OSS/BSS is normally the only writer. A primary was rejected on requirement | `cgdnsctl drift` + store-hash alerting |
| 3 | **A node down longer than 7 days can resurrect a deleted record** | The tombstone TTL has to be finite; a week outlives any realistic outage | Documented; a node out that long should be rebuilt, not rejoined |
| 4 | **Pair-link failure detection on an idle link takes up to 30 s** | There is no keepalive; nothing on the query path waits on the link | `cgdns_peer_outbound_up` / `_inbound_up`; a link carrying queries detects within `fetch_timeout` |
| 5 | **Health dampening state is lost on process restart** | Keeping it on disk adds a durability problem to a decision that should be fast | `StartLimitBurst=5` / `StartLimitIntervalSec=300` in the unit |
| 6 | **A POP going dark sends its subscribers to the next-closest POP** | This is the design, not a failure — anycast doing its job | Latency change only; `cgdns_anycast_advertised` per node |
| 6b | **A single node failure leaves the POP**, rather than being absorbed by the sibling: that address is then served from another state, and the remote same-role node carries two states' primary load | The price of never putting both of a subscriber's resolvers on one box (§1). The subscriber's other resolver stays local throughout | `cgdns_anycast_advertised` per node; capacity planning must assume a same-role node can inherit a neighbouring state's primary load |
| 6c | **The lab implements one shared anycast address on both nodes, not the two-address production model** | It was built to prove recursion, DNSSEC, failover and the pair link, all of which it did | Real, and called out in §3.4a — the two-address model has **not** been exercised end to end |
| 7 | **Nothing detects config drift between POPs automatically** | There is deliberately no cross-POP control plane | `cgdnsctl drift` is per-pair; cross-POP consistency is the provisioning system's job |
| 8 | **We own DNS correctness** rather than inheriting Unbound's two decades of hardening | The three features that justify the product all need to be inside the resolver | Named regression tests for every security invariant; RFC + section cited in source; live and lab verification |
| 9 | **NSEC3 zones get no aggressive-denial protection** | NSEC3 needs closest-encloser reasoning and per-candidate hashing; not yet built | Falls through to a normal lookup — correct, just not optimised. RRL still applies |
| 10 | **The TOTP secret is stored recoverable** | Verifying a code requires computing it | Store file mode; replicates only over the mTLS pair link |
| 11 | **`redirect` policy action returns an address the subscriber did not ask for** | It is what a walled-garden product requires | EDE 15 on every policy response so clients can tell |
| 12 | **Rate limiting could in principle limit our own health probe** | Probes come from loopback and are answers, not denials | Live flood test asserts `cgdns_anycast_advertised` stays 1; **re-check on any bucketing change** |

---

## 18. Not built yet, and why that order

| Item | Status and reasoning |
|---|---|
| **DoQ (RFC 9250)** | Lowest-value transport for this deployment — subscribers reach us over the carrier's own network, where DoQ's advantage over DoT is smallest. |
| **Aggressive NSEC3** | NSEC is done. NSEC3 means hashing each candidate with the zone's parameters and reasoning about the closest encloser. Those zones fall through to a normal lookup, which is correct but unoptimised. |
| **Config anti-entropy proven on live nodes** | Unit-tested, and the management API now makes runtime writes possible; the full multi-day live soak has not been run. |

**Order rationale.** The build order throughout has been: query path first
(nothing else matters if resolution is wrong), then the things that keep it
serving under attack (RRL, aggressive NSEC, serve-stale), then the things that
make it operable (management API, CLI, packaging), then the presentation layer
(WebUI). Every step has been deployed and exercised on the lab pair before moving
on.

---

## 19. Questions you are going to ask

**"Why not just run Unbound? It's free, it's proven, and it's someone else's
problem."**
Because the three things that make this a product rather than a resolver — per
subscriber policy with no I/O on the query path, cache sharing between the pair,
and a health decision that probes the real serving path and drives BGP — all
require being inside the resolver. With Unbound, policy becomes generated config
plus a reload on a box taking production traffic, cache sharing is impossible,
and health becomes parsing `unbound-control` output. See §2.1 for the full
comparison including PowerDNS and Knot. The cost of this decision is stated
honestly: we own DNS correctness now, and §7 and §8 exist because of it.

**"Two nodes with no quorum. What happens when they disagree?"**
They converge, deterministically, on the higher Lamport counter with node ID as
tiebreak — no clock synchronisation required (§5.1). The one case that loses
data is the same record edited on both nodes *during* a partition, which is
listed as accepted risk #2. What catches a real disagreement is the store hash:
`cgdnsctl drift` exits non-zero, and it refuses to report "in step" when fewer
than two nodes answered.

**"You built raft and then deleted it. Wasn't that wasted work?"**
It was ~830 lines, and deleting it was the right call the moment the architecture
became two nodes per POP: raft at N=2 has a quorum of 2, so a single node failure
freezes the control plane — strictly worse than LWW replication, which keeps
accepting writes. The code is shelved, not lost, and `internal/control` kept the
record types and publisher from it.

**"If ns1 dies, why doesn't ns2 just pick up its address? It's right there."**
Because then both of a subscriber's resolvers could be served by one machine,
and a node-level fault would take out both at once. Each node announces one of
the two service addresses, in every POP, so the primary and secondary are always
different hardware (§1). The cost is real and we accept it knowingly: BNE ns1
failing means BNE subscribers' primary is answered by SYD ns1 until it returns,
and SYD ns1 carries two states' primary load meanwhile — so capacity planning
has to assume a same-role node can inherit a neighbouring state. Their secondary
never moves. If that trade is ever judged wrong, §1 sets out the alternative
(both addresses on both nodes, optionally with MED so each is preferred on its
own node) — it would need BGP attributes `internal/health/gobgp.go` does not set
today.

**"Has the two-address model actually been run?"**
No, and §3.4a says so. The lab proved recursion, DNSSEC, health-driven
withdraw/advertise and the pair link — but on a *single shared* anycast address,
so the failover it demonstrated was within the POP, which is the behaviour
production will not have. The daemon does not block the real model
(`anycast_prefixes` is a list, each node reads its own config), but it needs
proving before the first production POP.

**"What happens if the link between ns1 and ns2 goes down?"**
Lab-verified with iptables DROP in both directions: both halves report the link
down, **both nodes keep resolving, and both stay in the anycast set.** Cache
sharing stops and config replication pauses; the link re-establishes within the
2 s redial tick on heal and repairs any gap by anti-entropy. Loss of the pair
degrades management and cache warmth, never resolution (§6.8).

**"How do I know this is actually validating DNSSEC and not just setting the AD
bit?"**
`AD` is set only when this resolver built and verified the chain itself, in both
resolver modes, with tests asserting a forwarded upstream's AD bit is stripped.
Verified live: `AD` set on iana.org and cloudflare.com, SERVFAIL with EDE 9 on
dnssec-failed.org. The subtle part is §8.3 — a stripped DS is treated as *bogus*,
not insecure, because an unproven insecure delegation is a downgrade attack.

**"An open recursive resolver is an amplification source. What stops that?"**
Four things: `listen.allow_query` is default-deny and **required** — the daemon
will not boot without it; a `/0` in it logs a loud startup warning;
`max_outbound_per_query` (32) caps what one client query can generate, shared
across every sub-lookup it triggers; and response rate limiting caps what a
spoofed victim receives, with slip so real clients survive.

**"Filtering feels like scope creep on a carrier resolver."**
Stated fairly and answered in §10.1. It is off unless enabled, and when off it is
not on the query path. The three boundaries in §10.2 are what keep it from
compromising the resolver: no I/O on the query path, only small mutable state
replicates, feed content never replicates. The per-subscriber whitelist is not a
nice-to-have — without it, one false positive on a customer's payment gateway
means editing a feed you may not own or losing the customer.

**"Who can reach the management API and the WebUI?"**
Only what `management.allow_from` lists, checked at `Accept` before TLS. A
wildcard bind is refused, sharing a non-loopback address with a DNS listener is
refused, and anything inside `health.anycast_prefixes` is refused by name. Off
loopback, TLS and an ACL are both mandatory. The WebUI cannot open its own
socket. Lab-verified refused on both anycast addresses (§13.1).

**"What's the blast radius of a bad config push?"**
Startup: the node refuses to boot and therefore never advertises, so it takes no
traffic. Runtime: a broken *feed* keeps the previously compiled rules serving —
filtering goes stale, resolution does not. A bad *subscriber* record replicates
to the sibling, which is why `cgdnsctl` re-reads after writing and why drift
alerting exists.

**"How much of this is actually tested versus asserted?"**
343 test/benchmark/fuzz functions, `-race` clean, **zero skips** — verified at the
time of writing. Beyond that: verified live against the real root servers and
against `dnssec-failed.org`; verified on the two-node lab POP for anycast
failover, graceful withdraw on SIGTERM, pair partition and heal, config
replication catch-up across a partition, a 15 000-query live flood, node
isolation for serve-stale, and a full run with IPv4 egress disabled entirely so
every outbound query went over IPv6. Each claim in this document says which kind
of evidence backs it.

**"Three of your bugs were found by watching a live daemon, not by tests. Doesn't
that undermine the test suite?"**
It bounds what a test suite can do, which is worth being honest about. The
prefetch no-op, the rate-limiter first-contact burst and the addressless-root
delegation all passed every unit test — the first two because the tests reused a
single bucket or entry, the third because it only appears against the real root.
Each now has a named regression test, verified by reverting the fix and
confirming failure. The standing rule from it is written into the project notes:
*"the metric says it ran" is not "it did something"*.

**"What stops a node that's cut off from the internet from holding the anycast
prefix?"**
This is the interaction in §12.2, and it is the one most likely to be got wrong.
Serve-stale keeps a cut-off node answering subscribers from expired cache — so
health checks explicitly **do not accept stale answers**. Lab-verified by cutting
both address families: the node kept answering cached names and still withdrew,
citing `. NS was answered from expired cache, so this node is not resolving`.
Note that isolating a node requires **both** `iptables` and `ip6tables` —
recursion runs over v6 too, and a v4-only rule proves nothing.

**"IPv6 — is it actually tested, or is it 'supported'?"**
Every listener and every outbound path is dual-stack, and the test suite runs
both families with **zero skips** (the transport tests call `requireIPv6`, which
skips *loudly* if v6 ever disappears — a green run with skips is not coverage).
Verified in the lab with v4 egress disabled entirely: iana.org, cloudflare.com,
nlnetlabs.nl and ripe.net all resolved over IPv6 only, DNSSEC still validating.

**"Why is there so little commenting in the source?"**
A deliberate standard: comments only where a reader genuinely cannot recover the
meaning from the code — a non-obvious *why*, the RFC and section that constrains
the behaviour, a deliberate deviation, or a real trap. Names carry the rest. In
particular a comment never narrates history ("this used to…", "faster than the
old…"), because git holds that far more reliably and a source file that doubles
as a changelog rots. Godoc on exported identifiers is the package contract and
stays. This document is where the history and the alternatives live.

---

## 20. Decisions still open

Genuinely undecided, flagged rather than hidden:

1. **Licence.** Not yet chosen. Needs deciding before any external distribution.
2. **Repository home.** The Go module path is currently
   `github.com/JoshFinlayAU/cgdns`, and the systemd unit's `Documentation=`
   points there — while the house convention is the self-hosted
   `gitlab.athenanetworks.com.au`. Worth settling deliberately, since changing
   it later is a `sed` across imports plus a packaging change.
3. **Whether a cross-POP *management* cluster is ever wanted.** Explicitly not a
   resolution cluster. The shelved raft implementation would be the starting
   point if so.
4. **Public IPv6 anycast addressing.** The lab uses a ULA for the v6 anycast
   address because a /128 from a connected /64 causes the router to attempt
   neighbour discovery on the wrong interface. Production needs a separately
   routed prefix.
5. **Canary check target.** `health.canary` is optional and currently unset.
   Pointing it at a third party means *their* outage withdraws our node — so if
   it is used, it must be something we operate.
6. **Prove the two-address anycast model in the lab** (§3.4a). The lab runs one
   shared address on both nodes; production gives each node its own. Needs a
   second address configured, each node announcing only its own, and a
   demonstration that withdrawing one node moves only that address, out of the
   POP, while the sibling keeps serving the other. This should happen before the
   first production POP, not during it.
7. **RFC 8326 `GRACEFUL_SHUTDOWN` community on planned maintenance.** Today a
   planned restart does a plain withdraw before the listeners stop, which works
   but drops whatever was in flight at the moment the route disappears. Tagging
   the routes with the well-known community first would let the adjacent router
   de-preference the path and drain traffic before withdrawal. Small change to
   `internal/health/gobgp.go`; worth doing before the first production POP.

---

### A note on the source of this document

Every decision above was verified against the code at the time of writing, not
recalled from notes. Where this document quotes a rationale, that rationale is
generally also in the source at the point it constrains behaviour — the config
validator's error messages in particular are written to explain *why* a
configuration is refused, not just that it was.

Seven doc comments and config comments still described replication as going
through raft (`internal/config/config.go` on `Subscriber` and `Policy`,
`internal/control/records.go`, `internal/policy/load.go`, the `internal/cache`
package doc, and two comments in `deploy/dev/cgdns-recursive.yaml`). They were
cosmetic — no behaviour depended on them — but they contradicted both the code
and this document, so they have been corrected to describe the control store as
it actually works.
