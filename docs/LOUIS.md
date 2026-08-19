# cgdns — the decision record

*Every significant choice in this project, what else was on the table, and why we
landed where we did. Written to be picked apart.*

> **Read [OVERVIEW.md](OVERVIEW.md) first.** It covers what the product is, what
> it is built from, the architecture decisions that matter, and what is needed to
> run a real-world test — in the order those questions get asked, and in about a
> third of the length.
>
> **This document is the reference behind it.** It exists so that any decision in
> the overview can be traced to its alternatives, its trade-off, and the test or
> lab run that keeps it true. Read it when you want the receipts on a specific
> point, not front to back.

---

## First, the question everyone opens with: why is there filtering in a carrier resolver?

It is the right thing to challenge, so it goes first rather than at §10 where it
would look buried.

**It was never an architectural ambition.** Nobody set out to build a content
filter. Filtering is here because of four separate pressures, and only one of
them is a product someone chose to sell.

**1. Somebody sells it.** "Filtered DNS", "family safe", "secure business DNS" —
whatever it ends up called, it gets sold as a value-add, and the resolver is the
only place it can be implemented. The resolver is the single point that sees
every subscriber's lookups and can already identify who is asking. Once that sale
happens, the capability either exists here or it does not exist.

**2. A carrier will, at some point, be required not to resolve something.** Court
orders, regulator directions, upstream security feeds. That obligation lands on
the carrier regardless of whether anyone bought a filtering product, and a
resolver with no mechanism to express it means implementing it somewhere worse —
in the routing layer, or by standing up separate infrastructure under time
pressure.

**3. The alternative is two resolver platforms, which is strictly worse.**
Without filtering here, filtered customers need a second platform: two codebases,
two config surfaces, two sets of failure modes, subscribers split across them by
product code, and an incident where the first question is "which platform is this
customer on". One platform with a per-subscriber ACL is a smaller, safer system
than two platforms without one.

**4. It is off unless you turn it on.** `policy.enabled: false` and the enforcer
is not in the handler chain at all — not bypassed per query, not present. A
deployment that never sells a filtered product pays nothing for this, in
performance or in complexity.

**So what is it, really?** An ACL with a per-subscriber exception list. That
framing is the whole answer: it is not a content-inspection system, it does not
look at traffic, and it makes exactly one decision — does this subscriber get an
answer for this name.

**The risk was never the feature.** It was mutable per-subscriber state landing
on the query path — because *that* is what could turn a carrier resolver into
something that stalls on a database, pauses on a policy push, or fails to resolve
because a blocklist would not download. That risk is contained by three
boundaries which are treated as contract, not convention (§10.2):

1. **The query path does no I/O for policy.** Lookups are lock-free reads of
   atomically-swapped structures. A policy push never pauses resolution.
2. **Only small mutable state replicates** — subscriber prefix map and overrides,
   roughly 4 MB at 500 k subscribers.
3. **Feed content is never replicated**, and a feed that fails to load leaves the
   previous rules serving. **Filtering degrades; resolution does not.**

**And why the per-subscriber allow list is load-bearing rather than a nicety.**
Every curated blocklist eventually false-positives on some customer's supplier or
payment gateway. Without a per-subscriber unblock, the only remedies are editing
a shared feed you may not own, or switching filtering off for that customer and
losing the revenue. The whitelist is what makes the product supportable at all,
which is why it is evaluated *before* class feeds and why that order is a
contract (§10.4).

If the conclusion is still that filtering does not belong in this product, the
argument to make is that requirements 1 and 2 above are not real — see §2.1,
where the same two requirements are what decide against buying Unbound.

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
`go vet ./...` clean, `gofmt` clean, `go test ./...` green across all 22
packages, **zero skipped tests**. 406 tests, 13 benchmarks and **nine fuzz
targets** over the wire parsers. POP-BNE — the first pair built to the reference
deployment model — is live, verified at the PE, and carrying real subscriber
traffic (§3.4c).

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
16. [Performance, privacy and telemetry](#16-performance-privacy-and-telemetry)
17. [Accepted risk register](#17-accepted-risk-register)
18. [Not built yet, and why that order](#18-not-built-yet-and-why-that-order)
19. [Questions you are going to ask](#19-questions-you-are-going-to-ask)
20. [Decisions still open](#20-decisions-still-open)

---

## 1. The shape of the thing

cgdns is a recursive DNS resolver for a carrier network. Two daemons — `cgdns`,
which answers queries, and `cgdns-routed`, which installs learned routes — one
operator CLI (`cgdnsctl`), one YAML config file shared by all three, and one
management REST API that the CLI and the embedded operator console both sit on.

The split between the two daemons is a privilege boundary, not a packaging
accident: installing routes needs `CAP_NET_ADMIN`, and **the process answering
queries from the internet must not also be able to reconfigure the network**
(§4.9).

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

#### The four requirements every candidate was measured against

Stating these first is what makes the rejections definitive rather than
preferences. A candidate had to be able to do all four **without being patched**,
because a fork of someone else's resolver that we maintain forever is a worse
position than writing our own, not a better one.

| # | Requirement | Why it is not negotiable |
|---|---|---|
| **R1** | Per-subscriber policy on the query path, identity by longest-prefix match on the source address, with a per-subscriber allow list beating shared class feeds, **and no I/O, no reload and no cache flush when it changes** | Provisioning events are continuous. A resolver that hiccups on every subscriber change is not carrier-grade (§10.2) |
| **R2** | Insert and retrieve **individual cache entries** at runtime, carrying remaining TTL and DNSSEC status | This is what push-on-fill and pull-on-miss between the pair are (§6.3) |
| **R3** | A health probe that traverses the **real serving path** — rate limiter, policy, serve-stale, resolver — whose result drives BGP | A probe of a private path proves the probe works (§4.2) |
| **R4** | Per-address `SO_REUSEPORT` sockets and per-family outbound source pinning | Anycast reply-source correctness (§3.4, §9.2) |

**R2 is the one that kills every candidate outright.** Not one of the four
mainstream recursors exposes per-entry cache insertion. That is not an oversight
on their part — a resolver's cache is a security boundary, and an API that lets
anything write into it is a poisoning primitive. Their position is right for
their product and disqualifying for ours.

#### Unbound — rejected on R1 and R2

The default choice, and the one that needed the most work to rule out.

- **R1: views cannot be created at runtime.** Per-client policy in Unbound is
  `access-control-view`, binding a source ACL to a named view. Views are declared
  in `unbound.conf` and read at startup or reload. `unbound-control` can modify
  an *existing* view's contents (`view_local_data`, `view_local_zone`) but cannot
  bring a new view into existence. **So a new subscriber with an override means
  editing a config file and reloading a box that is taking production traffic** —
  and at 500 k subscribers that is a config file with a view per subscriber.
- **R1: reload is not free.** `unbound-control reload` re-reads the whole config;
  historically it also dropped the cache, and while newer versions offer
  `reload_keep_cache`, the operation is still a stop-the-world re-parse of a
  file we would be generating. Compare with our atomic pointer swap, which costs
  the query path nothing and cannot fail halfway.
- **R2: no per-entry cache access.** `unbound-control` gives `dump_cache` and
  `load_cache`, which are whole-cache text dumps. There is no "insert this RRset
  with this remaining TTL". Pair cache sharing is therefore not implementable.
- **R3: partially achievable** — probing over loopback does traverse Unbound's
  real path — but the policy and rate-limiting layers would be Unbound's, and the
  internals we would need for the decision come from parsing
  `unbound-control stats_noreset`.
- **R4: achievable.** Unbound has `so-reuseport` and `outgoing-interface`. This is
  the one requirement it meets cleanly.
- **The escape hatch, and why it is worse.** Unbound has `dynlibmod`, so per
  subscriber policy could be a C module inside its event loop. That means writing
  C against a module ABI, in someone else's memory model, pinned to their
  internal structures across upgrades — strictly more risk than writing Go, and
  it still does not solve R2.

Licence (BSD-3) would have been no obstacle. It failed on capability.

#### BIND 9 — rejected on R1, R2 and on surface area

- **R1 and R2:** the same view-and-reload and no-cache-insert problems as
  Unbound. `rndc reconfig` to add a view.
- **Surface area is its own disqualifier.** BIND 9 is an authoritative server, a
  DNSSEC signer, a dynamic-update target, a catalog-zone consumer and a DLZ host,
  in addition to being a recursor. We need none of that, and every line of it is
  attack surface on a box reachable by every subscriber. The project's own goal
  line is "recursive DNS at carrier scale… bug free" — shipping five subsystems
  we do not use contradicts it directly.
- **Performance.** It is consistently the slowest of the mainstream recursors on
  recursion, which is why large recursive deployments have been migrating off it
  for a decade.

#### PowerDNS Recursor — the strongest candidate, and the closest call

It deserves an honest hearing, because its Lua hooks genuinely could express
most of R1.

- **What it gets right.** `gettag` is called per query specifically to classify a
  client cheaply and return a tag that selects downstream policy. With netmask
  trees for prefix matching, that is very close to `subscriber.Classify`.
  `preresolve`, `postresolve` and `nxdomain` cover the enforcement points, and
  RPZ is well supported.
- **R1 fails on the hot path, not on expressiveness.** `gettag` runs a Lua VM
  **per query**. Our budget is zero allocations and a 3.6 ns classification
  (§16.1); a scripting VM invocation per query is orders of magnitude off that,
  and it introduces a second garbage collector interacting with the process under
  load. PowerDNS's own documentation warns about the cost of per-query Lua.
- **R1 also fails on the update path.** Reloading policy means re-running the Lua
  script. There is no incremental "this one subscriber changed" path, and no
  replication of that state to a sibling — we would be building §5 and §6
  regardless.
- **R2 fails outright.** `rec_control` offers `wipe-cache` and `dump-cache`. There
  is no insert.
- **The decisive practical point.** Choosing PowerDNS means writing: a Lua policy
  layer, an external control-plane store, an external replication daemon, an
  external health daemon driving BGP — **that is most of this repository** — and
  at the end of it still not having pair cache sharing. The build is not avoided,
  only fragmented across two languages and two processes.
- **Licence: GPLv2.** With the project licence still undecided (§20), building
  the product on a GPLv2 core constrains that decision permanently. That is a
  commercial consideration, not a technical one, but it is real and it is
  irreversible.

#### Knot Resolver — rejected on R1, R2 and licence

- **What it gets right.** The `view` module does per-subnet policy directly, and
  Knot Resolver 6's declarative config with a management API is architecturally
  the closest of any candidate to what we built.
- **Its cache is the only one that is externally addressable at all** — LMDB,
  memory-mapped and shared between worker processes on one machine. That is worth
  acknowledging honestly. But it is shared *between processes on a host*, not
  between hosts: LMDB over a network filesystem is unsafe, and the layout is an
  internal format with no stability guarantee. **Building pair replication on
  another project's undocumented on-disk format is a maintenance trap** — every
  upstream release becomes a risk to our replication.
- **R1**: per-query Lua policy, same objection as PowerDNS.
- **Licence: GPLv3**, which constrains the licence decision harder than PowerDNS
  does.
- Smaller operator community locally, which matters at 3 a.m.

#### CoreDNS — the "why not extend a Go project" answer

This is the sharpest version of the question, because CoreDNS is Go, has a clean
plugin chain, and would let us write policy in the same language.

- **It is not a recursive resolver.** CoreDNS forwards; its `forward` plugin
  sends queries to an upstream. There is no delegation walk, no bailiwick
  handling, no DNSSEC chain building. The historical way to get recursion under
  CoreDNS was a plugin wrapping **libunbound via cgo** — which lands us back at
  Unbound, now with cgo in the build and a third project in the dependency chain.
- **Its performance model is wrong for this.** The plugin chain and its message
  handling allocate per query; it is built for Kubernetes service discovery at
  moderate rates, not carrier recursion with a zero-allocation hot path.
- So CoreDNS would have given us the language, and none of R1–R4.

#### dnsmasq, systemd-resolved, nscd — category, not capability

All three are stub or forwarding caches for a host or a small network. None
recurses; each requires a real recursive resolver behind it. They are consumers
of this product, not alternatives to it. nscd gets its own entry below (§2.1a)
because it is the one most often raised.

#### Buy rather than build

Commercial carrier DNS platforms exist and do all of this. That is a genuine
option and was weighed as one. Against it: recurring per-subscriber licensing on
a function that is pure cost, no ability to change filtering behaviour on our own
timetable, subscriber query data leaving our control, and an upgrade cadence set
by a vendor. The build cost here is bounded and now largely spent; the licence
cost would have compounded for as long as the product existed.

---

### Why we went this way — the positive case in full

The rejections above say what would not work. This is what the chosen approach
actually buys, beyond avoiding those problems.

**1. All four requirements land in one process, so there is one failure domain.**
During an incident there is one log stream, one metric namespace, one config
file, one binary version to confirm. The alternative architectures all end as
"our daemon plus their daemon plus a glue layer", where the interesting failures
live in the seams and no single component's logs explain them.

**2. Policy changes cost the query path nothing.** `policy.Registry` and
`subscriber.Classifier` both swap an atomic pointer. A provisioning push does not
reload a config, does not regenerate a file, does not flush a cache, and cannot
pause resolution. Measured: 3.6 ns / 7.0 ns per classification, zero allocations
(§16.1). No candidate could offer this without a per-query scripting VM or a
config reload.

**3. Cache sharing is expressible at all.** Push-on-fill and pull-on-miss with
TTL decremented in transit and DNSSEC status carried alongside (§6.3, §6.4)
require direct entry access in both directions. Owning the cache is the only way
to have it, and it is what makes a cold node useful within seconds of joining its
pair rather than within a TTL cycle.

**4. Health means what it says.** The probe runs
`udp → ratelimit → policy → servestale → resolver` — the same chain a subscriber
traverses — so a pass means subscribers are being served, not that a control
socket answered. This is not theoretical: the probe caught a real
addressless-delegation bug that every unit test missed (§4.2), and it is what
lets serve-stale and health interact correctly (§12.2) rather than a cut-off node
holding its prefix forever.

**5. The client's wall-clock budget threads through everything for free.** Go's
`context` deadline is derived once from the client budget and carried into every
outbound query, every glueless nameserver lookup and every DNSSEC chain fetch, so
one inbound query genuinely cannot exceed its allowance (§7.2). Retrofitting that
guarantee into an event-loop C daemon's callback structure is exactly the kind of
change that gets it 95 % right and leaves a path that ignores the deadline.

**6. Every security invariant is ours to test.** Bailiwick rules, the 32-query
amplification cap, 0x20 verification, stripped-DS-is-bogus — each has a named
regression test that fails if the property regresses (§7, §8). With a wrapped
resolver those properties are real but unowned: we would be trusting them, not
verifying them, and we could not add one the upstream did not already have —
aggressive NSEC scoped by the SOA's own zone (§8.8) being a concrete example.

**7. Telemetry is defined by us, including what it deliberately omits.** 87
series, and **no QNAME or client-address label anywhere, by construction**
(§16.5). With a wrapper, the telemetry is whatever they expose and the privacy
property is not ours to guarantee — a subscriber browsing history reconstructable
from a metric series would be our problem and someone else's design.

**8. One static binary, one config file, no runtime dependencies.** Packaging is
`go build` plus nfpm; upgrade is replacing a file. No shared library ABI, no
scripting runtime to keep patched, no second daemon whose version must be matched.

**9. The licence stays an open decision.** Not inheriting GPLv2 or GPLv3 from a
core dependency keeps §20 an actual choice.

**10. The failure modes are ones we can reason about.** Every accepted risk in
§17 is one we chose and can measure. Wrapping means inheriting a set of failure
modes that are someone else's design, discovered during incidents.

---

### What would make this decision wrong

Stated plainly, because a decision record that cannot be falsified is marketing.

**If per-subscriber policy and pair cache sharing were both dropped from the
product, Unbound would be the correct answer and this project would not be
justified.** R1 and R2 are what carry the decision; R3 and R4 are achievable
elsewhere with effort. Anyone arguing to buy or wrap should be arguing that those
two requirements are not real — that is the actual debate, and it is a legitimate
one to have.

The other way it goes wrong is sustained under-investment: a resolver we own
needs the invariant tests kept green and the RFC behaviour kept current. That
obligation does not end, and it is the true cost of the decision.

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

### 2.1a Why nscd is not in that table

It comes up, and it is a fair question to ask, because the name reads as "the
Linux DNS cache daemon". It is worth answering properly rather than waving away.

**What nscd actually is.** glibc's **Name Service Cache Daemon**. It caches
**NSS** lookups — `passwd`, `group`, `hosts`, `services`, `netgroup` — on behalf
of **processes running on the same machine**, reached over a local Unix socket.

**Why it is not a candidate, in order of severity:**

1. **It is not a DNS server.** It does not listen on port 53, does not speak the
   DNS wire protocol to clients, and cannot answer a subscriber's query. A
   subscriber's CPE cannot point at it.
2. **It does not resolve.** nscd caches the *result* of `getaddrinfo()`, which it
   obtains by asking whatever `/etc/resolv.conf` names. It therefore **requires a
   real recursive resolver behind it** — it is a consumer of the thing this
   project builds, not a substitute for it.
3. **It caches names, not RRsets.** Its `hosts` cache is name→address. There is no
   MX, TXT, SRV, NS, SOA, CNAME chain or DNSKEY, because NSS has no concept of
   them.
4. **It ignores DNS TTLs.** The `hosts` cache expires on a configured
   `positive-time-to-live` constant, not on the TTL the authoritative published.
   For a carrier that is disqualifying on its own: CDN and cloud failover *are*
   TTLs, and a cache that overrides them hands subscribers endpoints that have
   already moved.
5. **No DNSSEC, no EDNS, no TCP fallback, no 0x20, no QNAME minimisation.** None
   of §7 or §8 exists in it, and none of it could.
6. **Single host, no anycast, no pair, no policy, no operator API**, and no
   metrics beyond `nscd -g`.

**The correct comparison for nscd is `systemd-resolved`'s cache or a browser's
DNS cache** — a client-side stub cache — not Unbound or BIND. If anything, nscd
is what a subscriber's own Linux box might run *in front of* cgdns.

**Its trajectory, for completeness.** nscd is still shipped by glibc upstream and
still packaged by Debian, so "it was removed" would be wrong. But Fedora
deprecated it in F34 and dropped the subpackage in F35, pointing users at
`systemd-resolved` and `sssd`; and glibc 2.40 (July 2024) shipped fixes for four
nscd CVEs, including a stack-based buffer overflow in the netgroup cache
(CVE-2024-33599). It is not where the ecosystem is investing. That is a
supporting argument only — points 1 to 3 above decide it on their own.

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
| `quic-go/quic-go` | QUIC transport for DoQ (§9.5) | Go has no QUIC in the standard library; this is the only mature pure-Go implementation |
| `vishvananda/netlink` | Kernel route installation in `cgdns-routed` (§4.9) | Netlink is the only sane way to install a route from Go; the alternative is shelling out to `ip route`, which the project forbids for the same reason it forbids `vtysh` |
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
  shared cache.
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
raft-boltdb, plus memberlist gossip, roughly 830 lines, working and tested — is
not part of the product.

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

### 3.4 Four interfaces per node, one job each — and no loopback

**Decision.** The reference model, set out in full in
[provisioning.md](provisioning.md):

| Interface | Role | Addressing |
|---|---|---|
| `eth0` | eBGP to this node's PE, **and the source of every outbound query** | public v4 + v6, sized to the PE link — a `/31` (RFC 3021) or `/30`, and a `/127` (RFC 6164) |
| `eth1` | pair link: config replication and cache sharing | public space, `/31` + `/127`, never announced |
| `eth2` | management: operator API, metrics, SSH | management prefix and gateway, **no default route** |
| `anycast0` | the service address subscribers query | `/32` + `/128` on a dummy device |

**Why queries must never be sourced from `anycast0`.** That address exists in
every POP, so a reply addressed to it follows BGP to whichever POP is nearest
*the authoritative server* — not necessarily the one that asked:

```
ns1 @ POP-A  --query, src <anycast>-->  root server
             <--reply, dst <anycast>--  routed to POP-C, not POP-A
POP-C's ns1: never asked -> dropped.    POP-A's ns1: times out.
```

Intermittent, load-dependent, and only visible in production. Sourcing from
`eth0` makes the address unique to one node, so replies come home.

**The consequence people miss: `eth0` is the one leg that touches the public
internet.** The resolver walks the delegation chain itself and talks to root, TLD
and authoritative servers directly, and they reply to whatever source the query
carried. So `eth0` must sit inside an aggregate the AS announces globally, even
though no subscriber ever addresses it. The `/31` itself never leaves the
network; longest-match does the rest.

**There is no loopback interface, and that is deliberate.** A loopback earns its
place when an address must outlive any single interface — a node dual-homed to
two PEs cannot source from either link's address, because that address dies with
its link. With one uplink per node, `eth0` going down takes the node with it
regardless, so a separate loopback buys nothing. **Add one the day a node gets a
second uplink, and not before.** Single-hop eBGP peers over the interface either
way.

**One node, one PE.** Two nodes peering with the same router makes that router a
single point of failure for the whole POP: it dies, both anycast addresses
withdraw together, and the second node bought nothing.

**Management supplies no default route.** It takes a prefix and a gateway in
their own table, with a policy rule so traffic sourced from the management
address replies out the management interface. The only default in the main table
is the one BGP learns. Accepting a management default and relying on metrics to
make it lose works right up until BGP drops, at which point management silently
becomes the service path.

**The pair link is numbered from public space but never announced.** It is a
directly connected link between two adjacent boxes, so it needs no reachability
beyond the pair. Public numbering keeps ICMPv6 errors and traceroute honest and
avoids the source-selection surprises ULA brings (RFC 6724). What crosses it is
mutually authenticated TLS regardless.

**The anycast prefix stays inside the routing domain.** Subscribers are internal,
so a `/32` in iBGP with `no-export` is right; leaking it further would draw
traffic toward a node that may not be the nearest.

### 3.4a Where the lab differs from the production model — stated, not glossed

**The lab pair predates the reference model and reaches equivalent behaviour by
other means.** It is a worked example, not the reference, and the differences are
wider than a single setting:

| Lab | Reference model (§3.4) |
|---|---|
| Both nodes peer with one router over a shared `/29` | one node per PE |
| A separate `loopback0` holds the query source | `eth0` is the query source; no loopback |
| RFC 1918 and ULA addressing, masqueraded out by the router | public space, no NAT |
| Static return routes on the router to reach each loopback | not needed — `eth0` is natively routed |
| A dedicated interface (`eth3`) carries v6 on its own VLAN | v6 rides `eth0` alongside v4 |
| One shared anycast address across the pair | each node owns its own |
| One POP | the same two addresses announced from every POP |

The `eth3` split was a workaround for a lab environment with no v6 on the BGP
path, not part of the design.

**What each has proved.** The lab proved the *software* — recursion, DNSSEC
validation, health-driven withdraw/advertise, failover within the pair, the pair
link, rate limiting under live flood, serve-stale isolation. The reference
topology is proved at POP-BNE (§3.4c), which is where the addressing, peering and
anycast behaviour are demonstrated rather than reasoned about.

### 3.4b Verify at the far end, not the near end

**A principle earned the hard way, and it belongs in this document because it
changes what a green dashboard is worth.**

`cgdns_anycast_advertised` reports the node's own internal health decision. It
says **nothing** about whether a route ever left the box.

The failure that taught it: a gobgpd import filter placed in
`[global.apply-policy]` rather than per-neighbour also judges the routes the node
*originates*, so the anycast prefix never enters the RIB. Both the gRPC API and
`gobgp global rib add` return success having done nothing — **the node reports
itself advertised while the PE has no route to it at all.** Silent, and in the
safe-looking direction.

What follows:

- Confirm an announcement **on the PE**, not on the node.
- Confirm which family and source address are really in use with a **packet
  capture**. A `dig` that returns an answer proves an answer came back, not what
  produced it.
- Confirm withdrawal by stopping the service and watching the PE lose exactly
  that node's two prefixes.

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

### 3.4c POP-BNE — the reference model, deployed

**The first pair outside the lab, and the first built to `provisioning.md`.**
Two nodes, one PE session per node per family, public addressing in both
families, no NAT, `eth0` as the query source, each node owning its own anycast
`/32` and `/128`.

Verified where it counts — **at the PE, which is the only place that proves an
announcement landed**: all four prefixes active with native next hops, both nodes
learning and installing a default per family at metric 5 with the correct
preferred source, 6/6 signed domains validating with `AD` over both anycast
addresses in both families, and **every outbound query carrying `eth0`'s address
rather than the anycast one, confirmed by capture**. Encrypted transports answer
on both addresses under **publicly trusted Let's Encrypt certificates issued
automatically**, and the pair link is up in both directions serving cache fetches
between the nodes. Four services run on each node: `cgdns`, `gobgpd`,
`cgdns-routed` and `cgdns-probe`. It carries a household's real traffic.

**Two settings at POP-BNE differ from the shipped defaults, and in both cases
the deployed value is the correct one.** They look like tuning and are not:

| Setting | Default | POP-BNE | Why the deployed value is right |
|---|---|---|---|
| `resolver.accept_sha1` | false | **true** | RFC 8624 makes RSASHA1 NOT RECOMMENDED for *signing* but **MUST for validation**. Refusing it protects nobody and makes zones that still sign with it — including many `.gov` zones — unreachable (§8.4) |
| `resolver.max_outbound_per_query` | 32 | **100** | It bounds honest work, not loops; loops are capped by `max_delegation_depth` and `max_cname_chain` (§7.2). A CDN-fronted name crosses several zones by CNAME, each needing its own DNSKEY and DS, so a low ceiling SERVFAILs names people use daily |

**Filtering is not enabled there.** The configuration carries no `policy` block,
so the enforcer is not in the query path at all (§10.1) — the correct state until
a product needs it.

**One deliberate divergence, and it has a cost.** POP-BNE peers **iBGP inside
AS135559** rather than the private-ASN eBGP `provisioning.md` describes, matching
the pattern already used in the estate. The consequence is **iBGP split
horizon**: a route learned from one iBGP peer is never re-advertised to another,
which is the rule that keeps a full mesh loop-free — so the anycast prefixes
reached the PE and stopped one hop later. The PE could reach them and nothing
else in the estate could. Resolved by making the PE a route reflector for those
sessions.

**eBGP with a private ASN avoids this entirely**, because eBGP-learned routes
propagate into iBGP without reflection. Both work; the choice is not cosmetic,
and the second POP is the moment to make it deliberately rather than inherit it.

**Three things the turn-up surfaced, worth carrying to the next site:**

1. **Management was handing out an IPv6 default.** `eth2` accepted RAs and
   installed a default at metric 512, beating the real one on `eth0` at 1024, so
   every v6 packet left via management. `accept-ra: false` plus flushing the
   learned state — which netplan does not do for you. Silent, and the box looks
   fine.
2. **Both families on one BGP session does not work.** A v6 NLRI carried on a v4
   transport arrives with an IPv4-mapped next hop that neither end can forward
   on, so the v6 default was received and not installable. One session per family.
3. **A PE filter matching `dst-len == 32` silently drops every v6 `/128`.**
   Length matches need writing per family.

---

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

1. **An import filter belongs on each neighbour, never in
   `[global.apply-policy]`.** A global `default-import-policy = "reject-route"`
   also judges the routes this node *originates*, not just those it receives, so
   the anycast prefix never enters the RIB. Both the gRPC API and `gobgp global
   rib add` return success having done nothing — the session establishes, the
   node reports itself advertised, and the PE has no route to it at all. Filter
   per-neighbour with an explicit prefix-set instead; see `provisioning.md` §2
   for the working shape. This is the origin of the rule in §3.4b: **check the
   PE, not the resolver.**
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

### 4.9 `cgdns-routed` — installing the routes gobgpd learns

**The gap it closes.** gobgpd is a BGP *speaker*: it holds a learned route in its
RIB and never puts it in the forwarding table. That is enough to advertise an
anycast address, which is all the resolver needed at first — but it means a node
**cannot use a default its upstream is offering**, and keeps a static one even
when that next hop is gone.

**Alternatives.**

| Option | Why not |
|---|---|
| Adopt a full routing suite (FRR, BIRD) on the resolver | An enormous amount of machinery, and a second routing daemon's worth of attack surface and failure modes, to install one default route |
| Shell out to `ip route` from cgdns | Forbidden by the same rule that forbids `vtysh` and `birdc`: parsing and driving a CLI makes routing behaviour depend on a text format nobody versions |
| Have the resolver install routes itself over netlink | It would need `CAP_NET_ADMIN`. See the privilege argument below — this is the whole reason it is a separate binary |
| Static routes only | Works until the next hop is gone, which is precisely the case worth handling |

**Why it is a separate daemon, and this is the point of it.** Installing routes
needs `CAP_NET_ADMIN`, and **the process answering queries from the internet must
not also be able to reconfigure the network.** The `cgdns-routed` unit grants
that one capability and nothing else — not even the `CAP_NET_BIND_SERVICE` the
resolver has. Neither daemon can do the other's job.

**Deliberately narrow, in three ways:**

1. **Prefixes are matched exactly against an explicit allow list.** Accepting a
   default does not accept the routes inside it. Config validation refuses an
   empty list rather than defaulting to "anything": *"the agent installs nothing
   without one, and an empty list is more likely a mistake than an intention."*
2. **At most `max_routes` are held**, so a loose filter upstream cannot become a
   full table in the kernel.
3. **It only ever deletes routes it installed**, identified by protocol.

Between the router's output policy, gobgp's import policy and this list there are
three filters — **and only the last is not somebody else's configuration to get
wrong.**

**Installed routes carry a preferred source, and that was learned the hard way.**
It was not in the first version. A static default written by hand usually pins a
source; the learned route that replaced it did not, so **the node's egress
address silently moved off its intended interface**. Resolver queries were
unaffected, because they pin their own source — but nothing else on the node did.
Config validation now requires `route_agent.source_v4`/`_v6` to match what the
resolver sources from.

**The metric is below any static fallback**, so a learned route wins while it
exists and the static one takes over the instant it is withdrawn.

**It polls rather than streams.** A default route changes rarely, and a reconcile
is idempotent: it repairs drift from anything that touched the table behind us,
which a stream of deltas would not.

**Lab-verified on ns2** with gobgp filtered to accept only a default: the router
advertising a default put it in gobgp's RIB and *not* the kernel; starting the
agent installed it with the right preferred source and metric, beating the static
route; withdrawing it removed the route within one interval and egress fell back
to the static route, with resolution unaffected throughout.

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

**What the outbound cap actually bounds, and it is worth being precise.** It
bounds *honest work*, not loops — loops are already caught by
`max_delegation_depth` and `max_cname_chain`. A CDN-fronted name crosses several
zones by CNAME, and each zone needs its own DNSKEY and DS fetched, so the count
climbs quickly on names people use every day. **Set it too low and the resolver
SERVFAILs ordinary names**; the shipped default of 32 is the conservative
reading and production runs 100, which is the working figure.

It is still the amplification bound in the sense that matters — one inbound
query can generate at most that many outbound ones, and every sub-lookup it
triggers draws from the same allowance.

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

**Why the algorithm list is what it is.** SHA-1 is no longer collision
resistant, so it has no business signing anything.

**But refusing it as a validator is a different question, and the answer runs
the other way.** RFC 8624 makes RSASHA1 **NOT RECOMMENDED for signing and MUST
for validation** — the asymmetry is deliberate. A validator that refuses it does
not stop anyone forging, because a forger simply would not use it; what it does
is make every zone still signed with RSASHA1 unresolvable, and that set still
includes many `.gov` zones. **The subscriber experiences that as the resolver
being broken.**

So the shipped default is the conservative reading and **production runs with
`accept_sha1: true`**, which is the correct operational choice. The knob exists
so the decision is explicit either way rather than buried.

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

### 8.7 Validate once on insert, trust on hit — and record that it happened

**Decision.** A cache entry marked `Authenticated` is served as Secure without
re-verifying. Separately, every entry records whether validation was **actually
run** (`Validated`), as distinct from what the verdict was.

**Why not re-verify.** It would put public-key cryptography on the hot path for
no added assurance — the entry has not changed since we verified it, and the
cache is node-local memory.

**Why the second flag exists, and it is the subtler half.** A cached entry keeps
**no signatures**. The delegation walk caches records on its way past — delegation
NS sets, glue, the root's own NS RRset — and those were never judged. Without a
way to tell "not judged yet" from "judged, turned out insecure", a later client
query for one of those names re-validates a cached copy **against evidence the
cache never kept**, and the name fails for as long as the entry lives.

Now: *not judged* is passed over and resolved again; *judged insecure* is served
without `AD` and without being re-walked on every hit.

**This one caused a full-POP outage in the lab**, and it is worth understanding
because of how far the blast radius travelled from the bug. The failure reached
**the root's own NS set** — at which point the health probe, which resolves `. NS`
through the real serving path, failed on both nodes. Both withdrew themselves
from the anycast set. A cache-metadata bug three layers away from the health
check took the POP off the air.

Two readings, both fair. The health check **worked** — it is designed to catch
"this node cannot resolve" regardless of cause, and it did, on a cause nobody
anticipated. And it is exactly the class of bug we took on by owning the resolver
(§2.1). Both are in this document rather than one of them.

### 8.7a Each RRset is verified against its own signer

**Decision.** Verification uses the keys of the zone that signed each RRset, not
one zone chosen for the whole answer (RFC 4035 §5.3.1). The answer takes the
status of its weakest link.

**Why.** A CNAME crossing a zone boundary is signed by one zone and its target's
address records by another. Verifying the whole answer under a single zone's keys
fails on one side of the cut or the other — and it fails on perfectly valid data,
which is the worst kind of validation failure.

### 8.7b An unreachable authority is not a verdict on a zone

**Decision.** A DNSKEY or DS that could not be *fetched* surfaces as EDE 22/23
with its own counter (`cgdns_dnssec_unavailable_total`), not as Bogus. The answer
is still withheld — unvalidated data is never served.

**Why.** Reporting Bogus tells an operator their signing is broken when the truth
is that **this node could not see**. That sends someone to debug a zone that is
fine, while the actual fault — a reachability problem on our side — goes
unexamined. The distinction costs one counter and saves an incident.

### 8.8 Aggressive NSEC (RFC 8198)

**Decision.** A validated signed denial says "nothing exists between these two
names", so one denial answers for every name in the gap. `internal/aggressive`
stores those ranges and synthesises denials from them. On by default.

**Why.** Against a random-subdomain (water-torture) flood aimed at a **signed**
zone this is the strongest defence available, because the denial is answered here
rather than at the zone being attacked.

**Measured on the live internet, 50 random names per zone:**

| Zone | Denial type | Synthesised | Outbound |
|---|---|---|---|
| `nlnetlabs.nl` | NSEC | 49/50 | 6 |
| `isc.org` | NSEC3 | 49/50 | 6 |
| `debian.org` | NSEC3, large zone | 4/50, rising to 22/50 as the chain cached | 294, falling to 234 |
| `google.com` | unsigned (control) | 0/50 | 250 |

**The NSEC/NSEC3 gap is inherent, not an implementation shortfall.** NSEC gaps
are contiguous in name space, so one denial covers many made-up names at once.
NSEC3 hashes scatter names uniformly across the chain, so each made-up name tends
to land in a different gap. The result is close to total protection on a small or
NSEC-signed zone, and a gradual saving that improves as the chain caches on a
large NSEC3 one. An unsigned zone gets nothing from this — there is no proof to
reuse — which is what the `google.com` row is there to show.

**A correction worth recording, because it is a lesson about measurement.** An
earlier version of this claimed "zero outbound queries". That figure was read
from `cgdns_recursion_outbound_queries_total`, **which does not exist** — the
metric is `cgdns_recursion_outbound_total` — so the shell arithmetic subtracted
two empty strings and produced a zero that meant nothing. The synthesis counts
were real; the outbound figure was not. Same family of error as the prefetch
no-op in §12.5: a number that agrees with what you expect is not evidence until
you have checked it is a number at all.

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
- **NSEC3 is handled, and more strictly than NSEC.** An NSEC records a gap
  between names and can be checked against a name directly. NSEC3 records a gap
  between *hashes*, and a hash says nothing about where a name sits, so proving
  absence needs three records together: one matching the closest encloser, one
  covering the next closer name, and one covering the wildcard that could
  otherwise still answer.
- **Opt-out spans are never used.** Such a span may contain unsigned
  delegations, so it proves only that nothing *signed* is there. Treating it as
  proof of absence would let this node deny names that genuinely exist.
- **Unknown hash algorithms and iteration counts above the RFC 9276 limit are
  refused**, not reasoned about.

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

### 9.1 All five, all dual-stack: UDP, TCP, DoT, DoH, DoQ

| Transport | RFC | Note |
|---|---|---|
| UDP | 1035 | `SO_REUSEPORT`, one socket per CPU per address |
| TCP | 7766 | Multiple queries per connection, idle timeout |
| DoT | 7858 | Reuses the TCP connection loop under a TLS listener — the framing is identical |
| DoH | 8484 | HTTP/2, GET and POST |
| DoQ | 9250 | QUIC, one stream per query — no head-of-line blocking between concurrent queries |

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

### 9.5 DoQ (RFC 9250)

**Decision.** DNS over QUIC, served on 853/UDP — the same port number as DoT but
a different socket, since one is TCP and the other UDP.

**What it buys over DoT.** QUIC gives each query its own stream, so
head-of-line blocking between concurrent queries disappears. On DoT, one slow
answer stalls everything behind it on the same TCP connection.

**Decisions inside it:**

- **ALPN `doq` is set by the listener, not taken from the caller.** A listener
  that negotiated anything else would not be a DoQ listener, and a client that
  does not offer the token is refused during the handshake rather than after.
- **`doq_max_streams_per_conn`** caps concurrent queries on one connection. That
  is what stops a single client opening unbounded work — the QUIC equivalent of
  the bounded worker pool on UDP (§9.3).
- **Addresses are bound individually, never a wildcard**, for exactly the same
  reason as the UDP listener: a reply has to leave from the address it arrived
  on (§9.2).
- RFC 9250's application error codes are used properly, including
  `0x4 DOQ_EXCESSIVE_LOAD` for shedding a client rather than dropping it silently.
- **RFC 9250 §4.2.1:** the message ID on a DoQ stream is zero, because a stream
  carries exactly one exchange. Answering a non-zero ID would invite clients to
  treat a stream as multiplexed. There is a test for it.

---

## 10. Subscriber policy and filtering

### 10.1 Why a carrier resolver has per-subscriber policy at all

**Answered at the top of this document**, since it is the first thing anyone
challenges: a product someone sells, an obligation a carrier gets handed anyway,
and the fact that the alternative is two resolver platforms rather than one with
an ACL.

Two implementation facts that back the "it costs nothing when unused" claim,
since it is the part most worth verifying rather than believing:

- **The enforcer is conditionally constructed, not conditionally executed.**
  `buildPolicy` returns a nil classifier when `policy.enabled` is false, and the
  handler chain only wraps `policy.NewEnforcer` when that classifier is non-nil
  (`cmd/cgdns/main.go:266-274`). With filtering off there is no policy frame on
  the stack, no branch per query, and no metrics to maintain.
- **Nothing about policy is reachable from the query path except memory.** See
  §10.2 — that is the property that makes the feature safe to ship in a carrier
  resolver at all.

**Where the boundary sits with the rest of the business.** The local control
store is authoritative at runtime, but records are created and edited by the
existing OSS/BSS over the management API. The resolver *consumes* policy and
never owns subscriber lifecycle — no billing sync, no customer records, no
retention obligations. That is deliberate: it keeps CRM concerns out of a daemon
whose job is to answer queries, and it is consistent with the operator-only
tenancy decision in §13.10.

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

### 10.5a Fetching a feed is a control-plane operation wearing the clothes of a download

**Decision.** A feed record carrying a URL is fetched on a schedule, hashed into
a temporary file and renamed into place, then compiled into new rules that are
swapped into the query path — **with no restart**.

**Why it is treated as control-plane rather than as a download.** A feed decides
what subscribers are allowed to resolve. Something that can silently change that
is a control-plane input, and gets control-plane handling:

- **A record may pin a SHA-256. It is checked whenever present, and it is
  *required* for an `http://` URL** — a list fetched over plain HTTP can be
  rewritten by anyone on the path.
- **Content is hashed into a temporary file and renamed into place**, so a reader
  sees the whole old feed or the whole new one and never half of either.
- `cgdns_feed_hash_mismatches_total` above zero is worth an alert: the feed was
  tampered with, or its publisher changed it without telling the control plane.

**Every failure keeps the previous content** — a bad hash, a timeout, an HTTP
error, a feed over its size cap, or one that came back **empty**. That last case
is the one worth stating: an empty list would silently unblock everything it used
to block, which is a filtering product quietly ceasing to be one. One broken feed
does not stop the others refreshing.

**A refresh that changes nothing does not republish**, because recompiling
identical rules would swap the query path's tables for no reason.

**`POST /api/v1/policy/refresh` forces one**, because a feed added through the API
otherwise waits for the next interval — which is an odd thing to explain to
someone who has just pressed save.

**Two validation rules encode the reasoning:** `feed_refresh_interval` may not be
under a minute (*"refetching a blocklist more often than that costs the publisher
more than it gains anyone"*), and `feed_max_bytes` must be set, because an
uncapped feed can fill the disk of every node subscribed to it.

**Verified end to end on a dev node:** a feed served over HTTP with a pinned
digest was fetched, compiled, and blocked its names with EDE 15 while other names
resolved; changing the content refreshed and recompiled with no restart; and
rewriting it *without* updating the digest was refused, counted, and left the
previous list serving.

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

Every position in that chain is load-bearing:

- **Serve-stale sits *inside* policy**, so a blocked name stays blocked even when
  the answer comes from expired data. The other order would let a filtered
  customer reach a blocked name precisely when upstream is broken.
- **Rate limiting wraps everything**, so it sees the response actually bound for
  the client — **including one that policy rewrote**. A device hammering a
  blocked name is still a device hammering us, and a limiter placed inside policy
  would never see that traffic.
- **Policy sits outside the resolver**, so a blocked name is never resolved at
  all. Filtering that resolved first and discarded the answer would leak the
  lookup to the authoritative and pay the latency for a result nobody receives.

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
exact opposite of a management address. Everything in the routing domain that
carries the prefix routes to it, and it
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

### 13.9a The local node is managed over a unix socket, not a token

**Decision.** `cgdnsctl` talks to `/run/cgdns/control.sock` for the node it runs
on. The file is `0600` and the peer's uid is checked at accept, so the request is
authorised by the socket rather than by a bearer token. Tokens remain what a
*remote* operator or a sibling node uses.

**Why.** Whoever can open that socket can already read the config, replace the
binary and stop the service. A token on top of that protects nothing — and it
does leave a standing admin secret sitting in a file or a shell history.

**Why a socket rather than loopback TCP**, which would have been easier: a TCP
port is reachable by every local user, and given a routing mistake, from off the
box. The uid check is what makes the argument hold, and it needs a socket.

### 13.9b The console is off by default

**Decision.** `management.ui` defaults false. The code and its tests stay;
`ui: true` brings it back.

**Why.** It is the only part of this daemon that accepts credentials, holds
sessions and renders HTML — a standing authentication and XSS surface on a
resolver. Carrying that permanently is only worth it if somebody uses it, and on
the first production pair it was built, deployed, and never signed into: zero
accounts, zero tokens, zero sessions, and its bootstrap credential still unread
on disk after two days.

**The general rule worth taking from it:** a surface that accepts credentials
should be opt-in, not default-on, unless it is the primary way the thing is
operated. Here the API and the CLI are.

### 13.9c Certificates are obtained and renewed automatically

**Decision.** Built-in ACME. The manager writes to the same `listen.tls` paths
the listeners read, so the two cannot drift, and renewals are picked up through
`GetCertificate` on the next handshake rather than by restarting a listener.

**Why it is not a cron job with a shell script.** Renewing by hand is a scheduled
outage: silent until the day it expires, then every encrypted client stops
resolving at once.

**http-01 is the default and its port is not left open.** It binds when a
challenge starts and closes the moment it finishes — about fifteen seconds a
quarter, recorded in `cgdns_acme_challenge_seconds`. A resolver's addresses are
reachable by every subscriber and, through the covering prefix, from the
internet; **a web server running all year to serve one file for a few seconds is
attack surface bought for nothing.** The responder serves exactly one path, 404s
everything else, and closes on its own timeout even if the CA never returns.

**dns-01 is used instead wherever a provider is configured**, because it opens
nothing — and it is the only workable option once a name is anycast from several
POPs, where the CA would validate against whichever POP is nearest *it* rather
than the one asking. That matters directly for the second site.

**A certificate no public CA vouches for is treated as needing replacement**,
even when it is valid for years and names the right hosts. An interim
placeholder passes every expiry and hostname check, so nothing else would ever
replace it. The certificate directory's writability is checked at construction,
because finding out after a successful order wastes an issuance against a rate
limit that takes a week to recover.

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

### 15.5a Two units, two capability sets

The package ships `cgdns.service` and `cgdns-routed.service`, and the difference
between them is the privilege separation in §4.9 made concrete:

| | `cgdns` | `cgdns-routed` |
|---|---|---|
| Capability | `CAP_NET_BIND_SERVICE` | `CAP_NET_ADMIN` |
| Bounding set | the same one capability | the same one capability |
| Can bind port 53 | yes | **no** |
| Can install a route | **no** | yes |
| Extra address family | — | `AF_NETLINK`, which is how it installs them |

Neither can do the other's job, and a compromise of the internet-facing daemon
does not reach the routing table.

`cgdns-routed` is `PartOf=gobgpd.service` — it reads gobgpd's RIB, so it is
useless without it. It is a **separate unit** rather than part of the resolver
precisely so that a routing problem and a resolution problem stay separate
failures.

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

## 16. Performance, privacy and telemetry

### 16.1 Measured numbers

Measured on a Xeon Gold 6140, hot path, zero allocations:

| | |
|---|---|
| Subscriber prefix lookup (v4 / v6) | 3.6 ns / 7.0 ns |
| Cache hit | 344 ns |
| Cache miss | 262 ns |
| Rate-limiter decision | ~120 ns |

Live resolution against the real root servers: cold 1.1 s, warm 156 ms.

**Capacity, measured with `cgdnsload`.** The tool ramps *offered* load and
reports what was *achieved*, because those differ and the difference is the
measurement. Daemon pinned to 4 CPUs to match a POP node, forwarding to a local
authoritative so the figure is this daemon rather than the internet:

| | achieved | loss | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 600 senders | 143,105 | 0.07% | 1.2 ms | 5.5 ms | 10.6 ms |
| 1500 senders | 137,395 | 0.32% | 2.0 ms | 7.6 ms | 13.7 ms |

**The shape past the knee is the part worth recognising.** More concurrency
yields *less* throughput and several times the loss — a saturated resolver does
not slow down politely, it starts dropping. CPU peaked at 290% of 400%, so the
packet path binds before compute does and adding cores would not move it much.

A five-minute soak at the knee answered **41,993,025 queries** at 0.07% loss,
p99 steady at 9.7 ms, nothing logged.

**A measurement caveat built into the tool.** Paced mode cannot find a ceiling on
its own: a ticker asked for an interval of a few microseconds does not keep it,
and above a few tens of thousands per second the generator quietly becomes the
bottleneck. The numbers above come from unpaced mode for that reason.

### 16.1a Resident memory is not the cache size

**What `cache.max_size` bounds, exactly.** Under load a 64 MiB cache held
**exactly 64 MiB** across 176,000 entries and 400,000 evictions — the ceiling
does what it says.

**What it does not bound.** The process sat at 277 MB while doing it. The
difference is Go's heap under load, and it scales with query *rate* rather than
with cache size: the same build serving a household holds about a megabyte of
cache inside 64 MB of RSS.

**So a node is sized as cache share plus roughly 200 MB of headroom at full
tilt**, not as cache alone. Sizing on `max_size` and nothing else is how a node
gets OOM-killed at the exact moment it is busiest.

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

`privacy.Hash` exists for correlating log lines without the name appearing. It is
**unkeyed**, so it defends against casual disclosure only, not against someone
who can hash candidate names — a threat model needing that wants an HMAC with a
rotated per-node key, and the source says so rather than implying more than it
delivers.

### 16.5 Telemetry: what comes out of this, and at what cost

**Decision.** Two streams, both structured, both cheap: a Prometheus endpoint on
the management plane, and structured event logs on stderr.

**105 metric series**, and the shape of them matters more than the count:

| Subsystem | Series | Answers the question |
|---|---|---|
| `recursion_*` | 12 | Is the delegation walk healthy — referrals, bogus referrals, budget/depth exhaustion, 0x20 mismatches, glueless lookups, EDNS downgrades, TCP fallbacks, CNAME chases, minimise fallbacks |
| `peer_*` | 11 | Is the pair link up in both directions, what is it saving us, is anything looping |
| `policy_*` | 8 | What is filtering doing, including per-subscriber override hits |
| `ratelimit_*` | 7 | Are we under attack, and is the limiter itself under pressure (evictions) |
| `prefetch_*`, `nsec_*` | 5 + 5 | Are the two cache-warmth defences actually working |
| `cache_*`, `infra_*` | 5 + 1 | Hit rate, evictions, what we know about authoritatives |
| `anycast_*` | 5 | **Is this node taking traffic, and is dampening escalating** |
| `dnssec_*`, `serve_*` | 3 + 3 | Validation outcomes; is expired data keeping subscribers online |
| runtime (`goroutines`, `memory`, `gc`, `uptime`) | 4 | Standard process health |

**The design decision behind them.** A metric is a `Source` with a
`Read func() float64` closure, evaluated **at scrape time** over an atomic
counter. So the hot path pays exactly one atomic increment per event, and all
formatting, sorting and text generation is paid by the scraper. Observability
does not tax the query path, which is what makes it acceptable to instrument
this densely.

**The privacy ceiling, which is deliberate and load-bearing.** Nothing is
labelled by QNAME or client address. Not at debug, not behind a flag — the
exporter has no label mechanism for them. A per-subscriber or per-domain series
would let a browsing history be reconstructed from a time series, which is the
same privacy failure as leaking the logs, only retained longer and readable by
anyone with dashboard access. **This is the hard limit on what any telemetry
pipeline downstream can ever contain**, and it is worth saying out loud before
someone asks for per-subscriber query dashboards.

### 16.6 Streaming it out

**What is available today, with no change to the daemon:**

- **The metrics endpoint** is a scrape target on the management address behind
  the source ACL (§13.1) — Prometheus, VictoriaMetrics, a Telegraf `prometheus`
  input, or anything else that scrapes. From there, remote-write into whatever
  the NOC already runs.
- **Structured JSON event logs.** `log.format: json` makes every line a JSON
  object on stderr; systemd captures it to journald. From journald, a shipper —
  Vector, Fluent Bit, promtail — streams it to Kafka, Loki, Elasticsearch or a
  SIEM. **That is a genuine per-event stream today**, and it costs the daemon
  nothing beyond writing the line, because the shipping happens outside the
  process where backpressure cannot reach the query path.
- The events worth streaming are already structured for it: DNSSEC bogus with the
  reason, 0x20 case mismatches (off-path spoofing attempts), policy blocks with
  subscriber and rule, anycast state transitions with the failing check named,
  rate-limit engagement, peer link up/down, and every management-plane
  authentication event with user and remote address.
- **GoBGP has its own gRPC telemetry** for the routing side, independent of
  cgdns, so the BGP view is already streamable by whatever monitors the routers.

**What is not built, stated plainly so nobody assumes it:**

| Not present | What it would give | Note |
|---|---|---|
| **OTLP / OpenTelemetry export** | Push metrics and traces to a collector | The cleanest addition — the `Source` registry maps onto OTLP metrics directly |
| **gNMI / OpenConfig streaming** | Subscribe-and-push in the shape carrier NMS tooling already speaks | Most valuable if the NOC is already gNMI-based for the routers |
| **dnstap** | Per-query streaming in the DNS-native format Unbound, BIND, Knot and PowerDNS all emit | See the warning below |
| statsd, Kafka producer, pushgateway | Push without a shipper | Log shipping covers this today |

**On dnstap specifically, since it is the obvious ask.** It is the standard for
DNS query streaming and it would slot into the handler chain naturally. But
**dnstap carries full QNAMEs and client addresses** — it exists to carry exactly
what §16.4 spends effort keeping out of logs and metrics. Adding it would create
the highest-sensitivity data stream in the platform, and it should therefore be a
deliberate, ACL'd, off-by-default decision with a retention policy attached and
lawful-intercept-grade handling — not a feature that arrives because a dashboard
wanted it. Flagged as a decision to take consciously, not a gap to close
casually.

### 16.7 Alerting: the series that matter

Not everything with a counter deserves a page. These do:

| Metric | What a change means |
|---|---|
| `cgdns_anycast_advertised` | 0 means this node has decided it should not be taking traffic. The most important series — but it is the node's *own decision*, not proof a route left the box (§3.4b). Pair it with a route check on the PE |
| `cgdns_anycast_flaps_total` | Rising means dampening is escalating; a node is sick, not merely down |
| `cgdns_dnssec_bogus_total` | A broken zone, or an attack — **but read it against a baseline, not against zero.** `cgdns-probe` queries a deliberately broken zone on a timer to confirm validation is still *rejecting*, so a healthy node counts bogus answers continuously. Alert on the rate changing |
| `cgdns_dnssec_unavailable_total` | A chain could not be judged because a DNSKEY or DS was unreachable. **A reachability problem here, not a signing problem at the zone** — the distinction is what stops an operator being sent to debug someone else's DNSSEC |
| `cgdns_recursion_case_mismatch_total` | Non-zero means off-path spoofing attempts |
| `cgdns_ratelimit_dropped_total` | An attack, or a rate set below what real clients need |
| `cgdns_ratelimit_evictions_total` | Sustained means `max_buckets` is too small for the client population |
| `cgdns_serve_stale_served_total` | Authoritatives failing; expired data is holding subscribers up |
| `cgdns_prefetch_dropped_total` | `max_concurrent` too small — popular names expiring before their refresh gets a slot |
| `cgdns_nsec_synthesised_total` | Rising fast means a flood of made-up names is being absorbed here rather than reaching the zone it targets |
| `cgdns_peer_outbound_up` / `_inbound_up` | 0 means the pair is split and each node is on its own |
| `cgdns_feed_hash_mismatches_total` | **Above zero is worth waking up for**: a blocklist was tampered with in transit, or its publisher changed content without the control plane being told. Either way the previous list is still serving |
| `cgdns_feed_fetch_failures_total` | Filtering is going stale. Resolution is unaffected, so this is a next-business-day alert, not a page |
| `cgdns_feed_last_success_timestamp` | The honest measure of feed freshness — how long since a feed last updated cleanly, rather than whether the last attempt errored |

**The store hash is deliberately not a metric.** Drift is a *comparison between
two nodes*, and a single node cannot report it — publishing a hash as a series
would invite an alert rule that cannot actually detect the condition. Use
`cgdnsctl drift`, and alert on a disagreement that persists past a sync interval
(§5.4).

---

### 16.8 Fuzzing the parsers, and judging the node from outside itself

**Decision.** Nine fuzz targets over the parsers where attacker-chosen bytes
become a decision, and a separate binary, `cgdns-probe`, that queries the anycast
address the way a subscriber does and judges only the answer returned.

**Why fuzz these specifically.** The denial proofs get the most attention,
because they decide whether a name is *securely absent* — a wrong answer there is
a downgrade, not a crash. Those targets assert more than the absence of a panic:
a held no-DS proof must not be contradicted by a DS sitting in the very records
it read, and a zone-cut verdict must come from a record that actually matches the
name. The rest cover the aggressive-denial store, the feed and root-hints parsers
that read third-party and operator files, and the acceptance path every listener
applies before the resolver is involved. Nine million executions found nothing.

**Why an external probe exists at all.** A node's metrics describe what it
*believes*. They cannot describe what a subscriber *receives*, and that gap is
where serious incidents live. Three checks, because there are three distinct ways
to be broken: a signed name must return NOERROR **with `AD`** (or validation has
silently stopped), a deliberately broken zone must return **SERVFAIL** (or
validation is not rejecting and subscribers are exposed to forged answers), and
an ordinary name must resolve. **Passing only the third looks perfectly healthy
and is not DNSSEC at all.**

**Where a probe rule and a node rule disagree, believe the probe.** The alert
ordering says so deliberately. Deployed at POP-BNE with each node probing its
sibling; a wholly independent vantage point is better still and is a change to
`-targets`.

### 16.9 The cache is bounded by memory, not by entry count

**Decision.** `cache.max_size` takes a memory figure — `512MiB`, `2GiB`, or a
byte count — enforced by the same LRU eviction per shard. The entry count still
applies, whichever binds first.

**Why.** An entry count cannot bound memory. An entry holding eight address
records costs roughly two and a half times one holding two, so the same
`max_entries` can mean 380 MB or 930 MB depending on what subscribers happen to
ask for. **That is not a figure a node can be sized against, and the failure mode
is the process being killed rather than the cache getting smaller.**

**What it costs.** Bounding memory needs an estimate of it, and Go offers no
cheap way to weigh a live object graph. The cost is modelled — a fixed charge per
entry, a fixed charge per record, plus the record's own data — with constants
calibrated against real heap growth. A test measures actual heap while filling a
cache and fails if the estimate drifts beyond a third either way; it currently
tracks within four percent.

**One deliberate exception:** an entry larger than a single shard's budget is
kept rather than evicted the instant it lands, or the cache would thrash on it
for ever and never serve it.

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
| 6c | **The lab differs from the reference deployment model in seven respects** — shared router, loopback query source, RFC 1918/ULA with NAT, static return routes, v6 on its own interface, one shared anycast address, one POP | It was built to prove the software, which it did thoroughly | Real, and tabulated in §3.4a. **None of the production addressing, peering or anycast topology has been run.** The first POP built to `provisioning.md` is the test |
| 6d | **A node reporting itself advertised is not evidence a route left the box** | The health decision is internal by design; it cannot see the PE | §3.4b — confirm on the PE, confirm egress with a packet capture. A gobgpd misconfiguration already caused exactly this, silently |
| 7 | **Nothing detects config drift between POPs automatically** | There is deliberately no cross-POP control plane | `cgdnsctl drift` is per-pair; cross-POP consistency is the provisioning system's job |
| 8 | **We own DNS correctness** rather than inheriting Unbound's two decades of hardening | The three features that justify the product all need to be inside the resolver | Named regression tests for every security invariant; RFC + section cited in source; live and lab verification |
| 9 | **Aggressive denial saves much less on a large NSEC3 zone than on an NSEC one** (`debian.org`: 4/50 rising to 22/50, against 49/50 for NSEC) | Inherent to NSEC3: hashing scatters names across the chain, so one denial rarely covers the next made-up name. Not an implementation shortfall | Improves as the chain caches; RRL (§11) still caps what a flood costs regardless |
| 10 | **The TOTP secret is stored recoverable** | Verifying a code requires computing it | Store file mode; replicates only over the mTLS pair link |
| 11 | **`redirect` policy action returns an address the subscriber did not ask for** | It is what a walled-garden product requires | EDE 15 on every policy response so clients can tell |
| 12 | **Rate limiting could in principle limit our own health probe** | Probes come from loopback and are answers, not denials | Live flood test asserts `cgdns_anycast_advertised` stays 1; **re-check on any bucketing change** |

---

## 18. Not built yet, and why that order

Every feature originally on this list has now landed — WebUI, DoQ, aggressive
NSEC3, feed fetching with hot reload, and the route agent included. What remains
is **verification work, not construction**, and it matters more than the feature
list did:

| Item | Status and reasoning |
|---|---|
| **A second POP** | POP-BNE is live and built to the reference model (§3.4c), so the addressing, peering and anycast topology are all now deployed and verified at the PE. What one site cannot show is an address moving *between* sites — the property the whole design exists for. **The most valuable outstanding item** |
| **A withdrawal drill in production** | Exercised thoroughly in the lab; not yet run against POP-BNE's live PE |
| **Carrier query volumes** | POP-BNE carries a household's traffic. Real, and not representative load |
| **Config anti-entropy on live nodes** | Unit-tested, and the management API now makes runtime writes possible; the full multi-day live soak has not been run |

**Deliberately deferred, with reasons rather than omissions:**

| Item | Why |
|---|---|
| **Session replication** | A console session is node-local, so moving to the sibling means signing in again. Replicating live session state would put mutable per-request data on the pair link to save one login |
| **A licence** | §20. Needed before any external distribution |
| **RFC 8326 `GRACEFUL_SHUTDOWN`** | Planned maintenance does a plain withdraw (§4.8), which works but drops what was in flight when the route disappears |

**Order rationale.** The build order throughout has been: query path first
(nothing else matters if resolution is wrong), then the things that keep it
serving under attack (RRL, aggressive NSEC/NSEC3, serve-stale), then the things
that make it operable (management API, CLI, packaging), then the presentation
layer (WebUI), then the remaining transport (DoQ). Every step has been deployed
and exercised on the lab pair before moving on.

**The honest read on where the risk now sits.** It has moved out of the code and
out of deployment and into scale. The software is built, tested, fuzzed and
running; the reference model is deployed at POP-BNE and verified at the router;
real queries are being answered. What remains unproven is behaviour *across*
sites and at volume. That should be said plainly rather than left to be inferred
from a short "not built" list.

---

## 19. Questions you are going to ask

**"Why not just run Unbound? It's free, it's proven, and it's someone else's
problem."**
Two specific blockers, both checkable rather than matters of taste. **Unbound
cannot create a view at runtime** — per-client policy lives in `unbound.conf` and
needs a reload, so every subscriber override becomes a config edit on a box
taking production traffic. And **no mainstream recursor exposes per-entry cache
insertion**, so pair cache sharing is not implementable against any of them;
`unbound-control` offers whole-cache dump and load, nothing finer. §2.1 sets out
the four requirements every candidate was measured against and works through
Unbound, BIND, PowerDNS, Knot and CoreDNS one at a time. The cost is stated
honestly there too: we own DNS correctness now, which is why §7 and §8 exist —
and §2.1 ends with the conditions under which this decision would be wrong.

**"Why not nscd? Or dnsmasq, or systemd-resolved?"**
Category rather than capability: all three are stub or forwarding caches serving
one host or one small network, none of them recurses, and each needs a real
recursive resolver behind it. nscd in particular is glibc's *NSS* cache — it does
not listen on 53, does not speak DNS to clients, caches `getaddrinfo()` results
rather than RRsets, and expires them on a configured constant rather than the
record's TTL, which alone breaks CDN and failover behaviour. §2.1a has the full
answer including where nscd stands with the distributions today.

**"What can we get out of it for monitoring? Can we stream it?"**
105 Prometheus series on the management listener behind the ACL, plus structured
JSON event logs that journald and a shipper turn into a real per-event stream to
Kafka, Loki or a SIEM — both available today with no change to the daemon
(§16.6). Metrics are read at scrape time from atomic counters, so instrumentation
costs the query path one increment. Native push (OTLP, gNMI) is not built and is
an open decision. The one hard limit: **nothing is labelled by QNAME or client
address, by construction** — a browsing history reconstructable from a time
series is the same failure as leaking the logs, so per-subscriber query
dashboards are not something this will ever produce. Per-query streaming would
mean dnstap, which is a deliberate decision with a retention policy attached, not
a switch to flip (§16.6).

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
proving with a second site.

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
406 tests, 13 benchmarks and 9 fuzz targets, `-race` clean, **zero skips** — verified at the
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
7. **Whether to add push telemetry, and in which shape** (§16.6). Today the
   metrics are pull and the event stream is JSON logs via a shipper, which covers
   most needs. OTLP is the cheapest addition; gNMI is worth it only if the NOC is
   already gNMI-based. **dnstap is a separate decision with a privacy weight** —
   it carries full QNAMEs and client addresses, so it needs a retention policy
   and an access model agreed before it is switched on, not after.
8. **RFC 8326 `GRACEFUL_SHUTDOWN` community on planned maintenance.** Today a
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
