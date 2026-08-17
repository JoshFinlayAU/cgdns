# cgdns

**A carrier-grade recursive DNS platform, and the case for running it nationally.**

*Part 1 is what the product is and why it is worth deploying. Part 2 is what it
is made of. Part 3 is the architecture and why those choices matter. Part 4 is
everything else we weighed and why we went this way.*

*Companion documents: [LOUIS.md](LOUIS.md) is the exhaustive
decision-by-decision record, including every rejected alternative in full.
[provisioning.md](provisioning.md) is how to bring a pair up from nothing —
address plan, BGP sessions, the lot. This document is the readable overview of
both.*

---

## Contents

**Part 1 — [What this is, and why it should go national](#part-1--what-this-is-and-why-it-should-go-national)**
· [In one paragraph](#in-one-paragraph)
· [The eight reasons](#the-eight-reasons-to-deploy-this-nationally)
· [What it costs and what is unproven](#what-it-costs-and-what-is-still-unproven)
· [Evidence](#the-evidence-behind-those-claims)

**Part 2 — [The components](#part-2--the-components)**
· [Query path](#the-query-path-in-order)
· [Resolution engine](#the-resolution-engine)
· [DNSSEC](#dnssec)
· [Caching](#caching)
· [The pair](#the-pair)
· [Anycast and routing](#anycast-and-routing)
· [Management](#management)
· [Packaging](#packaging-and-operations)

**Part 3 — [The architecture decisions that matter](#part-3--the-architecture-decisions-that-matter)**

**Part 4 — [Everything else we considered](#part-4--everything-else-we-considered)**

---
---

# Part 1 — What this is, and why it should go national

## In one paragraph

cgdns is the recursive DNS resolver our subscribers use. It answers queries
itself — walking the delegation chain from the root rather than forwarding to
anyone else's resolver — validates DNSSEC, and applies per-subscriber policy
where a filtered product has been sold. It runs as two nodes per POP, each
announcing one of the two anycast addresses subscribers receive as their primary
and secondary. Nodes are managed through a REST API, a CLI or a web console, all
equivalent, from either node. A sick node withdraws itself from BGP and traffic
moves; a dead POP means subscribers are served by the next-closest one. There is
no central cluster, no quorum, and nothing between POPs.

## The eight reasons to deploy this nationally

### 1. It removes a third-party dependency from a service nothing works without

A forwarding resolver is only as good as whoever it forwards to. cgdns performs
the full recursion itself: root, TLD, authoritative. Our resolution depends on
the public DNS hierarchy and nothing else — no upstream provider whose outage
becomes ours, whose filtering decisions become ours, and whose rate limits apply
to us.

When DNS fails, everything downstream of it appears to fail simultaneously and
the support calls do not say "DNS". Owning the resolution path is what makes that
class of incident ours to diagnose and fix rather than ours to escalate and wait
on.

### 2. Subscriber query data stays inside our network

A recursive resolver sees every name every subscriber looks up. That is among
the most sensitive data a carrier holds. With cgdns it never leaves our
infrastructure — no third-party resolver receives it, and there is no contract
governing what someone else may do with it.

The platform treats this as a design constraint rather than a policy statement:
**full query names never appear in logs or metric labels**. Log lines carry the
registrable domain (`example.com`, not `very.specific.host.example.com`), and the
metrics exporter has no mechanism to label a series by query name or client
address at all. A subscriber browsing history cannot be reconstructed from our
own telemetry, which is a property worth having before anyone asks for it.

### 3. Answers come from the nearest POP, and mostly from memory

Subscribers are routed by BGP to their closest POP. Within it, the pair share
cache: a name one node has resolved is available to the other in under a
millisecond over the pair link, rather than 20–50 ms upstream. Popular names are
refreshed in the background shortly before they expire, so the unlucky
subscriber whose query lands the moment a hot entry expires no longer pays for
everyone else's cache miss.

Measured on a Xeon Gold 6140: cache hit **344 ns**, subscriber classification
**3.6 ns**, zero allocations on the hot path. Live resolution against the real
root: **1.1 s cold, 156 ms warm**.

### 4. It absorbs the attacks that are actually aimed at resolvers

Three defences, each targeting a real attack rather than a category:

- **Response rate limiting** stops us reflecting at a spoofed victim, and stops a
  random-subdomain flood costing us outbound capacity. The key design point is
  that denials are grouped by the *zone* that denied them, so a flood of
  `random1.victim.com`, `random2.victim.com`… collapses into one bucket instead
  of creating one bucket per query. Measured under a live flood: 15 000 queries
  at 500/s collapsed to a single bucket, and the node stayed healthy and in the
  anycast set throughout.
- **Aggressive NSEC/NSEC3** reuses a validated denial to answer for every name it
  proves absent, so a flood aimed at a signed zone is answered here and never
  reaches the zone under attack. Measured live: 49 of 50 made-up names answered
  from cache on `nlnetlabs.nl` and `isc.org`.
- **Serve-stale** keeps subscribers online when an authoritative has gone away,
  answering from expired data only after resolution has genuinely failed.

### 5. Failure is a routing event, not an outage

Each node continuously probes its own ability to resolve — through the real
serving path, not a private health endpoint — and withdraws its anycast prefix
by BGP when it cannot. Withdrawal is fast; re-advertisement is dampened, because
a flapping prefix costs every POP carrying that address while a withdrawn node
costs only the traffic that was heading to it.

Lab-verified: stopping the service withdraws the prefix gracefully on SIGTERM,
the router moves traffic, and **no queries fail during the transition**.

### 6. It enables the filtered-DNS product without a second platform

Where a subscriber has bought a filtered or security DNS product, their prefix is
attached to a policy class. Where they have not, they are unfiltered and the
policy layer is not in the query path at all — not bypassed per query, but
absent, because the handler is only constructed when filtering is enabled.

Per-subscriber allow lists override shared blocklists, which is what makes the
product supportable: every curated feed eventually false-positives on some
customer's supplier or payment gateway, and without a per-customer unblock the
only remedies are editing a feed you do not own or refunding the customer.

The same mechanism is what a blocking obligation lands on when one arrives.

### 7. It is operable at carrier scale, by machines

Everything is an API. `cgdnsctl` is a plain client of it with no privileged
back door, so **anything an engineer can do, the existing OSS/BSS can do over
HTTP** — which is the only way per-subscriber provisioning works at national
scale. Writes land on either node of a pair and both converge; there is no
primary to track and no management VIP to fail over.

The console is served by the management listener only, behind the same source
ACL and TLS, and adds no listener of its own.

### 8. The economics are commodity hardware and no per-subscriber licence

Two ordinary servers per POP, a static Go binary, a `.deb` or `.rpm`, and a
systemd unit. No per-query or per-subscriber licensing, no appliance refresh
cycle, and no vendor release cadence deciding when we can fix something.

---

## What it costs, and what is still unproven

Stated here rather than buried, because a case that only lists strengths is not
a case.

**We own DNS correctness.** Not wrapping Unbound means bailiwick rules, EDNS
negotiation, TCP fallback, CNAME chasing, DNSSEC chain building and NSEC/NSEC3
proofs are ours to get right and keep right. That is the real price of this
decision. It is why every security invariant has a named regression test, why
protocol behaviour cites its RFC section in the source, and why the test suite is
the size it is. **This obligation does not end**, and under-investing in it later
is the way this decision turns out to have been wrong.

**The reference deployment model has never been run.** This is the single most
important caveat in this document, and it is wider than one setting.

The lab pair predates the model in [provisioning.md](provisioning.md) and reaches
equivalent behaviour by other means. It is a worked example, not the reference:

| Lab | Reference model |
|---|---|
| Both nodes peer with one router over a shared /29 | one node per PE, so a router failure withdraws one node, not the POP |
| A separate `loopback0` holds the query source | `eth0` is the query source; no loopback |
| RFC 1918 and ULA addressing, masqueraded out by the router | public space, no NAT |
| Static return routes on the router to reach each loopback | not needed — eth0 is natively routed |
| A dedicated interface carries IPv6 on its own VLAN | v6 rides eth0 alongside v4 |
| One shared anycast address across the pair | each node owns its own, announced from every POP |
| One POP | the same two addresses announced from every POP |

So the lab has proved the *software* thoroughly — recursion, DNSSEC,
health-driven withdraw and re-advertise, failover, the pair link, rate limiting
under flood, serve-stale isolation — and has proved **none of the production
addressing, peering or anycast topology**. In particular, the failover it
demonstrated was *within* the POP, which is specifically not what production
will do.

Standing up one POP to the reference model is the most important outstanding
item, and it belongs before the first production deployment rather than during
it.

**Verification has to happen at the far end, not the near end.** A lesson already
paid for: `cgdns_anycast_advertised` reports the node's own internal health
decision and says **nothing** about whether a route ever left the box. A gobgpd
import filter placed globally instead of per-neighbour rejects the routes the
node originates as well as those it receives — the API returns success having
done nothing, and the node reports itself advertised while the PE has no route to
it at all. Confirm an announcement on the PE, and confirm the egress path with a
packet capture. A `dig` that returns an answer proves an answer came back, not
which address or family produced it.

**There has been no multi-day soak under real subscriber load.** Everything has
been verified in a two-node lab and against the live internet. That is meaningful
evidence and it is not the same as production.

**Capacity planning has a consequence people miss.** Because each node holds one
of the two addresses, a single node failure sends that address to the next state.
The same-role node there must be sized to absorb a neighbouring state's primary
load.

**A genuinely instructive failure, included deliberately.** A DNSSEC bug was found
in the lab in which cached delegation records — stored by the walk on its way
past, and keeping no signatures — were re-validated on a later lookup against
evidence the cache never held. Names failed for as long as the entry lived. When
it reached the root's own NS set, the health probe failed and **both nodes
withdrew themselves from the anycast set**: a full-POP outage, self-inflicted,
from a correctness bug three layers away from the health check.

It is in this document because it is the best argument for both halves of the
design. The health check found it, because it probes the real serving path. And
it is exactly the class of bug we took on when we chose to own the resolver. It
is fixed — entries now record whether validation actually ran, separating "not
judged yet" from "judged insecure" — with a regression test.

---

## The evidence behind those claims

| Claim | Backed by |
|---|---|
| Correctness of the resolution engine | **391 test, benchmark and fuzz functions**, `-race` clean, **zero skipped tests**; verified live against the real root servers |
| DNSSEC validation | `AD` set on `iana.org` and `cloudflare.com`; SERVFAIL with EDE 9 on `dnssec-failed.org` |
| IPv6 is real, not nominal | Full lab run with **IPv4 egress disabled entirely** — every outbound query over v6, DNSSEC still validating |
| Anycast failover | Lab: prefix withdrawn on SIGTERM, router moves to sibling, no failed queries, re-advertises on restart |
| Pair link under partition | Lab: `iptables` DROP both directions — both nodes keep resolving, both stay in the anycast set, link heals and resumes |
| Config replication | Lab: write on either node reaches the other; a write made during a partition catches up on heal with matching hashes |
| Rate limiting under attack | Lab: 15 000 queries at 500/s, collapsed to one bucket, node stayed healthy and advertised |
| Aggressive NSEC/NSEC3 | Live internet: 49/50 synthesised on NSEC and small NSEC3 zones; measured honestly, including the large-zone case where it saves much less |
| Serve-stale vs health | Lab: isolated node kept answering cached names **and still withdrew**, citing that the root NS came from expired cache |
| Packaging | Real `.deb` install on a lab node, including the upgrade and removal paths |

---
---

# Part 2 — The components

## The query path, in order

A subscriber's query traverses these in sequence. Every stage is bounded, and
every position in the chain is deliberate.

```
UDP / TCP / DoT / DoH / DoQ
        │
        ▼
   source ACL            default-deny, enforced before any work
        │
        ▼
   rate limiter          UDP only; sees the response actually bound for the client
        │
        ▼
   policy enforcer       absent entirely when filtering is off
        │
        ▼
   serve-stale           inside policy, so a blocked name stays blocked
        │
        ▼
   resolver              cache → peer → recursion from the root
```

**Transports.** UDP and TCP on 53, DoT on 853 (RFC 7858), DoH on 443 over HTTP/2
(RFC 8484), and DoQ on 853/UDP (RFC 9250). All dual-stack. UDP uses one
`SO_REUSEPORT` socket per CPU per address so a single address scales past one
kernel receive queue; addresses are always bound explicitly, never a wildcard,
because a wildcard bind loses the destination address and would let an anycast
reply leave with the wrong source. DoT reuses the TCP connection loop under a TLS
listener — the framing is identical, and writing it twice would have meant two
places to get it wrong. DoQ gives each query its own QUIC stream, removing the
head-of-line blocking DoT has when one slow answer stalls everything behind it.

**Source ACL and subscriber identity.** Both are longest-prefix matches over a
combined v4/v6 trie — 3.6 ns and 7.0 ns respectively, zero allocations. The query
ACL is default-deny and *required*: the daemon will not start without it, because
a recursive resolver reachable from the internet is a reflection source. A `/0`
in it is legal but logs a loud warning at startup.

**Rate limiter.** Limits *responses*, not queries, because the victim of a
spoofed query never sent it and the only thing that helps them is us not sending
the answer. UDP only — TCP, DoT and DoH complete a handshake, so there is nothing
to spoof. Answers are unlimited by default; denials are limited and grouped by
the zone that denied them. Every second over-limit response is sent truncated
rather than dropped, so a real client discovers TCP while a spoofed victim gets a
small packet instead of a large one. ~120 ns/op, zero allocations.

**Policy enforcer.** Subscriber allow list, then subscriber block list, then the
feeds their class subscribes to — that order is the contract, because an unblock
that could not override a feed would be useless. Blocked answers carry EDE 15 so
a client can tell policy from a genuine NXDOMAIN. Feeds are fetched on a
schedule, verified against a pinned SHA-256, and recompiled into the query path
by swapping an atomic pointer. **Every failure mode keeps the previous content** —
bad hash, timeout, HTTP error, oversized feed, or one that came back empty, that
last because an empty list would silently unblock everything it used to block.
Filtering goes stale; resolution does not.

## The resolution engine

Walks the delegation chain itself: start at the deepest known delegation, ask one
of that zone's authoritative servers, and either get an answer or get referred
one step closer.

**What a server is trusted to say** is the security core:

- Glue is kept only if its owner name is inside the delegated zone.
  Out-of-bailiwick glue is discarded, never cached — that is the classic
  cache-poisoning vector.
- A referral must delegate strictly *below* the current zone and be a suffix of
  the query name. Self-, sideways- and upward-delegation are all rejected.
- Answer records outside the CNAME chain being followed are dropped.

**What one query may cost** is bounded by a single budget shared across
everything it triggers — including the side lookups that resolve nameserver names
with no glue. Wall clock (5 s), delegation depth (16), **total outbound queries
(32)**, CNAME chain (8), nameserver-resolution nesting (4). The 32 is the
amplification limit: it is what stops one inbound query becoming a lever against
a third party.

**Privacy and anti-spoofing.** QNAME minimisation (RFC 9156) means the root never
learns a subscriber's full query — it is a privacy control, not an optimisation.
0x20 mixed-case encoding adds entropy an off-path attacker must guess alongside
the query ID and source port; a response that does not echo the case exactly is
discarded and counted.

**Server selection** is driven by an infrastructure cache holding per-nameserver
round-trip time, health and EDNS quirks — what we know about the servers
themselves, kept separately from their data because it has a completely different
lifetime.

## DNSSEC

Full chain of trust from IANA's root anchors, embedded in the binary.

- **`AD` is set only on a chain this node verified itself.** An upstream's AD bit
  is someone else's claim and is stripped in both resolver modes.
- **A broken chain is SERVFAIL with an RFC 8914 extended error** naming the
  cause. There is no silent downgrade.
- **A stripped DS is bogus, not insecure.** A zone with no DS in its parent is
  insecure only if the parent *proved* the absence. Without that proof, an
  attacker stripping the DS looks exactly like an unsigned zone — treating it as
  insecure would make DNSSEC bypassable by anyone on path.
- **Denials are validated like answers**, and a validated denial is cached as
  authenticated. Negative caching keeps only the SOA (RFC 2308), so re-proving a
  cached denial would fail for want of evidence deliberately not kept.
- **Each RRset is verified against its own signer**, which matters wherever a
  CNAME crosses a zone boundary: the CNAME is signed by one zone and the target's
  addresses by another, and either fails under the other's keys.
- **An unreachable authority is not a verdict.** A DNSKEY or DS that could not be
  fetched surfaces as EDE 22/23 with its own counter rather than being reported
  as bogus — saying "your signing is broken" when the truth is "this node could
  not see" sends operators chasing the wrong fault. The answer is still withheld;
  unvalidated data is never served.
- SHA-1 is off by default. NSEC3 iteration counts above the RFC 9276 limit are
  refused rather than computed.

## Caching

**RRset and negative cache**, sharded with per-shard locks and intrusive LRU
lists, storing absolute expiry so an entry can be handed to the pair carrying its
*remaining* TTL.

**Prefetch** refreshes an entry when a read finds it near expiry, so a name asked
for constantly is answered from cache constantly. Only names actually being asked
for — an idle entry expires normally, otherwise the cache becomes a crawler.
Denials are never refreshed. Refreshes are deduplicated and capped, and drop
rather than queue over the cap: the thing preventing a stampede must not cause
one.

**Serve-stale** (RFC 8767) retains expired entries and uses them *only* after
resolution has already failed. Only SERVFAIL triggers it — NXDOMAIN and NODATA
are answers, and overriding them would resurrect names their owner deliberately
removed. Stale answers carry EDE 3 and never set `AD`, because signatures as old
as the data may have expired.

**Aggressive NSEC/NSEC3** stores validated denials and reuses them for every name
they prove absent. Only validated denials are stored, an NSEC is only used inside
the zone its own SOA names, and NSEC3 proof is stricter — closest encloser, next
closer name, and the wildcard — with opt-out spans never used, since such a span
may contain unsigned delegations and would let us deny names that exist.

## The pair

One mutually authenticated TLS connection between the two nodes of a POP,
carrying two payloads with deliberately different guarantees.

**Config replication is reliable and converging.** Write to either node; both
converge. Records are ordered by a Lamport counter with node ID as tiebreak, so
the two agree without depending on synchronised clocks. Deletes are tombstones
held seven days — without them a node that was down during a delete resurrects
the record on rejoin. A node that was unreachable repairs the gap by anti-entropy
on reconnect. `cgdnsctl drift` compares the store hash across the pair and exits
non-zero on disagreement; that hash is the only drift detector a pair has, so it
is the thing to alert on.

**Cache sharing is best-effort.** Push on fill to keep the sibling warm, pull on
miss before going upstream, bounded at 150 ms because a peer slower than that is
worse than just resolving. A peer that is slow, gone or wrong is indistinguishable
from a cache miss.

**Losing the link degrades management and cache warmth, never resolution.** Both
nodes keep serving and both stay in the anycast set.

## Anycast and routing

**Four interfaces per node, one job each**, and keeping them apart is what makes
the rest work:

| Interface | Carries |
|---|---|
| `eth0` | eBGP to this node's PE, **and the source address for every outbound query** — public space in both families, because authoritative servers on the internet reply to it |
| `eth1` | pair link to the sibling: config replication and cache sharing. Numbered from public space but never announced |
| `eth2` | management: operator API, metrics, SSH. **Supplies no default route** |
| `anycast0` | this node's service address — a `/32` + `/128` on a dummy device, and what DNS listeners bind to |

**Queries must never be sourced from `anycast0`.** That address exists in every
POP, so a reply addressed to it follows BGP to whichever POP is nearest *the
authoritative server* — which is not necessarily the one that asked. The reply
lands on a node that never sent the query and is dropped, while the node that did
ask times out. Sourcing from `eth0` makes the address unique to one node, so
replies come home.

That makes `eth0` **the one leg of the system that touches the public internet**:
the resolver talks to root, TLD and authoritative servers directly, and they
reply to whatever source the query carried. So it must sit inside an aggregate
the AS announces globally, even though no subscriber ever addresses it. The `/31`
itself never leaves the network — longest-match sorts out the rest.

**There is no loopback interface, deliberately.** A loopback earns its place when
an address must outlive any single interface — a node dual-homed to two PEs
cannot source from either link's address, because that address dies with its
link. With one uplink per node, eth0 going down takes the node with it anyway, so
a separate loopback buys nothing. Add one the day a node gets a second uplink,
and not before.

**Each node peers with its own PE** where the topology allows. Two nodes peering
with the same router makes that router a single point of failure for the whole
POP: it dies, both anycast addresses withdraw together, and the second node
bought you nothing.

**Management supplies no default route.** It takes a prefix and a gateway in
their own routing table; the only default in the main table is the one BGP
learns. Accepting a management default and relying on metrics to make it lose is
a trap that works right up until BGP drops, at which point management silently
becomes the service path.

**`cgdns` decides** whether the node is in the anycast set, and it is the only
thing that does: two components with independent opinions produce a flapping
prefix. The decision is driven by probes through the real serving path.

**`gobgpd` speaks BGP**, as its own service. cgdns drives it over gRPC — never by
shelling out to a CLI, and never embedded in-process, which would drop the
session on every resolver restart and blackhole the prefix.

**`cgdns-routed` installs learned routes.** gobgpd holds a learned route in its
RIB and never puts it in the forwarding table, so without this a node cannot use
a default its upstream is offering and keeps a static one even when that next hop
is gone. The agent is deliberately narrow: prefixes matched exactly against an
explicit allow list, a hard cap on how many may be held, and it only ever removes
routes it installed. Between the router's output policy, gobgp's import policy
and this list there are three filters, and only the last is not somebody else's
configuration to get wrong.

**It is a separate daemon because it needs `CAP_NET_ADMIN`, and the process
answering queries from the internet must not also be able to reconfigure the
network.** Its unit grants that one capability and not even the
`CAP_NET_BIND_SERVICE` the resolver has.

## Management

**REST API**, bound only to management addresses, behind a default-deny source
ACL enforced at `Accept` — before the TLS handshake, so a blocked peer costs no
CPU and learns nothing. TLS mandatory off loopback. The validator refuses a
management or metrics listener that is a wildcard, that shares a non-loopback
address with a DNS listener, or that falls inside an anycast prefix.

**Two credential types, treated differently on purpose.** API tokens are 256 bits
of randomness stored as a plain SHA-256 — there is no dictionary to attack, and a
slow KDF would tax every request for nothing; verification is constant-time and
compares an unknown ID against a dummy hash so a missing token costs the same as
a wrong one. Operator passwords are whatever a human chose, so they get argon2id
and a TOTP second factor. Only hashes replicate, so managing the pair from either
node never moves a secret.

**Bootstrap** mints an admin token to a root-only file on a node holding no token
at all — including none adopted from its sibling, which is what stops a rejoining
node growing a credential nobody knows about. There is no default password
anywhere.

**Web console**, embedded in the binary: three files, no framework, no build step,
nothing fetched from a CDN. Content-Security-Policy has no `unsafe-inline`
because the console renders every value with `textContent`, so an operator-supplied
record can never be parsed as markup. It adds no listener of its own.

**Telemetry.** 95 Prometheus series on the management plane, read at scrape time
from atomic counters so instrumentation costs the query path one increment.
Structured JSON logs make a per-event stream that journald and a shipper turn
into Kafka, Loki or a SIEM feed. Nothing is labelled by query name or client
address.

## Packaging and operations

`.deb` and `.rpm` built by nfpm in pure Go — no `dpkg-dev`, no `rpmbuild`.
Binaries to `/usr/sbin` and `/usr/bin`, units to `/usr/lib/systemd/system`.

**A first install neither enables nor starts anything.** The shipped config has no
listen addresses and no query ACL, so the daemon refuses to start until
configured — anycast would route production traffic at a node the moment it came
up. An upgrade restarts only a node that was already running. `purge` removes
`/var/lib/cgdns`; a plain `remove` does not, because it holds the trust-anchor
state and the control store.

The unit is hardened, and grants `CAP_NET_BIND_SERVICE` as an *ambient*
capability rather than via `setcap` — `NoNewPrivileges` strips file capabilities,
and ambient ones survive replacing the binary on upgrade, so deployment needs no
`setcap` step.

Bringing a pair up from nothing — the address plan, the BGP sessions, the PE
side and the policy routing — is documented step by step in
[provisioning.md](provisioning.md).

---
---

# Part 3 — The architecture decisions that matter

Five decisions shape everything else. Each is stated with what it buys, what it
costs, and what breaks if it is reversed.

## 1. Independent pairs per POP, with nothing between POPs

**The decision.** Two nodes per POP sharing config and cache with each other and
nothing with any other POP. No cross-POP cluster, no quorum, no VIP.

**Why it matters.** It means a POP is a complete, self-contained failure domain.
A partition between Brisbane and Perth is not an event — they never needed to
agree about anything in real time. Nothing central exists to fail, and there is
no consensus protocol whose quorum loss freezes a control plane.

**What it costs.** No POP is authoritative about another. A provisioning push
that reaches Sydney and not Melbourne is not detected automatically, which is why
the store hash and `cgdnsctl drift` exist and why they are the thing to alert on.

**Reverse it and** you get a national control plane whose WAN links become a
dependency of every POP's manageability, and you invite a globally shared cache —
which is a correctness bug, not a performance choice. See decision 2.

## 2. Cache is shared within a POP and never between them

**The decision.** The pair share cache. POPs never do.

**Why it matters, and this is a correctness argument.** CDN and cloud
authoritatives answer based on where the *resolver* sits. A `www.example.com`
filled in Sydney holds Sydney-region endpoints. Replicating it to Perth would
hand Perth subscribers Sydney endpoints for the life of the TTL — not a slow
answer, a wrong one, and invisible in every metric we have.

**What it costs.** Each POP pays its own cache-fill cost. Accepted, and cheap.

**Reverse it and** you get subtly wrong CDN routing nationally, with no signal
that it is happening.

## 3. Each node announces its own anycast address

**The decision.** Two anycast service addresses. Node 1 announces the first, node
2 announces the second, and every POP repeats the pattern. Subscribers receive
both as primary and secondary.

**Why it matters.** A subscriber's two resolvers are always different physical
machines. A node-level fault that is not a clean failure — a bad build, a policy
bug, a process still passing its own checks — cannot take out both of their
resolvers at once. Putting both addresses on both nodes would let the router land
both on the same box, quietly turning two configured resolvers into one point of
failure.

**What it costs.** A single node failure leaves the POP: that address is served
from the next state until the node returns, and the same-role node there carries
two states' primary load. Capacity planning must assume that.

**A second failure domain comes with it.** Each node peers with its own PE where
the topology allows, so a router failure withdraws one address rather than the
whole POP. Two nodes on one router means that router is a single point of failure
and the second node bought nothing.

**Status: reasoned and documented, not yet run.** The lab uses a single shared
address on both nodes, so this is the top outstanding verification item — see the
lab-versus-reference table in Part 1.

## 4. The control plane converges; it does not vote

**The decision.** Last-write-wins ordered by a Lamport counter with node ID as
tiebreak, deletes as tombstones, gaps repaired by anti-entropy. No consensus
protocol.

**Why it matters.** Writes land on either node with no primary to track and no
coordination round trip, and a node that was down catches up on rejoin. Raft was
built for this and deleted: **at two nodes its quorum is 2 of 2, so a single
failure freezes the control plane entirely** — strictly worse than no consensus,
because LWW keeps accepting writes and reconciles later.

**What it costs.** The same record edited on both nodes during a partition loses
one edit on heal. Deterministic, never corrupting, and small in practice because
the OSS/BSS is normally the only writer.

**Reverse it and** at N=2 you have made a single node failure a management outage.

## 5. The query path does no I/O, and the control plane cannot stall it

**The decision.** Policy and subscriber lookups are lock-free reads of
atomically-swapped structures. Feed content is fetched out of band and swapped in
whole. Nothing on the query path touches a disk, a database or the network except
to resolve.

**Why it matters.** This is what makes a filtering product safe to run on a
carrier resolver. A policy push does not pause resolution. A blocklist that will
not download leaves the previous rules serving. A management plane that is wedged,
a pair link that is cut, a control store that is stale — none of them can stop
the node answering queries.

**What it costs.** Policy changes are eventually consistent across a pair rather
than transactional, and feed content is a fetch-and-verify pipeline rather than a
simple read.

**Reverse it and** filtering becomes a way to take resolution down.

## And two that are smaller but load-bearing

**Health owns one decision, and probes the real path.** One component decides
whether the node belongs in the anycast set, and it decides by running queries
through the same handler chain a subscriber uses. This is what caught the
validation bug that had both lab nodes withdraw themselves — a bug three layers
away from anything a health endpoint would have tested.

**Privilege is split across two daemons.** Installing routes needs
`CAP_NET_ADMIN`. The resolver does not get it. The route agent gets nothing else,
not even the bind capability the resolver has.

---
---

# Part 4 — Everything else we considered

## Why not run an existing resolver

Every candidate was measured against four requirements, and a candidate had to
meet them **without being patched** — maintaining a private fork of someone
else's resolver forever is a worse position than writing our own.

| | Requirement |
|---|---|
| **R1** | Per-subscriber policy on the query path, identity by source prefix, per-subscriber allow lists beating shared feeds, with no reload or cache flush when it changes |
| **R2** | Insert and retrieve **individual cache entries** at runtime, carrying remaining TTL and DNSSEC status |
| **R3** | A health probe traversing the real serving path, driving BGP |
| **R4** | Per-address `SO_REUSEPORT` sockets and per-family outbound source pinning |

**R2 rules out every mainstream recursor.** None exposes per-entry cache
insertion — and that is not an oversight on their part. A cache write API is a
poisoning primitive; their position is correct for their product and
disqualifying for ours.

**Unbound** — the default choice, and the one that took the most work to rule
out. Per-client policy is a *view*, views are declared in the config file, and
**`unbound-control` cannot create one at runtime**. Every subscriber override
becomes a config edit and a reload on a box carrying production traffic. Its
cache offers whole-file dump and load, nothing finer. It meets R4 cleanly. Its
`dynlibmod` escape hatch means writing C against a module ABI inside someone
else's memory model — more risk than writing Go, and it still does not solve R2.

**BIND 9** — the same view-and-reload problem, plus surface area as its own
disqualifier: an authoritative server, a DNSSEC signer, a dynamic-update target
and a DLZ host, none of which we use, all of which is attack surface on a box
every subscriber can reach.

**PowerDNS Recursor** — the closest call, and it deserves the credit. `gettag` is
designed to classify a client cheaply and return a tag selecting policy, which is
genuinely close to what we do. It fails on the hot path rather than on
expressiveness: a Lua VM invocation per query against a 3.6 ns budget, and a
second garbage collector in the process. It fails R2 outright. And the decisive
practical point — choosing it still means writing the control store, the
replication, the health daemon and the policy layer, so the build is not avoided,
only split across two languages and two processes. GPLv2 would also permanently
constrain a licence decision that is still open.

**Knot Resolver** — architecturally the closest, and the only candidate whose
cache is externally addressable at all (LMDB, shared between processes on one
host). But that sharing is between processes, not hosts, and the layout is an
internal format with no stability guarantee — building pair replication on
another project's on-disk format makes every upstream release a risk to our
replication. Per-query Lua, and GPLv3.

**CoreDNS** — the sharpest form of the question, since it is Go and pluggable.
But it does not recurse; it forwards. The historical route to recursion under it
was a plugin wrapping libunbound via cgo, which lands back at Unbound with an
extra dependency and cgo in the build.

**nscd, dnsmasq, systemd-resolved** — category, not capability. All are stub or
forwarding caches for one host or a small network; none recurses, and each needs a
real recursive resolver behind it. nscd in particular is glibc's *NSS* cache: it
does not listen on 53, does not speak DNS to clients, caches `getaddrinfo()`
results rather than RRsets, and expires them on a configured constant instead of
the record's TTL — which alone breaks CDN and failover behaviour.

**Buying a commercial platform** — a real option, weighed as one. Against it:
recurring per-subscriber licensing on a pure-cost function, no ability to change
filtering behaviour on our own timetable, subscriber query data leaving our
control, and an upgrade cadence set by a vendor.

## Other roads not taken

| Considered | Rejected because |
|---|---|
| **A VIP per POP** (keepalived/VRRP) | Solves a problem anycast already solves, and adds a second failover mechanism with its own split-brain modes |
| **Three or five nodes per POP** | Two is what the traffic needs; adding a third so a consensus protocol has a quorum is letting software dictate rack layout |
| **Designating ns1 as config primary** | Writes must land on either node; a primary also means provisioning must track which node is primary and handle it being down |
| **Re-validating cache entries received from the sibling** | Doubles validation cost against an attacker already inside a mutually-authenticated trust boundary. The accepted consequence — a compromised node can poison its sibling — is recorded rather than hidden |
| **Embedding BGP in the resolver** | Every resolver restart, including a routine upgrade, would drop the session and blackhole the prefix |
| **Shelling out to `vtysh`/`birdc`/`gobgp`/`ip route`** | Parsing CLI output makes routing behaviour depend on a text format nobody versions |
| **An IGP on the resolvers** | Makes a resolver a routing participant, where a sick node can affect SPF for the whole area |
| **Wall-clock timestamps for replication ordering** | Requires clock sync; NTP skew silently reorders writes and the failure is invisible |
| **Vector clocks** | Correctly detect concurrent writes, but something must then pick a winner anyway — extra machinery for detection we cannot act on |
| **A customer self-service portal** | Would require multi-tenant RBAC across the whole management plane. If wanted, it should be a separate application against this API, not a mode of the resolver |
| **An external identity provider** | A resolver must be manageable during exactly the network events that make an external IdP unreachable |
| **dnstap for per-query streaming** | Deferred, deliberately: it carries full query names and client addresses, which is precisely what the privacy design excludes. It needs a retention policy and access model agreed before it is switched on, not after |

## What would make this decision wrong

**If per-subscriber policy and pair cache sharing were both dropped from the
product, Unbound would be the correct answer and this project would not be
justified.** R1 and R2 carry the decision; R3 and R4 are achievable elsewhere
with effort. Anyone arguing to buy or wrap should be arguing that those two
requirements are not real — that is the actual debate, and it is a legitimate one.

The other way it goes wrong is sustained under-investment. A resolver we own
needs its invariant tests kept green and its RFC behaviour kept current. That
obligation is permanent and it is the true cost of the decision.

## What is outstanding

Every feature originally planned has landed. What remains splits into two kinds
of work, and the first kind matters more than the feature list ever did.

**Verification — the reference model has not been run:**

1. **Stand up one POP to the model in `provisioning.md`** — one node per PE,
   public addressing with no NAT, eth0 as the query source, each node owning its
   own anycast address. The lab differs from this in six respects (Part 1), so
   this is the first time the production topology will exist anywhere. Before the
   first production deployment, not during it.
2. **A second POP**, since "the same address announced from every POP" is the
   property that makes inter-POP failover real and cannot be shown with one.
3. **Config anti-entropy over a multi-day window** — unit-tested and lab-verified
   in short runs.
4. **A soak under real subscriber load.**

**Deliberately deferred, with reasons:**

| | Status |
|---|---|
| **Public IPv6 anycast** | Needs a separately routed prefix rather than an on-link `/64`. A `/128` taken from a connected subnet makes the router attempt neighbour discovery for it on the wrong interface |
| **Session replication** | A console session is node-local, so moving to the sibling means signing in again. A considered trade: replicating live session state would put mutable per-request data on the pair link for a saving measured in one login |
| **A licence** | Not yet chosen, and needed before any external distribution |
| **RFC 8326 `GRACEFUL_SHUTDOWN`** | Planned maintenance does a plain withdraw, which works but drops what was in flight when the route disappears. Tagging routes with the community first would let the PE drain the path before withdrawal |

**Where the risk sits now.** It has moved out of the code and into deployment.
The features are built, tested and lab-verified; what has not been proven is the
production topology and multi-day behaviour under real subscriber load. That is
the right place for a project at this stage to be — but it should be said plainly
rather than inferred from a short list.
