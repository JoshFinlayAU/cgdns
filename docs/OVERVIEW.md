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
· [What it costs, and what POP-BNE has proved](#what-it-costs-and-what-is-still-unproven)
· [Evidence](#the-evidence-behind-those-claims)

**Part 2 — [The components](#part-2--the-components)**
· [Query path](#the-query-path-in-order)
· [Resolution engine](#the-resolution-engine)
· [DNSSEC](#dnssec)
· [Caching](#caching)
· [The pair](#the-pair)
· [Anycast and routing](#anycast-and-routing)
· [Management](#management)
· [Certificates and the external probe](#certificates-and-judging-the-node-from-outside-itself)
· [Packaging](#packaging-and-operations)

**Part 3 — [The architecture decisions that matter](#part-3--the-architecture-decisions-that-matter)**

**Part 4 — [Everything else we considered](#part-4--everything-else-we-considered)**
· [What we are deliberately not doing](#things-we-are-deliberately-not-doing-and-the-bar-for-changing-that)
· [What is outstanding](#what-is-outstanding)
· [How this has been tested and hardened](#how-this-has-been-tested-and-hardened)

**→ [What I need next: a second POP in S1](#what-i-need-next-a-second-pop-in-s1)** — *the ask, if you read nothing else*
· [Addressing](#addressing) · [BGP peering](#bgp-peering) · [The test plan, already written](#the-test-plan-is-already-written)

---
---

# Part 1 — What this is, and why it should go national

## In one paragraph

cgdns is the recursive DNS resolver our subscribers use. It answers queries
itself — walking the delegation chain from the root rather than forwarding to
anyone else's resolver — validates DNSSEC, and applies per-subscriber policy
where a filtered product has been sold. It runs as two nodes per POP, each
announcing one of the two anycast addresses subscribers receive as their primary
and secondary. Nodes are managed through a REST API and a CLI — and
an optional web console — all equivalent, from either node. A sick node withdraws itself from BGP and traffic
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

**POP-BNE is live, built to the reference model, and carrying real subscriber
traffic.** A household resolves through it, and the counters below were read off
the running nodes rather than inferred.

Verified on `athena--dns1` and `athena--dns2`, and at the PE, which is the only
place that proves an announcement landed:

| Property | State |
|---|---|
| Services | `cgdns`, `gobgpd`, `cgdns-routed`, `cgdns-probe` — all active on both nodes |
| BGP | One session per family per node to the PE, both established |
| Anycast | `anycast0` holds `160.30.37.252/32` + `2001:df4:2040:53::1/128` on ns1, `.253`/`::2` on ns2. `cgdns_anycast_advertised 1` on both |
| Learned default | Installed per family by the route agent at metric 5, with the correct preferred source (`src 160.30.37.37`) |
| Query source | `outbound_source_v4/_v6` pinned to eth0, never the anycast address |
| Encrypted transports | DoT + DoQ on 853, DoH on 443, TLS 1.3 minimum, on both anycast addresses in both families |
| Certificates | **Publicly trusted Let's Encrypt**, issued automatically — `dns1.as135559.net.au` and `dns2.as135559.net.au`, valid to 15 Nov 2026. Zero ACME failures |
| Pair link | `cgdns_peer_inbound_up 1` and `_outbound_up 1` on both, with peer cache fetches actually being served |
| DNSSEC | Validating and rejecting: secure, insecure and bogus all counting |
| Cache | Memory-bounded at 1 GiB; currently a few hundred KiB and ~1,300 entries |

**A metric worth understanding before anyone alerts on it.**
`cgdns_dnssec_bogus_total` sits in the low hundreds on both nodes, and **that is
the system working**. Almost every one of them is `dnssec-failed.org` — the
deliberately broken zone `cgdns-probe` queries on a timer to confirm validation
is still *rejecting*. A resolver that only ever counted `secure` would look
healthier and be less trustworthy. Alert on a *change in the rate* against a
known baseline, not on the counter being non-zero.

**What POP-BNE does not yet prove**, and these are the honest remaining gaps:

- **Carrier query volumes.** One household is real traffic, not representative
  load. Nothing here has been driven at the rates a state's subscriber base
  produces.
- **Inter-POP behaviour.** With one POP there is nowhere for an address to move
  to. The property that makes anycast worth having — a node withdrawing and the
  same address answering from the next site — cannot be demonstrated until a
  second POP exists. **This is now the single most valuable next step.**
- **The withdrawal path in production.** Exercised thoroughly in the lab, not yet
  drilled at POP-BNE.
- **Multi-day behaviour under sustained load**, as opposed to multi-day
  behaviour under a household's.

**One deliberate divergence from the written model, and it has a cost worth
knowing.** POP-BNE peers **iBGP inside AS135559** rather than the private-ASN
eBGP that `provisioning.md` describes, because it matches the pattern already
used elsewhere in the estate. The consequence is iBGP split horizon: a route
learned from one iBGP peer is never re-advertised to another, so the anycast
prefixes reached the PE and stopped one hop later — the PE could reach them and
nothing else could. Resolved by making the PE a route reflector for those
sessions. **eBGP with a private ASN avoids this entirely**, because eBGP-learned
routes propagate into iBGP without reflection. The choice is not cosmetic, and
it is worth settling deliberately before the second POP rather than inheriting it.

**Capacity planning has a consequence people miss.** Because each node holds one
of the two addresses, a single node failure sends that address to the next state.
The same-role node there must be sized to absorb a neighbouring state's primary
load.

---

## The evidence behind those claims

| Claim | Backed by |
|---|---|
| Correctness of the resolution engine | **406 tests, 13 benchmarks and 9 fuzz targets**, `-race` clean, **zero skipped tests**; verified live against the real root servers |
| DNSSEC validation | `AD` set on `iana.org` and `cloudflare.com`; SERVFAIL with EDE 9 on `dnssec-failed.org` |
| IPv6 is real, not nominal | Full lab run with **IPv4 egress disabled entirely** — every outbound query over v6, DNSSEC still validating |
| Anycast failover | Lab: prefix withdrawn on SIGTERM, router moves to sibling, no failed queries, re-advertises on restart |
| Pair link under partition | Lab: `iptables` DROP both directions — both nodes keep resolving, both stay in the anycast set, link heals and resumes |
| Config replication | Lab: write on either node reaches the other; a write made during a partition catches up on heal with matching hashes |
| Rate limiting under attack | Lab: 15 000 queries at 500/s, collapsed to one bucket, node stayed healthy and advertised |
| Aggressive NSEC/NSEC3 | Live internet: 49/50 synthesised on NSEC and small NSEC3 zones; measured honestly, including the large-zone case where it saves much less |
| Serve-stale vs health | Lab: isolated node kept answering cached names **and still withdrew**, citing that the root NS came from expired cache |
| Packaging | Real `.deb` install on a lab node, including the upgrade and removal paths |
| **The deployment model itself** | **POP-BNE, built to `provisioning.md`**: four prefixes active at the PE with native next hops, defaults learned and installed per family, egress source confirmed by capture |
| **Real subscriber use** | **A household resolving through POP-BNE today**, over both anycast addresses and both families |
| Automatic certificates | Publicly trusted Let's Encrypt certificates issued and installed on both nodes without manual steps, zero ACME failures |
| The pair link in production | Peer up in both directions on both nodes, with cache fetches actually served between them |
| Wire parsers under hostile input | **Nine fuzz targets** over the parsers where attacker-chosen bytes become a decision — denial proofs, the aggressive store, feed and root-hints parsing, and the listener acceptance path. **Nine million executions, nothing found** |
| Judged from outside itself | `cgdns-probe` runs off-node, queries the anycast address as a subscriber does, and judges only the answer returned |

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

**The cache is bounded by memory, not by entry count.** An entry count cannot
bound memory: an entry holding eight address records costs roughly two and a half
times one holding two, so the same `max_entries` can mean 380 MB or 930 MB
depending on what subscribers happen to ask for. That is not a figure a node can
be sized against, and the failure mode is the process being killed rather than
the cache getting smaller. `cache.max_size` takes the memory instead — `512MiB`,
`2GiB`, or a byte count — enforced by the same LRU eviction per shard, with the
entry count still capping the map itself. Both bounds apply, whichever binds
first. `cgdns_cache_bytes` reports where a node actually sits.

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

**The local node is managed over a unix socket**, not a token.
`cgdnsctl` talks to `/run/cgdns/control.sock`; the file is `0600` and the peer's
uid is checked at accept, so a request arriving there is authorised by the socket
itself. Whoever can open it can already read the config, replace the binary and
stop the service — a token on top of that protects nothing, and it does leave a
standing admin secret in a file or a shell history. It is a socket rather than
loopback TCP so that argument holds: a TCP port is reachable by every local user
and, given a routing mistake, from off the box. Tokens remain what a *remote*
operator or a sibling node uses.

**Web console**, embedded in the binary and **off by default**: three files, no
framework, no build step, nothing fetched from a CDN. It is the only part of the
daemon that accepts credentials, holds sessions and renders HTML — a standing
authentication and XSS surface on a resolver — so it is carried only where
somebody actually wants it. `ui: true` brings it back. Content-Security-Policy has no `unsafe-inline`
because the console renders every value with `textContent`, so an operator-supplied
record can never be parsed as markup. It adds no listener of its own.

**Telemetry.** 105 Prometheus series on the management plane, read at scrape time
from atomic counters so instrumentation costs the query path one increment.
Structured JSON logs make a per-event stream that journald and a shipper turn
into Kafka, Loki or a SIEM feed. Nothing is labelled by query name or client
address.

## Certificates, and judging the node from outside itself

**ACME issuance and renewal is built in.** DoT, DoH and DoQ need a certificate
subscriber devices trust, and renewing one by hand is a scheduled outage —
silent until the day it expires, then every encrypted client stops resolving at
once. The manager writes to the same `listen.tls` paths the listeners read, so
the two cannot drift, and renewals are picked up on the next handshake rather
than by restarting a listener.

- **http-01 is the default, and its port is not left open.** It binds when a
  challenge starts and closes the moment it finishes — about fifteen seconds a
  quarter, recorded in `cgdns_acme_challenge_seconds`. A resolver's addresses are
  reachable by every subscriber and, through the covering prefix, from the
  internet; a web server running all year to serve one file for a few seconds is
  attack surface bought for nothing.
- **dns-01 is used instead wherever a provider is configured**, because it opens
  nothing — and it is the only workable option once a name is anycast from
  several POPs, where the CA would validate against whichever POP is nearest *it*
  rather than the one asking.
- **A certificate no public CA vouches for is treated as needing replacement**
  even when it is valid for years and names the right hosts. An interim
  placeholder passes every expiry and hostname check, so nothing else would ever
  replace it.

**`cgdns-probe` judges the resolver from outside itself.** A node's metrics
describe what it believes; they cannot describe what a subscriber receives, and
the gap between those two is where the serious incidents live. The probe runs
elsewhere, speaks to the anycast address the way a subscriber does, and judges
only the answer that comes back.

Three checks, because there are three distinct ways to be broken:

| Check | Catches |
|---|---|
| A signed name returns NOERROR **with `AD`** | Validation has silently stopped — no availability check would notice |
| A deliberately broken zone returns **SERVFAIL** | Validation is not *rejecting*, so subscribers are exposed to forged answers |
| An ordinary name resolves | Plain availability |

Passing only the third looks perfectly healthy and is not DNSSEC at all.

UDP, TCP and DoT; Prometheus metrics with `-listen`, or one-shot with a non-zero
exit. Deployed at POP-BNE with each node probing its sibling, which is
independent of either node's self-report. **Where a probe rule and a node rule
disagree, believe the probe** — the alert rules are ordered to say so. Verified
by drill rather than by assertion: stopping cgdns on one node turned all three of
its sibling's checks red within twelve seconds.

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
through the same handler chain a subscriber uses. That means it detects "this
node cannot resolve" whatever the cause, including causes several layers away
from anything a dedicated health endpoint would exercise — which is the whole
point of probing the serving path rather than a private one.

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

## Things we are deliberately not doing, and the bar for changing that

This section exists so that "why aren't you using X" has an answer that is not a
shrug — and so that adding X has a standard to meet rather than a mood.

Every item below was considered and set aside on a reason, not on unfamiliarity:

| Not doing | Why not |
|---|---|
| **DoH3 / HTTP/3** | DoQ (RFC 9250) already gives per-query streams over QUIC. DoH3 adds an HTTP layer on top of the same transport for no benefit a resolver can use |
| **Oblivious DNS (ODoH)** | It exists to hide subscriber queries *from the resolver operator*. We are the resolver operator, and the queries are already ours by design |
| **DNSCrypt** | Pre-standard, superseded by DoT/DoH/DoQ, and no client population that matters requires it |
| **eBPF / XDP fast path** | The hot path is already zero-allocation with a 344 ns cache hit. Nothing measured says the kernel boundary is the bottleneck, and adding one would be optimising by reputation rather than by profile |
| **Kubernetes, containers, a service mesh** | The workload is two long-lived processes per POP that must bind fixed addresses, hold BGP sessions and keep serving while the control plane is down. An orchestrator adds a dependency in exactly the failure mode where nothing else may be depended on |
| **A distributed cache (Redis, memcached)** | Cache is POP-local *by correctness requirement*, and the pair already shares it in under a millisecond. A network round trip to a shared store is slower than the local memory it would replace |
| **ML / "AI-powered" threat feeds** | The policy engine consumes any feed you point it at. What generates a feed is a supplier decision, not a resolver decision, and putting a model on the query path would break the no-I/O rule |
| **A rewrite in Rust** | Would buy tail-latency predictability we have not measured a need for, at the cost of the pool of people here who can maintain it |
| **Multi-tenant RBAC / a customer portal** | A separate application against the existing API, if it is ever wanted. Not a mode of the resolver |

**The bar for revisiting any of these** — the same bar the current design had to
clear:

1. **Name the requirement it serves.** A customer need, an obligation, or a
   measured problem. Not a capability.
2. **Show the measurement**, if the claim is performance. A profile or a
   benchmark against `main`, not an article.
3. **Say what it costs** — dependencies, failure modes, attack surface, and who
   maintains it at 3 a.m.
4. **Show it breaks no design constraint**: no I/O on the query path, no unbounded
   work per query, nothing trusted beyond its authority, dual-stack throughout, no
   subscriber data in logs or labels, fail loudly at startup.

Anything clearing those four gets built. Anything that cannot is a preference —
and preferences are how carrier infrastructure accumulates the complexity that
eventually takes it down.

## What is outstanding

Every feature originally planned has landed, and POP-BNE is live and serving. The
remaining work is proving behaviour that one POP and one household cannot show.

**Verification:**

1. **A second POP.** With one site there is nowhere for an anycast address to
   move to, so the property that justifies the whole design — a node withdrawing
   and the same address answering from the next site — has not been demonstrated.
   **This is the most valuable next step by a distance.**
2. **A withdrawal drill at POP-BNE.** Exercised thoroughly in the lab; not yet run
   against the live PE.
3. **Carrier query volumes.** A household is real traffic, not representative
   load.
4. **Config anti-entropy over a multi-day window** — unit-tested and lab-verified
   in short runs.

**Where the deployed configuration differs from the documented defaults.** Both
are deliberate operator choices at POP-BNE, and both are worth revisiting rather
than inheriting:

| Setting | Default | POP-BNE | Consequence |
|---|---|---|---|
| `resolver.max_outbound_per_query` | 32 | **100** | This is the amplification limit. A higher cap resolves deeper or more awkward delegation chains, and raises the ceiling on what a single client query can generate |
| `resolver.accept_sha1` | false | **true** | RSASHA1 signatures are accepted. SHA-1 is not collision resistant, so this weakens exactly the guarantee validation exists to provide |

**Filtering is not enabled in production.** There is no `policy` block in the
POP-BNE configuration, so the enforcer is not in the query path at all. The
capability is built, tested and documented; it is simply not switched on, which
is the correct state until something is sold that needs it.

**Open items at POP-BNE**, small but real:

| | Status |
|---|---|
| `no-export` on the anycast prefixes | The inbound filter no longer sets it. Sampled external sessions show the prefixes are not being advertised out, but the community is the belt-and-braces and it is absent |
| A v6 `/127` for the pair link | The pair link is v4-only there |

**Deliberately deferred, with reasons:**

| | Status |
|---|---|
| **Session replication** | A console session is node-local, so moving to the sibling means signing in again. A considered trade: replicating live session state would put mutable per-request data on the pair link for a saving measured in one login. The console is off by default in any case |
| **A licence** | Not yet chosen, and needed before any external distribution |
| **RFC 8326 `GRACEFUL_SHUTDOWN`** | Planned maintenance does a plain withdraw, which works but drops what was in flight when the route disappears. Tagging routes with the community first would let the PE drain the path before withdrawal |

**Where the risk sits now.** It has moved out of the code, through deployment,
and into scale. The software is built, tested, fuzzed and running; the model is
deployed and serving real queries. What is unproven is behaviour across sites and
at volume — which is a materially better place to be than a fortnight of
documentation would suggest.

---

## How this has been tested and hardened

Gathered in one place, because "it has been tested" means nothing without saying
how.

### Correctness

| | |
|---|---|
| **378 tests, 13 benchmarks** | Across 22 packages, over ~18,100 lines of non-test Go |
| **Zero skipped tests** | Deliberate policy. The dual-stack tests skip *loudly* if IPv6 disappears, because a green run with skips is not coverage |
| **`-race` mandatory** | This is a heavily concurrent daemon; a data race that only appears under production load is not something to find under production load |
| **`go vet`, `gofmt` clean** | Enforced by `make check` |
| **Table-driven, with golden wire fixtures** | New protocol behaviour gets a captured wire-format fixture in `testdata/` |
| **Benchmark comparison before merge** | Resolver or cache changes are not merged without a benchstat comparison against `main` |
| **Every security invariant has a named test** | Bailiwick rules, the 32-query amplification cap, 0x20 verification, stripped-DS-is-bogus, denial validation. Each is confirmed to fail when the property it guards is removed — a test that cannot fail is not evidence |

### Verified against the real internet, not just a lab

Resolution from the live root servers, cold and warm. DNSSEC `AD` on `iana.org`
and `cloudflare.com`; SERVFAIL with EDE 9 on `dnssec-failed.org`. Cross-TLD
CNAME chains, glueless delegations, NXDOMAIN with SOA. Aggressive NSEC/NSEC3
measured against `nlnetlabs.nl`, `isc.org`, `debian.org` and an unsigned control.
A full run with **IPv4 egress disabled entirely**, so every outbound query went
over IPv6 and DNSSEC still validated.

### Attack and failure testing

- **Live flood** against a running node: 15 000 queries at 500/s. Confirmed the
  limiter collapsed a water-torture flood into one bucket, answered at the
  configured rate, and — the part that matters — **the node stayed healthy and in
  the anycast set throughout**. A resolver that limits itself out of the anycast
  set has turned an attack into an outage.
- **Node isolation** with both `iptables` *and* `ip6tables`, confirming a node cut
  off from the internet keeps answering cached names for subscribers **and still
  withdraws itself**.
- **Pair partition** with traffic dropped in both directions: both nodes keep
  resolving, both stay advertised, the link heals on its own.
- **Anycast failover**: prefix withdrawn on SIGTERM, router moves traffic, no
  failed queries, node re-advertises on restart.
- **A real package install** on a lab node, including the upgrade and removal
  paths and the shadowing-unit trap.

### Security posture, by construction

| Layer | What is enforced |
|---|---|
| **Query ACL** | Default-deny and *required* — the daemon will not start without one. A `/0` logs a loud warning |
| **Amplification** | Hard cap on outbound queries per client query, shared across every sub-lookup it triggers |
| **Cache poisoning** | Strict bailiwick checks; out-of-bailiwick glue discarded, never cached. 0x20 mixed-case verification on every response |
| **DNSSEC downgrade** | A stripped DS is *bogus*, not insecure. No silent downgrade, ever |
| **Management plane** | Default-deny ACL enforced at `accept`, before the TLS handshake. Never on a wildcard, a DNS address, or inside an anycast prefix. TLS mandatory off loopback |
| **Credentials** | API tokens constant-time compared against a dummy hash to defeat timing enumeration; operator passwords argon2id + TOTP; only hashes replicate |
| **Web console** | CSP with no `unsafe-inline`, every value rendered via `textContent`, `__Host-` cookie, `SameSite=Strict` plus a CSRF token a cross-origin request cannot produce |
| **Pair link** | Mutual TLS with a CA, required by config validation — the sibling can write to this node's cache |
| **Process** | systemd-hardened: `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, and a capability bounding set of exactly one capability |
| **Privilege separation** | The resolver cannot install routes. The route agent cannot bind privileged ports. Neither can do the other's job |
| **Memory safety** | Go, no cgo, on a codebase whose entire input surface is attacker-controlled |
| **Supply chain** | Eight direct dependencies, no web framework, no ORM, no logging or metrics library, no test framework beyond stdlib |

### Fuzzing

**Nine targets**, covering the places where bytes an attacker chooses become a
decision the resolver acts on. **Nine million executions found nothing**, which
is worth knowing either way.

The denial proofs get the most attention, because they decide whether a name is
*securely absent* and a wrong answer there is a downgrade rather than a crash.
Those targets assert more than the absence of a panic: a held no-DS proof must
not be contradicted by a DS sitting in the very records it read, and a zone-cut
verdict must come from a record that actually matches the name. The rest cover
the aggressive-denial store, which must never synthesise a denial without an SOA
or with a dead TTL; the feed and root-hints parsers, which read third-party and
operator files; and the acceptance path every listener applies before the
resolver is involved.

### In production

POP-BNE is verified where it counts rather than where it is convenient: all four
anycast prefixes active **at the PE** with native next hops, defaults learned and
installed per family at metric 5 with the correct preferred source, 6/6 signed
domains validating with `AD` over both anycast addresses in both families, and
**every outbound query sourced from eth0 rather than the anycast address,
confirmed by packet capture**. Encrypted transports answer on both addresses
under publicly trusted certificates. The pair link is up in both directions and
serving cache fetches between the nodes. A household resolves through it.

The external probe is verified **by drill, not by assertion**: stopping cgdns on
one node turned all three of its sibling's checks red within twelve seconds.

### Where the testing does not reach

Said plainly: no second POP, so inter-POP failover is undemonstrated; no
withdrawal drill against the live PE; and no load beyond a household. Those are
the three gaps, and they are the first three items in the list above.

---
---

# What I need next: a second POP in S1

**The first POP is already built, live, and serving.** POP-BNE runs the model in
`provisioning.md`, announces four anycast prefixes that are active at the PE and
reflected across the estate, resolves with DNSSEC over both families, serves the
encrypted transports, and has a household resolving through it. It was stood up,
verified at the router, and it works.

So this is no longer a request to find out whether the thing runs. **It is a
request for the one property a single site cannot demonstrate: that an address
withdrawn in one POP is answered by the next one.** That is the whole reason for
building it this way, and until a second POP exists it is a design argument
rather than a demonstrated fact.

S1 is the obvious second site. Here is exactly what it needs.

## Addressing

| # | What | For | The important bit |
|---|---|---|---|
| **2 ×** | **`/31`** to the Nokias in S1 | `eth0` on each node — the eBGP session **and** the source of every outbound query | One per node. **Must sit inside an aggregate we announce globally**, because authoritative servers on the internet reply to this address. The `/31` itself never leaves our network |
| **2 ×** | **`/127`** to the Nokias in S1 | the same, IPv6 | RFC 6164. Same global-aggregate requirement |
| **2 ×** | **`/32`** I can announce to the Nokias | the anycast service addresses — one owned by each node | Stays **inside our routing domain**, tagged `no-export`. Subscribers are internal, so it never needs to survive public-internet filtering |
| **2 ×** | **`/128`** I can announce to the Nokias | the same, IPv6 | Needs to come from a **routed** prefix, not an on-link `/64` — a `/128` out of a connected subnet makes the router run neighbour discovery for it on the wrong interface |

**The distinction between the first two rows and the last two is the one to get
right.** The `eth0` addresses must be globally reachable, because that is where
the world replies to. The anycast addresses must *not* leave our routing domain,
because leaking them draws traffic toward a node that is not the nearest. Getting
these the wrong way round produces a resolver that looks perfectly configured and
cannot resolve anything.

## BGP peering

**One session per node, per family, to that node's own Nokia** where the topology
allows. If both nodes peer with the same router, that router is a single point of
failure for the entire POP and the second node has bought us nothing.

From the PE side:

- eBGP to each node — private ASN on our side, single-hop over the interface.
- **Originate a default** to each node. That is the only default they take;
  management deliberately supplies none, so that a BGP failure can never silently
  turn the management path into the service path.
- **Accept only the anycast prefixes**, filtered to exactly the `/32` and `/128`
  above and tagged `no-export`. Reject everything else from them.

`docs/provisioning.md` has the complete working configuration for both sides. The
PE example there is written against RouterOS, so the S1 Nokias need the SR OS
equivalent — a small piece of work, but it is your team's to do and it is the
only part of this I cannot write myself.

**One thing to decide deliberately rather than inherit: iBGP or eBGP.** POP-BNE
peers iBGP inside AS135559, matching the pattern already used in the estate, and
that ran straight into split horizon — a route learned from one iBGP peer is
never re-advertised to another, so the anycast prefixes reached the PE and went
no further. The PE could reach them; nothing else could. It is fixed there by
making the PE a route reflector for those sessions. **eBGP with a private ASN
avoids it outright**, because eBGP-learned routes propagate into iBGP without
reflection. Either works. I would rather we picked one on purpose for S1 than
copied BNE without noticing why it needed a route reflector.

## One thing that is easy to forget

**A `/31` and a `/127` for the pair link** between the two nodes. It is a directly
connected cable between adjacent boxes and is never announced, but it is numbered
from public space on purpose: it keeps ICMPv6 errors and traceroute honest and
avoids the source-selection surprises ULA brings (RFC 6724). Everything crossing
it is mutually authenticated TLS regardless.

Management addressing on `eth2` can come from the existing S1 management range.

## And the thing I need most

**Time to test it properly, and the trust to do that before anyone mentions
customers.**

To be completely clear about what I am **not** asking for: **no customer goes
near this. Not one.** The first four things on the old version of this list are
now done and verified at POP-BNE. What a second site adds is the rest:

1. A single node failing, and **only its address moving** — to the other POP
2. Inter-POP behaviour generally: nearest-site selection, and reconvergence
3. The withdrawal path drilled against live PEs rather than a lab router
4. Two sites' worth of sustained running before anyone discusses a customer

The household is on it because I am willing to be the first person inconvenienced
if it breaks. That is the order I would like to keep: me, then internal, then a
customer who has been asked.

I will come back with the results either way, including the parts that do not
work. The flood test, the isolation test and the partition test all exist because
the failure case is the one worth designing for, and that is the standard I want
this held to.

When it has run clean for long enough that I would put my own service behind it,
I will say so. **Then** we can have the conversation about a customer.

## The test plan is already written

This is not a request for time to work out how to test it. The turnup and
verification procedure is written up in `docs/provisioning.md`, and it is
specific about where each check is made.

**The principle it is built on: verify at the far end, not the near end.** A
daemon reporting on itself proves the daemon's opinion.
`cgdns_anycast_advertised` reports the node's internal health decision and says
nothing about whether a route ever left the box — so the announcement is
confirmed **on the PE**, not on the node.

| Check | Where | Proves |
|---|---|---|
| `/ip route print where bgp` — expect one `/32` and one `/128` per node | **On the PE** | The announcement actually landed |
| `gobgp neighbor`, `ip route show default proto bgp` | On the node | Sessions are up and the learned default is installed |
| `tcpdump -ni eth0 'udp port 53'` | **On the wire** | Every outbound query carries `eth0`'s address, not the anycast one |
| `systemctl stop cgdns` | **On the PE** | Withdrawal removes exactly that node's two prefixes |

**The packet capture is not optional, and it is the check most worth
understanding.** Sourcing a query from the anycast address is the single failure
the whole addressing model exists to prevent — and it is **invisible from inside
one POP**, because the replies still come back to the only node announcing that
address. It only breaks once a second site exists, at which point replies start
landing on a node that never asked. A capture detects it on day one, in one POP,
which is why it is a check at every build rather than a thing to remember later.

A `dig` against the anycast address proves an answer came back. It does not prove
which family or which source address produced it, and those are exactly what this
model depends on getting right.

**So the sequence is:** interfaces on both nodes, PE sessions and filter, gobgpd,
then cgdns — which announces only once its health checks pass. Each stage is
verifiable before the next one starts, and none of it involves a customer.
