# cgdns

Carrier-grade recursive DNS resolver. Anycast-served, DNSSEC-validating, with per-subscriber policy.

The recursion engine is its own - it walks the delegation chain from the root rather than wrapping Unbound, BIND or PowerDNS.

..before you say it, I know per-subscriber policy doesn't sound very carrier, and it isn't until some sales guy somewhere sells someone that "filtered DNS product" that we have.. now its just an ACL. You don't have to use it, and you probably won't... until you do.

## Side note

I don't want this to be a repo/product that gets lots of feature ideas from the home labbers, its recursive DNS at carrier scale.. lets just make it fast as f*ck, simple to spin up, easy to pull telemetry out of and bug free?

## LOUIS

Start here: **[docs/OVERVIEW.md](docs/OVERVIEW.md)** — what it is, what it is made
of, the architecture decisions and why they matter, everything else that was
considered, and what I need from you to run a real-world test in S1.

Read that first and in full. It answers the questions in the order you would ask
them, and the last section is the only thing I am actually asking for.

If you still want the receipts after that, every individual decision is written
up with its alternatives and its trade-offs in `docs/LOUIS.md`, and
`docs/provisioning.md` has the addressing and BGP configuration end to end. Both
are referenced from the overview at the points where they are relevant — you
should not need to go looking.

## Deployment model

Two resolvers per POP. Each owns **its own** anycast address, and that address is announced from every POP.

```
                 ns1 address                      ns2 address
                 10.255.0.53                      10.255.0.54

  SYD            ns1 ──── pair link ──── ns2      config replication + cache sync
                  └── eBGP ── router ── eBGP ─┘

  MEL            ns1 ──── pair link ──── ns2
                  └── eBGP ── router ── eBGP ─┘

  Between POPs: nothing at all.
```

Subscribers are handed both addresses, the way anyone hands out a primary and a secondary. BGP routes each to the nearest POP announcing it, so a subscriber in Sydney reaches Sydney's ns1 and Sydney's ns2.

The reason for two addresses rather than one shared between the pair is what happens when a node dies. Sydney's ns1 withdraws `10.255.0.53`, and that address now routes to Melbourne's ns1 — a little further away but still answering. The subscriber's second resolver, `10.255.0.54`, is untouched and still in Sydney, so the common case is served locally by the other address rather than waiting on reconvergence for the same one. Lose both nodes in a POP and both addresses simply route to the next closest POP.

**Cache is shared only within a POP, never between them.** CDN and cloud resolvers return geographically specific answers based on where the *resolver* sits, so replicating a Sydney cache entry to Perth would hand Perth subscribers Sydney endpoints. This is a correctness constraint as much as it realistically is a performance choice.

### Interfaces per node

| Interface | Carries |
|---|---|
| `eth0` | eBGP session to this node's PE, and the source address for every outbound query. Public space in both families, because authoritative servers on the internet reply to it |
| `eth1` | pair link: config replication and cache sharing to the sibling |
| `eth2` | management: operator API, metrics, SSH. Supplies no default route |
| `anycast0` | this node's service address - DNS listeners bind here (read below) |

Each node peers with its own PE where the topology allows, so one router failing
does not withdraw both nodes at once. There is no loopback interface: it would
earn its place only once a node is dual-homed and needs an address that outlives
any single link.

Setting all of this up from scratch - addressing, gobgpd, the router side, and
what to check where - is written up in [docs/provisioning.md](docs/provisioning.md).

The anycast0 dummy interface was a trial by fire decision that was settled on to work in basically the same way and reason that "nameserver 127.0.0.53" does in most Linux distros these days. We just need somewhere to bind to that never goes down (and that is not attached to anything and is never gonna ARP), then we let the kernel do the routing from there on.

## Implemented

**Recursion** - delegation walk from the root. QNAME minimisation (RFC 9156) and 0x20 mixed-case encoding on by default, both with config escape hatches. Strict jurisdiction checking: out-of-jurisdiction glue is discarded, and a referral must stay inside the referring zone *and* move toward the QNAME. Forwarding mode is available behind the same interface. Per-nameserver RTT and health drive server selection.

**DNSSEC validation** - full chain of trust with IANA root anchors embedded. NSEC and NSEC3 denial of existence, NSEC3 iteration limits per RFC 9276. A broken chain is SERVFAIL with an RFC 8914 extended error; there is no silent downgrade. A stripped DS is *bogus*, not insecure - an unproven insecure delegation is a downgrade attack. `AD` is set only on a chain verified locally. Each RRset is verified against the
keys of the zone that signed it, not against one zone chosen for the whole
answer, so a CNAME that crosses a zone boundary validates on both sides of the
cut. A cached record keeps no signatures and is therefore never re-judged: the
cache records whether a chain was decided, so an entry the delegation walk
stored on its way past is resolved again rather than failed on. A DNSKEY or DS
that could not be fetched is reported as unreachable, not as a bogus zone - the
answer is still withheld, but the extended error names the real fault.

**Transports** - UDP, TCP, DoT (RFC 7858), DoH (RFC 8484 over HTTP/2), DoQ (RFC 9250). All dual-stack. DoQ shares port 853 with DoT but not the socket - one is TCP, the other UDP - and gives every query its own stream, so a slow answer no longer stalls the ones behind it the way it does on a shared DoT connection. Measured on a dev node: 40 concurrent queries on one connection in 180 ms. It wants a larger UDP receive buffer than the kernel default; raise `net.core.rmem_max` and `net.core.wmem_max` or the QUIC stack will log that it could not. Message IDs must be zero (a stream carries exactly one exchange, so there is nothing to correlate) and `edns-tcp-keepalive` is refused, both per RFC 9250; 0-RTT is left off, since its data is replayable and a resolver would take on that problem to save a round trip. UDP uses `SO_REUSEPORT` per-address sockets so replies leave with the correct anycast source. DoH ignores forwarding headers unless the peer is a configured trusted proxy, because the client address selects subscriber policy.

**Feed fetching and reload** - a feed record carrying a URL is fetched on a schedule, written to disk atomically, and compiled into new rules that are swapped in without a restart. A fetch that fails, times out, overruns its size cap, returns an error or comes back empty leaves the previous content serving; filtering goes stale, which beats filtering going wrong. `POST /api/v1/policy/refresh` forces it, so a newly added feed does not wait for the next interval.

A feed decides what subscribers are allowed to resolve, so it is treated as a control-plane operation wearing the clothes of a download. A record may pin a SHA-256; it is checked whenever present and is **required** for an `http://` URL, because a list fetched over plain HTTP can be rewritten by anyone on the path. Content that fails its digest is refused and counted — `cgdns_feed_hash_mismatches_total` above zero means a feed was tampered with, or its publisher changed it without telling the control plane.

**Subscriber policy** - RPZ zones and plain domain lists, compiled per subscriber class with specificity-ordered matching. Per-subscriber allow and block overrides take precedence over shared class feeds, so one customer can be unblocked without editing a feed you may not own. Blocked answers carry EDE 15 so clients can distinguish policy from a genuine NXDOMAIN. A feed that fails to load leaves the previous rules serving - filtering goes stale, resolution does not.

**Learned routes** - gobgpd is a BGP speaker: it holds a learned route in its RIB and never puts it in the forwarding table. That is enough to advertise an anycast address, but it means a node cannot use a default its upstream is offering, and keeps a static one even when that next hop is gone. `cgdns-routed` closes the gap for an explicitly listed handful of prefixes - a default and the sibling's loopback, typically.

It is narrow on purpose. Prefixes are matched **exactly**, so accepting a default does not accept the routes inside it; at most `max_routes` are held, so a loose filter upstream cannot become a full table in the kernel; and it only ever deletes routes it installed. That is three filters - the router's output policy, gobgp's import policy, and the agent's own list - and only the last is not somebody else's configuration to get wrong.

Installed routes carry a metric below any static fallback, so a learned default wins while it exists and the static one takes over the instant it is withdrawn. They also carry a preferred source: a static default usually pins one, and a learned route that wins without it silently moves the node's egress address off the loopback.

It runs as its own daemon, because installing routes needs `CAP_NET_ADMIN` and the process answering internet queries should not also be able to reconfigure the network. Its unit grants that capability and nothing else - not even the `CAP_NET_BIND_SERVICE` the resolver has.

**Sizing the cache.** `cache.max_size` bounds the memory the cached data may
occupy — `"512MiB"`, `"2GiB"`, or a plain byte count — and it is the bound worth
setting. `max_entries` caps a count, and a count cannot tell you how much RAM
the process will take: an entry holding eight address records costs about two
and a half times one holding two. A carrier sizing a node for fifty thousand
subscribers needs to know the memory, not the entry count, and needs the process
to stop at that figure rather than discover it during an OOM.

Measured cost is about 400 bytes for a small RRset and roughly 1KiB for a large
one, so a gigabyte holds somewhere between one and two and a half million
entries depending on what subscribers ask for. Size the VM, decide the share the
cache may have, set `max_size` to it, and let the entry count follow. Both bounds
are enforced, whichever binds first, and `cgdns_cache_bytes` reports where it
actually sits. The estimate is checked against real heap growth by a test and
currently tracks within a few percent.

**Two limits that look like tuning and are not.** `resolver.accept_sha1` must
be on: RFC 8624 makes RSASHA1 NOT RECOMMENDED for signing but MUST for
validation, and refusing it does not protect anyone — it makes zones that still
sign with it, including many `.gov` zones, unreachable. And
`max_outbound_per_query` bounds honest work, not loops; loops are already capped
by `max_delegation_depth` and `max_cname_chain`. A CDN-fronted name crosses
several zones by CNAME and each needs its own DNSKEY and DS, so a low ceiling
SERVFAILs names people use daily. 100 is a working figure; 32 is not.

**External probing** - the node's own metrics describe what it believes, and
this daemon has twice reported itself healthy through a total failure. So
`cgdns-probe` runs somewhere else, speaks to the anycast address the way a
subscriber does, and judges only the answer that comes back. It runs three
checks because there are three ways to be broken and they need telling apart: a
signed name must return NOERROR **with AD**, a deliberately broken zone must
return SERVFAIL, and an ordinary name must resolve. A resolver failing the first
two while passing the third looks perfectly healthy on a dashboard and is not
validating anything.

It probes over UDP, TCP and DoT, exports Prometheus metrics, and runs one-shot
with a non-zero exit for use in CI or a turnup check. Deployed on a pair, each
node probes its **sibling** rather than itself; a genuinely separate vantage
point is better still, and moving it is a change to `-targets`.

Alert rules ship in `deploy/prometheus/cgdns-alerts.yml`. Where a probe rule and
a node rule disagree, believe the probe.

**Certificates** - the encrypted transports need a certificate a subscriber's
device trusts, and renewing that by hand is a scheduled outage: the failure is
silent until the day it expires, then every encrypted client stops resolving at
once. cgdns runs ACME itself, writing to the same `listen.tls` paths the
listeners read, so the two cannot drift apart. Renewal is picked up through
`GetCertificate` on the next handshake - no restart, no dropped connection.

**http-01 is the default and its port is not left open.** The listener binds when
a challenge starts and closes the moment it finishes, typically about fifteen
seconds a quarter; `cgdns_acme_challenge_seconds` records the last exposure
window. A resolver's addresses are reachable by every subscriber and, through
the covering prefix, by the internet, so a web server left running all year to
serve one file for a few seconds is attack surface bought for nothing. The
responder serves exactly one path and 404s everything else, and it closes on its
own timeout even if the CA never comes back.

**dns-01 is used instead whenever a provider is configured**, because it opens
nothing at all. It is also the only option where port 80 is unreachable, or
where the name is anycast from several POPs and the CA would validate against
whichever is nearest it rather than the one being issued for. Cloudflare is
implemented; the credential is read from a file rather than the config so it does
not travel with a config that gets copied between nodes.

A certificate no public CA vouches for is treated as needing replacement even if
it is valid for years and names the right hosts - that is exactly what an interim
self-signed placeholder looks like, and nothing else would ever replace it.

**Anycast health** - the node owns the decision on whether it belongs in the anycast set, and drives GoBGP (it just made sense.. go project.. gRPC..) over its gRPC API. `gobgpd` runs as a separate unit; cgdns never shells out to a CLI and never embeds BGP in-process, so a resolver restart does not drop the session. Checks run through the real serving path. Withdrawal is fast; re-advertisement is dampened, and the penalty decays on stable serving time rather than on recovery. SIGTERM withdraws before the
listeners stop, so a planned restart moves traffic away first.

One gobgpd trap is worth knowing, because it fails silently and in the safe-looking
direction. An import filter belongs on each neighbour, never in
`[global.apply-policy]`: a global policy with `default-import-policy = "reject-route"`
also judges the routes this node originates, so the anycast prefix never reaches
the RIB. Both the gRPC API and `gobgp global rib add` return success having done
nothing, and the node reports itself advertised while the router has no route to
it at all. Check the router, not the resolver, when confirming a node is really
in the anycast set.

**Pair link** - one mutually authenticated TLS connection between the two nodes in a POP, carrying two payloads with deliberately different guarantees. Config replication is reliable and converging: writes are acknowledged and any gap is repaired by an anti-entropy exchange when the link returns, so a change made while the sibling was down lands when it rejoins. Cache sharing is best-effort, because losing a push is a cache miss the sibling resolves for itself and that is never worth blocking a query for. There is no quorum and nothing to lose: a partitioned pair keeps resolving on both sides, and the link reconnects on its own.

**Config replication** - write to either node and both converge. Last-write-wins ordered by a Lamport counter with the node ID as tiebreak, so the two agree without depending on synchronised clocks. Deletes are tombstones held for seven days - without them, a node that was down during a delete resurrects the record on rejoin, because from its side the record simply still exists. `cgdnsctl drift` compares the store hash across the pair; that hash is the only drift detector a pair has, so it is the thing to alert on.

**Cache sharing** - push on fill to keep the sibling hot, pull on miss before going upstream, TTLs decremented in transit so a shared entry never outlives its own expiry. The pull is bounded by `peer.fetch_timeout` (150 ms by default): going upstream costs tens of milliseconds, so waiting longer than that for a sibling makes the pair link a pessimisation. A peer that is slow, gone or wrong is indistinguishable from a cache miss - the resolver just proceeds upstream, which is what it would have done without a pair at all. Entries arriving *from* the peer are never offered back, which is what stops a push loop. POP-local only, for the reason above.

**Management API** - REST, bound only to the management addresses, behind a default-deny source ACL enforced at accept, TLS mandatory unless every listener is loopback. Tokens carry read/write/admin scopes and are stored as a hash, so replicating them to the sibling - which is what lets you manage the pair from either node - never moves a secret. A node holding no token at all mints one to a root-only file; a node that already has one, including one adopted from its sibling, never does. Records are canonicalised on write, so what the API returns is what the resolver is actually enforcing.

**Managing the node you are on needs no token.** cgdnsctl talks to a unix socket
at `/run/cgdns/control.sock`, root-owned and `0600`, and a request arriving there
is already privileged — the peer's uid is checked at accept, and whoever can open
the socket can already read the config, replace the binary and stop the service.
Demanding a bearer token as well would protect nothing while leaving a standing
admin secret in a file or a shell history. `cgdnsctl status` just works.

It is a socket rather than loopback TCP precisely so that reasoning holds: a TCP
port is reachable by every local user and, given a routing mistake, from off the
box. Tokens are still what a remote operator or another node uses, and are still
how `cgdnsctl drift` reaches a sibling.

**The console is built and switched off.** `management.ui` defaults off: it was
never signed into once, and it is the only part of this daemon that accepts
credentials, holds sessions and renders HTML. That is a standing authentication
and XSS surface on a resolver, kept for a benefit nobody drew on. The code and
its tests remain, and `ui: true` brings it back for a NOC that wants one.

**Response rate limiting** - UDP only, because TCP, DoT and DoH complete a handshake and there is nothing there to spoof or reflect. It limits *responses* rather than queries, since the victim of a spoofed query never sent it and the only thing that helps them is us not sending the answer.

What makes it work against water-torture is the grouping. A flood of `random1.victim.com`, `random2.victim.com` and so on has a different QNAME every time, so a bucket keyed on the QNAME gives every query its own bucket and limits precisely nothing. Denials are grouped by the *zone* that denied them - the SOA owner - so the whole flood collapses into one bucket. Answers are unlimited by default and denials are not: a real client asks for names that exist.

Every Nth over-limit response is sent truncated instead of dropped, so a legitimate client discovers TCP and carries on, while a spoofed victim gets a small packet rather than a large one. A source seen for the first time starts with one second of allowance rather than a full window - the window is there so a client that has behaved can burst, and a source we have never seen has earned nothing.

Measured on the lab: 15,000 queries at 500/s against a 50/s denial limit collapsed to a single bucket, 1,547 answered (the configured rate), and the node stayed healthy and in the anycast set throughout. A resolver that limits itself out of the anycast set has turned an attack into an outage.

**Aggressive NSEC / NSEC3** - a signed denial does not only say "this name does not exist", it says "nothing exists between these two names". Ordinary caching throws that away and re-asks for every new name in the gap; keeping it lets one denial answer for all of them (RFC 8198). Only validated denials are reused - an unvalidated NSEC is an attacker's claim about what does not exist - and a record is only ever used inside the zone its own SOA names.

How much it helps depends on how the zone is signed, and the difference is large. NSEC gaps are contiguous in *name* space, so one cached gap often covers a whole flood of made-up names. NSEC3 gaps are contiguous in *hash* space, and hashing scatters random names uniformly, so coverage grows only as the chain is cached. Measured against 50 random names per zone:

| Zone | Signing | Answered from cache | Outbound queries |
|---|---|---|---|
| `nlnetlabs.nl` | NSEC | 49 / 50 | 6 |
| `isc.org` | NSEC3 | 49 / 50 | 6 |
| `debian.org` | NSEC3, large zone | 4 / 50 rising to 22 / 50 as the chain cached | 294 falling to 234 |
| `google.com` | unsigned | 0 / 50 | 250 |

So it is close to total against a small or NSEC-signed zone, and a gradual saving against a large NSEC3 one - never nothing, and never a correctness risk either way. NSEC3 opt-out spans are never used: they may contain unsigned delegations, so they prove only that nothing *signed* is there.

**Denial validation** - a denial is validated like an answer. An unvalidated NXDOMAIN is an assertion that a name does not exist, and taking one on trust lets anyone who can answer for a zone erase a name for as long as it stays cached. `AD` is now set on proven denials, and a denial that validates is cached as authenticated: negative caching keeps only the SOA (RFC 2308), so re-proving a cached denial would fail for want of evidence deliberately not kept.

**Prefetch** - a busy resolver spends much of its latency budget on the unlucky client whose query arrives the moment a popular entry expires; everyone behind them waits on one upstream round trip. Entries close to expiry are refreshed in the background as they are read, so a name asked for constantly is answered from cache constantly. Only names actually being asked for are refreshed, so an idle entry expires normally rather than the cache turning into a crawler. Refreshes are deduplicated per name and capped, so the thing preventing a stampede cannot cause one, and denials are never refreshed - a name that does not exist is not made more available by asking again, and a random-subdomain flood would otherwise become outbound traffic of our own.

**Serve-stale** - when an authoritative has gone away, answering slightly old data beats answering nothing (RFC 8767). Expired entries are kept for `max_stale` and used *only* after resolution has already failed, so a working authoritative is always preferred and a live entry is served by the normal path. Answers carry EDE 3 so a client can tell, and never set `AD`: the signatures are as old as the data and may have expired, so claiming the chain validated would be a claim we cannot stand behind. NXDOMAIN and NODATA are never overridden - those are answers, and replacing them would resurrect names their owner deliberately removed.

The interaction that matters: **health checks do not accept a stale answer.** Serve-stale exists to keep answering when a node cannot resolve, so a probe that accepted it would let a node cut off from the internet pass its checks forever on cached root data, holding an anycast prefix it can no longer serve while a working POP sits idle. Verified on the lab by cutting both address families: subscribers kept getting answers for cached names, and the node withdrew from the anycast set with `. NS was answered from expired cache, so this node is not resolving`.

**Operator accounts** - the WebUI logs in humans, which is a different problem from an API token. A token is 256 bits of randomness, so a plain hash is enough; a password is whatever someone chose, so it gets argon2id and a TOTP second factor (RFC 6238, verified against the published test vectors). Enrolment only takes effect once the operator proves they can generate a code, so a half-finished setup cannot lock them out. Sessions are node-local and their cookie is `__Host-` prefixed, `Secure`, `HttpOnly` and `SameSite=Strict`, with a CSRF token that a cross-origin request cannot produce whatever the cookie policy does. Changing a password ends every other session for that account, and deleting one ends its sessions immediately rather than at the next expiry.

The first account is created with the bootstrap token, so there is no default password anywhere:

```sh
cgdnsctl user create josh admin      # prompts for the password, never an argument
```

**The console** - status, the resolution and defence counters, and editors for subscribers, per-subscriber overrides, classes, feeds, tokens and operators. No framework and no build step: three embedded files, so there is nothing to fetch from a CDN and nothing the content-security policy needs an exception for. It renders every value with `textContent`, which is why the policy can refuse `unsafe-inline` outright. The page itself loads without a session because it holds no data; everything behind it does not.

**The WebUI binds to localhost by default**, on HTTPS. Put a tunnel or reverse proxy in front and let it terminate the real TLS. If no certificate is configured the daemon generates a self-signed one into `node.state_dir` - nobody is meant to trust it, it exists so the browser will store a `Secure` session cookie. Enabling the UI adds no listener of its own.

**`cgdnsctl`** - operator CLI, and a plain client of that API with no privileged state of its own, so anything it does your provisioning system can do over HTTP. Because the pair replicates its control plane, pointing it at either node is equivalent - that is the "manage from any node" behaviour, achieved by replication rather than by a cluster-wide API.

## Not yet implemented

Everything on the original list is in. What remains is real work, not polish:

| | Status |
|---|---|
| Session replication | A WebUI session is node-local, so moving to the sibling means signing in again. That is a considered trade, not an oversight — see the console section. |

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

Measured with `cgdnsload`, which ramps offered load and reports what was
achieved rather than what was asked for — the difference between the two is the
answer. The daemon was pinned to 4 CPUs to match a POP node; the load generator
had the rest of the host, and forwarded to a local authoritative so the
measurement is of this daemon and not of the internet.

```
                achieved   loss     p50     p95     p99
  600 senders    143,105   0.07%   1.2ms   5.5ms  10.6ms
 1500 senders    137,395   0.32%   2.0ms   7.6ms  13.7ms
```

The knee is around 140,000 queries per second. Past it, more concurrency yields
*less* throughput and several times the loss, which is the shape to recognise:
a saturated resolver does not slow down politely, it starts dropping. CPU peaked
at 290% of the 400% available, so the limit is the packet path rather than
compute — adding cores would not move it much.

A five-minute soak at the knee answered 41,993,025 queries at 0.07% loss with
p99 steady at 9.7ms and nothing logged. Memory rose from 44MB to 277MB and
stopped there.

**Resident memory is not the cache size.** With `max_size: "64MiB"` the cache
held exactly 64MiB across 176,000 entries and 400,000 evictions — the ceiling
does what it says — while the process sat at 277MB. The difference is Go's heap
under load, and it scales with query rate rather than with the cache: the same
build serving a household holds ~1MB of cache in 64MB of RSS. Size a node as
cache plus roughly 200MB of headroom at full tilt, not as cache alone.


## Configuration

One struct, one YAML file, validated in full at startup. Notable rules the
validator enforces rather than documents:

- Listen addresses must be explicit. A wildcard bind loses the destination
  address and breaks anycast source selection.
- `listen.allow_query` is default-deny and required. An open recursive resolver
  is an amplification source.
- The management plane may not share a non-loopback address with a DNS
  listener, and may not bind anything inside `health.anycast_prefixes`. Those
  addresses are routed from the whole internet and move between nodes, which is
  no place for an admin plane. The same rule applies to `metrics.listen`.
- Management off loopback requires both TLS and a source ACL.
- **The WebUI is served by the management listener and nowhere else.** Enabling
  it adds no listener of its own, so it inherits the bind address, the TLS
  requirement and the source ACL rather than needing its own.
- `resolver.outbound_source_v4` / `_v6` pin egress per family, and may not be
  an anycast address: a query sourced from an address the sibling also holds
  invites the reply back to whichever node the return path picks. A source this
  node cannot bind is refused at startup rather than failing every query later.
  Binding it is only half the requirement: whatever sits upstream has to be able
  to route replies back to that address. Where the loopback is private and NATed,
  the router needs an explicit route to it, or it will un-NAT each reply to a
  destination it cannot reach and drop it - the queries leave, the NAT counter
  climbs, and nothing ever comes back.
- Every rate-limit knob is configurable under `rate_limit` - the three per-class
  rates, the window, the slip ratio, the prefix lengths a bucket covers, the
  table bound, and an exemption list. A rate of 0 means that class is unlimited.
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
make integration                                        # wiring tests: real binary, real config
make fuzz                                               # every fuzz target, 60s each
FUZZTIME=10m make fuzz                                  # a longer soak

./bin/cgdns -config /etc/cgdns/cgdns.yaml -check        # validate and exit
./bin/cgdns -config /etc/cgdns/cgdns.yaml
```

The wiring tests answer a different question from the unit tests: not whether a
package works, but whether it is connected. They start the real binary with a
real config, drive queries at it, and assert the observable effect that exists
only if the feature is in the serving path — that a prefetch actually reached
the upstream, that serve-stale answers once resolution fails, that the rate
limiter drops under a flood. Every unit test in this repo can pass while a
feature does nothing at all, which is how prefetch once shipped refreshing
entries by reading the entry it meant to renew.

The fuzz targets cover the paths that turn attacker-controlled bytes into
decisions: the denial proofs that decide whether a name is securely absent, the
aggressive store that synthesises answers from cached records, the feed and root
hints parsers, and the query acceptance every listener applies before the
resolver is involved. The corpus persists in the build cache, so successive runs
go deeper rather than starting over.

`make package` produces a `.deb` and an `.rpm` in `dist/` (nfpm, pure Go - no
dpkg-dev or rpmbuild needed). Binaries land in `/usr/sbin` and `/usr/bin`, the
unit in `/usr/lib/systemd/system`.

A first install does not enable or start anything. The shipped
`/etc/cgdns/cgdns.yaml` has no listen addresses and no query ACL, so the daemon
refuses to start until you have configured it - anycast would route production
traffic at a node the moment it came up, and a node nobody has configured is not
one you want taking queries. Upgrades restart a node that was already running
and never overwrite its config.

If you are migrating a node that was deployed by hand, check for a unit in
`/etc/systemd/system/cgdns.service` - it shadows the packaged one, so the node
keeps running whatever that file points at and the install looks like it took
when it did not. The postinstall warns about this. Remove it, then
`systemctl reenable cgdns`: the old enable symlink points at the file you just
deleted, and a dangling one still reports `enabled` while quietly not coming
back after a reboot.

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
| `cgdns_dnssec_unavailable_total` | a chain could not be judged because a DNSKEY or DS was unreachable — a reachability problem here, not a signing problem at the zone |
| `cgdns_recursion_case_mismatch_total` | non-zero means off-path spoofing attempts |
| `cgdns_policy_override_allowed_total` | per-subscriber whitelist hits |
| `cgdns_ratelimit_dropped_total` | rising means an attack, or a rate set below what real clients need |
| `cgdns_ratelimit_evictions_total` | sustained means `max_buckets` is too small for the client population |
| `cgdns_serve_stale_served_total` | rising means authoritatives are failing and expired data is keeping subscribers online |
| `cgdns_prefetch_dropped_total` | sustained means `max_concurrent` is too small, so popular names expire before their refresh gets a slot |
| `cgdns_nsec_synthesised_total` | rising fast means a flood of made-up names is being absorbed here rather than reaching the zone it targets |
| `cgdns_peer_outbound_up` / `_inbound_up` | 0 means the pair is split and each node is on its own |
| `cgdns_peer_cache_fetch_hits_total` | work the sibling saved this node |

The store hash is not a metric - compare it with `cgdnsctl drift`, and alert on
a disagreement that persists past a sync interval. A brief difference just means
a write has not propagated yet.

## Licence

Not yet chosen.
