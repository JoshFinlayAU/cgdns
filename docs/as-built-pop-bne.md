# As-built — POP-BNE

What is actually deployed and running, as opposed to how it should be built. For
the model this was built *to*, see [provisioning.md](provisioning.md); this
records where the running estate sits against it, including where it differs.

**Captured 2026-08-20 from the live nodes**, not from notes. Everything below was
read off the running system. Where a value is easy to read wrongly, the command
that gives the true answer is noted with it.

Two nodes, one POP, serving live subscriber traffic.

## Nodes

| | ns1 | ns2 |
|---|---|---|
| hostname | `athena--dns1` | `athena--dns2` |
| OS | Debian 13 (trixie), kernel 6.12.94-cloud-amd64 | same |
| resources | 4 vCPU, 3975 MB RAM, **no swap** | same |
| cgdns | `0.3.1~6e752d7` | `0.3.1~6e752d7` |
| gobgpd | `4.7.0-1~bpo13+1` (trixie-backports) | same |
| service account | `cgdns` (system, nologin) | same |
| units | `cgdns` and `gobgpd`, both enabled | same |

No swap is deliberate and is why memory is bounded in three places — see
[Memory](#memory).

## Addressing

Four interfaces per node, each with one job. This is the model in
[provisioning.md](provisioning.md#1-interfaces) and the estate matches it.

| | ns1 | ns2 |
|---|---|---|
| **eth0** — to the PE, and the source of every outbound query | `160.30.37.37/31`<br>`2001:df4:2040:1::11/127` | `160.30.37.39/31`<br>`2001:df4:2040:1::13/127` |
| PE side of that /31 | `160.30.37.36`<br>`2001:df4:2040:1::10` | `160.30.37.38`<br>`2001:df4:2040:1::12` |
| **eth1** — pair link, node to node | `100.127.255.0/31` | `100.127.255.1/31` |
| **eth2** — management | `10.178.0.223/24` | `10.178.0.224/24` |
| **anycast0** — the service addresses | `160.30.37.252/32`<br>`2001:df4:2040:53::1/128` | `160.30.37.253/32`<br>`2001:df4:2040:53::2/128` |

**Each node announces its own anycast address**, rather than both announcing a
shared one. Subscribers are handed both as primary and secondary; losing a node
takes one address out of the POP and leaves the other answering locally.

The pair link is IPv4-only. It carries node-to-node traffic over a directly
connected /31 and never leaves the pair, so a second family would add
configuration without adding a path.

### Default routes

Each node holds two defaults per family: a static one, and a BGP-learned one at
metric 5 installed by `cgdns-routed` with the correct preferred source.

```
default via 160.30.37.36 dev eth0 proto bgp src 160.30.37.37 metric 5
default via 2001:df4:2040:1::10 dev eth0 proto bgp src 2001:df4:2040:1::11 metric 5
```

**The `src` is the part that matters.** Every outbound query must leave carrying
eth0's address, never anycast0's. Getting this wrong works perfectly in a
single-POP estate and breaks subtly the moment a second POP exists, so it is
verified by packet capture rather than by reading the routing table.

## BGP

iBGP to the PE, both families, one session each.

| | ns1 | ns2 |
|---|---|---|
| local AS | 135559 | 135559 |
| router-id | `160.30.37.37` | `160.30.37.39` |
| v4 peer | `160.30.37.36` (AS135559) | `160.30.37.38` (AS135559) |
| v6 peer | `2001:df4:2040:1::10` | `2001:df4:2040:1::12` |
| advertises | `160.30.37.252/32`, `2001:df4:2040:53::1/128` | `160.30.37.253/32`, `2001:df4:2040:53::2/128` |
| accepts | one default per family, nothing else | same |

Both sessions on both nodes have been established continuously for over two days
at the time of capture.

**gobgpd holds a learned route in its RIB and never installs it**, which is
enough to advertise an anycast address but leaves the node unable to use the
default its upstream is offering. `cgdns-routed` closes that gap for an
explicitly listed handful of prefixes, which is why the BGP-sourced defaults
above exist in the kernel at all.

### Two traps this estate has already hit

**`gobgpd`'s backports unit is broken.** It passes `--syslog`, which 4.7.0 does
not accept, so the daemon exits. Both nodes carry an `override.conf` replacing
`ExecStart`. cgdns will not start without gobgpd, so this presents as a cgdns
failure rather than a routing one.

**Apply-policy must be per-neighbour, not global.** A global
`default-import-policy = "reject-route"` also rejects the node's own originated
routes, and the anycast prefix is never announced — while everything on the node
reports healthy. The node's own view is not evidence; the PE's table is.

## Services

Both nodes answer on all five transports, on both families, bound to the anycast
address only.

| transport | port | notes |
|---|---|---|
| UDP | 53 | `SO_REUSEPORT`, per-address sockets |
| TCP | 53 | |
| DoT | 853 | |
| DoQ | 853 | UDP; shares the port number with DoT, not the socket |
| DoH | 443 | path `/dns-query` |

EDNS0 buffer 1232. QNAME minimisation on.

### Query ACL

Default-deny. As deployed:

```
160.30.37.0/24        2001:df4:2040::/48
163.223.212.0/24      10.0.0.0/8
100.127.255.0/31
```

An open resolver is a reflection amplifier pointed at someone else, so this list
is the difference between a subscriber service and a weapon. `100.127.255.0/31`
is the pair link, so a node can query its sibling.

### Certificates

Let's Encrypt via the built-in ACME client, HTTP-01, renewing at 720h remaining:

| node | CN | valid to |
|---|---|---|
| ns1 | `dns1.as135559.net.au` | 15 Nov 2026 |
| ns2 | `dns2.as135559.net.au` | 15 Nov 2026 |

Port 80 is bound only while a challenge is outstanding and closed the moment it
completes, so it is not a standing attack surface.

**Reading the cert files on disk will mislead you.** `/etc/cgdns/tls/resolver-cert.pem`
is a self-signed fallback with a 2028 expiry that ACME supersedes at runtime. The
certificate actually served is the one on the wire:

```sh
openssl s_client -connect 160.30.37.252:853 -servername dns1.as135559.net.au </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Health and anycast withdrawal

`internal/health` owns the single decision "should this node be in the anycast
set". The daemon never runs `vtysh` or `birdc` itself.

```yaml
interval: 5s          failure_threshold: 2      success_threshold: 3
timeout: 2s           min_hold: 30s             max_hold: 5m
stable_after: 5m      gobgp_target: 127.0.0.1:50051
```

**Withdrawal is fast and re-advertisement is dampened**, because flapping a
prefix is worse than one dead node. Health checks do not accept a stale answer —
otherwise a node cut off from the internet would pass its own checks forever on
cached root data while holding a prefix it cannot serve.

## The pair link

One mutually authenticated TLS 1.3 connection between the nodes over eth1.

```yaml
listen: 100.127.255.0:8853     remote: 100.127.255.1:8853
fetch_timeout: 150ms           timeout: 2s        push_interval: 200ms
```

It carries control records (converging, last-write-wins with tombstones) and
cache fetches (best effort — a miss is a miss, never a stall). The 150 ms fetch
timeout is what keeps the second property true.

Loss of the pair link degrades management and cache sharing. It does not affect
resolution on either node.

## Memory

Bounded in three places because each catches a different failure, on a node with
no swap to absorb a mistake.

| | value | catches |
|---|---|---|
| `cache.max_size` | 1536 MiB | the cache outgrowing the node |
| `GOMEMLIMIT` | 2560 MiB | Go's collector letting the heap reach ~2× live data |
| `MemoryHigh` | 2800 M | reclaim and throttle before anything is killed |
| `MemoryMax` | 3200 M | the kernel killing *this* service rather than the OOM killer picking sshd |

`cache.max_entries` is also set to 1,000,000; whichever bound binds first wins.

Observed steady state is roughly 1 GB resident per node with the cache filling
and 431,400 policy rules loaded — comfortable against a 2560 MiB `GOMEMLIMIT`,
with headroom for another category.

## Subscriber policy

**Enabled on both nodes, applied to exactly one address.**

| | |
|---|---|
| assignment | `160.30.37.11/32` → profile `home` (subscriber `josh-home`) |
| profile `home` | `hagezi-light` (ads) + `hagezi-tif-mini` (security), action NXDOMAIN |
| rules in force | 431,400 |
| every other address | no assignment — resolves unfiltered |

Feeds refresh every 12h with the guard at its defaults (0.3 change ratio, 50
minimum rules) and `protected_names` covering `gov.au`, `auspost.com.au`,
`as135559.net.au`, `athenanetworks.com.au`, `kinetix.net.au`. No refresh has been
rejected and no protected rule dropped.

There is no mandatory compliance list deployed. The tier exists and is tested;
nothing has required it.

**The `policy:` block is a local edit, not shipped by the package.** The packaged
config deliberately omits it, so an upgrade will not add filtering to a node
nobody asked to filter — and equally will not restore it if the file is replaced.
It is `config|noreplace`, so upgrades leave it alone. See
[policy.md](policy.md#turning-it-on).

## Management plane

| | |
|---|---|
| API | `10.178.0.223:8443` / `10.178.0.224:8443`, TLS, source ACL |
| metrics | `10.178.0.223:9153` / `10.178.0.224:9153`, path `/metrics` |
| local socket | `/run/cgdns/control.sock`, mode 0600 |
| WebUI | off |

**Both bind eth2 only.** The daemon refuses to start if a management listener
shares a non-loopback address with a DNS listener.

`cgdnsctl` on the node needs no token: it uses the local socket, and the peer
credential check accepts root or the daemon's own uid. `drift` is the exception —
it reaches the *sibling* over the network, so it needs a real token. Comparing
`cgdnsctl status` store hashes over each node's own socket is the token-free
equivalent.

The bootstrap token was read once and deleted, per the documented flow. Minting a
new one requires `cgdnsctl token create` over the local socket.

## How this estate is verified

Never at the reporting end. Every check that has ever mattered here was made
somewhere other than the daemon describing itself.

```sh
# from outside, against the anycast addresses, as a subscriber reaches them
cgdns-probe -targets "ns1=160.30.37.252,ns2=160.30.37.253" -v

# the pair agrees
cgdnsctl status | grep "store hash"        # on each node; the hashes must match

# the engine is constructed, and what is in force
cgdnsctl status | grep -i policy

# filtering, from an assigned client address
dig @160.30.37.252 <a name the profile blocks>   # NXDOMAIN + EDE 15
dig @160.30.37.252 example.com                   # NOERROR
```

`cgdns-probe` runs three checks per target and they fail independently: a signed
name must return NOERROR **with AD**, a deliberately broken name must SERVFAIL,
and an ordinary name must resolve. A resolver failing the first two and passing
the third looks healthy on any availability dashboard and is not validating at
all.

## Upgrade procedure, as practised

Both upgrades to date followed the same sequence, and it is the one to keep:

1. Build the `.deb` from a tagged commit on `main`.
2. Probe both nodes from outside; confirm both healthy before starting.
3. `dpkg -i` on **ns1** only. The postinstall restarts cgdns if it was running.
4. Probe ns1. Confirm it is healthy, advertised, and answering.
5. **Wait for ns1's cache to warm** before touching ns2 — a restarted node
   answers correctly but slowly, and two cold nodes at once is a POP-wide
   latency event.
6. `dpkg -i` on **ns2**. Probe both.
7. Confirm the store hashes still agree and any policy assignments survived.

The config is `config|noreplace`, so local edits survive. Package upgrades do
replace the systemd unit, which is where `GOMEMLIMIT` and the memory caps live —
worth knowing if those are ever tuned by hand rather than in the packaged unit.

## Where the estate differs from the model

- **One POP.** [provisioning.md](provisioning.md) describes a model that assumes
  several; inter-POP behaviour here is designed and untested.
- **One PE**, so each node peers with the same router rather than the pair of
  PEs the model prefers. A second is planned.
- **eth1 is IPv4-only.** The model allows a v6 /127 on the pair link; there is no
  reason to add one for a directly connected link that never leaves the pair.
- **Filtering has one subscriber behind it**, so the false-positive rate of a
  curated list against real traffic is not yet a measurement.
