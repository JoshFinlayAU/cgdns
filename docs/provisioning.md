# Provisioning a POP pair

Two resolver nodes, their addressing, and their BGP sessions, from nothing.

## The deployment model

Four interfaces per node, one job each.

| Interface | Carries | Addressing |
|---|---|---|
| `eth0` | eBGP session to the PE, **and** the source address for outbound queries | public v4 + v6, sized to the PE link — a /31 (RFC 3021) or /30, and a /127 (RFC 6164) or /64 |
| `eth1` | pair link to the sibling: config replication and cache sharing | a /31 or /30, and a /127 (RFC 6164) from public space |
| `eth2` | management: operator API, metrics, SSH | management prefix and gateway, **no default route** |
| `anycast0` | the service address subscribers query | `/32` + `/128` on a dummy device |

Worked example for one POP:

```
ns1   anycast0  160.30.37.100/32          <- announced, health-gated
      eth0      160.30.37.200/31          <- peers with PE1 at .201, and is
                                             the source of every outbound query

ns2   anycast0  160.30.37.101/32
      eth0      160.30.37.202/31          <- peers with PE2 at .203
```

The default route is learned over eth0 from the PE. Nothing else supplies one.

### Why each address exists

**`anycast0` is inbound only.** It is what subscribers resolve against, it is
announced from every POP, and each node owns a distinct one — ns1 holds `.100`
in Brisbane, Sydney and Perth alike, ns2 holds `.101`. A Brisbane subscriber
reaches Brisbane's ns1; if that node withdraws, the same address is still live
in Sydney and BGP carries them there. The prefix stays inside your own routing
domain: subscribers are internal, so a `/32` in iBGP is exactly right and never
needs to survive public-internet filtering.

**`eth0` is outbound.** Queries must never be sourced from `anycast0`. That
address exists in every POP, so a reply addressed to it follows BGP to whichever
POP is nearest *the authoritative server*, which is not necessarily the one that
asked:

```
ns1 @ POP-A  --query, src 160.30.37.100-->  root server
             <--reply, dst 160.30.37.100--  routed to POP-C, not POP-A
POP-C's ns1: never asked -> dropped.  POP-A's ns1: times out.
```

Sourcing from `eth0` makes the address unique to one node, so the reply comes
back to the node that asked. This is the one leg of the system that touches the
public internet — the resolver walks the delegation chain itself and talks to
root, TLD and authoritative servers directly, and they reply to whatever source
the query carried. So `eth0` must be covered by an aggregate your AS announces
globally, even though no subscriber ever addresses it. The `/31` itself never
leaves your network; longest-match sorts out the rest:

```
dst 160.30.37.200  -> the /31, carried from POP-A only    -> POP-A's ns1  ✓
dst 160.30.37.100  -> the /32, announced from every POP   -> nearest POP  ✓
```

### There is no loopback here, deliberately

A loopback earns its place when an address must outlive any single interface —
a node dual-homed to PE1 *and* PE2 cannot source from either link's address,
because that address dies with its link. With one uplink per node, eth0 going
down takes the node with it regardless, so a separate loopback buys nothing.

Add one the day a node gets a second uplink, and not before. The eBGP session
itself never needs it either way: single-hop eBGP peers over the interface.

### Peering is one node to one PE

Give each node its own PE where the topology allows. Two nodes peering with the
same router means that router is a single point of failure for the whole POP —
it dies, both anycast addresses withdraw together, and the second node bought
you nothing.

The segment's addressing is not a requirement. A /31, /30, a shared VLAN, or
IPv6 link-local peering all work. What matters is that the node can reach the
PE's peering address, and that it is a connected route for single-hop eBGP. A
non-adjacent PE needs `ebgp-multihop` and a route to reach it — a different
setup, not a bigger prefix.

## 1. Interfaces

```yaml
network:
  version: 2
  ethernets:
    eth0:                                    # to the PE; also the query source
      addresses: ["160.30.37.200/31", "2404:xxxx:xxxx::200/127"]
    eth1:                                    # pair link, not announced
      addresses: ["100.127.255.1/31", "2404:xxxx:xxxx:ffff::0/127"]
    eth2:                                    # management
      addresses: ["10.51.13.146/24"]
      routes:
      - {to: "default", via: "10.51.13.254", table: 100}
      routing-policy:
      - {from: "10.51.13.146/32", table: 100}
  dummy-devices:
    anycast0:
      addresses: ["160.30.37.100/32", "2404:xxxx:xxxx:53::100/128"]
```

`anycast0` is a dummy device for the same reason `systemd-resolved` binds
`127.0.0.53` to one: somewhere to bind that never goes down and never ARPs. The
similarity ends at the mechanism — `127.0.0.53` needs no coordination because
it is host-local, whereas an anycast address is announced into BGP and is what
subscriber DHCP hands out, so it is a service contract and must be chosen.

**Management must not supply a default.** Take a prefix and a gateway, and put
that gateway in its own table rather than the main one — the only default in the
main table should be the one BGP learns. Accepting a DHCP default and relying on
metrics to make it lose is a trap: it works until BGP drops, and then management
silently becomes the service path.

The policy rule solves a second, separate problem: management traffic *sourced*
from `eth2` must reply out `eth2`. Without it, SSH from off-subnet arrives on
management and leaves via the BGP default, and the asymmetry breaks the session.

The pair link is numbered from public space but never announced — it is a
directly connected link between two adjacent boxes, so it needs no reachability
beyond the pair. Numbering it publicly keeps ICMPv6 errors and traceroute
honest, and avoids the source-selection surprises ULA brings (RFC 6724). What
crosses it is mutually authenticated TLS regardless.

## 2. gobgpd on the node

One session per address family, to this node's PE.

```toml
[global.config]
  as = 65001
  router-id = "160.30.37.200"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "160.30.37.201"
    peer-as = 65000
  [neighbors.transport.config]
    local-address = "160.30.37.200"
  [neighbors.timers.config]
    hold-time = 9
    keepalive-interval = 3
  [neighbors.apply-policy.config]
    import-policy-list = ["import-upstream"]
    default-import-policy = "reject-route"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

# ... the v6 neighbour is the same shape, ipv6-unicast, same apply-policy block.

[[defined-sets.prefix-sets]]
  prefix-set-name = "upstream-v4"
  [[defined-sets.prefix-sets.prefix-list]]
    ip-prefix = "0.0.0.0/0"

# ... upstream-v6 likewise with "::/0"

[[policy-definitions]]
  name = "import-upstream"
  [[policy-definitions.statements]]
    name = "allow-v4"
    [policy-definitions.statements.conditions.match-prefix-set]
      prefix-set = "upstream-v4"
      match-set-options = "any"
    [policy-definitions.statements.actions]
      route-disposition = "accept-route"
  # ... allow-v6 likewise against upstream-v6
```

**The apply-policy belongs on each neighbour and nowhere else.** A
`[global.apply-policy]` with `default-import-policy = "reject-route"` also
judges the routes this node originates, so the anycast prefix never enters the
RIB. Both the gRPC API and `gobgp global rib add` return success having done
nothing, and the node reports itself advertised while the PE has no route to it
at all.

Nothing here originates the anycast prefix — cgdns does that over gobgpd's gRPC
API, so the advertisement follows health rather than the config file.

## 3. cgdns

```yaml
resolver:
  outbound_source_v4: "160.30.37.200"         # eth0, never anycast0
  outbound_source_v6: "2404:xxxx:xxxx::200"

health:
  anycast_prefixes:                           # announced while healthy
    - "160.30.37.100/32"
    - "2404:xxxx:xxxx:53::100/128"
  gobgp_target: "127.0.0.1:50051"

route_agent:                                  # installs what gobgpd learns
  gobgp_target: "127.0.0.1:50051"
  accept:                                     # matched exactly
    - "0.0.0.0/0"
    - "::/0"
  source_v4: "160.30.37.200"                  # prefsrc on the installed route
  source_v6: "2404:xxxx:xxxx::200"
  metric: 5
```

`route_agent` exists because gobgpd is a BGP speaker, not a routing daemon: it
holds a learned route in its RIB and never puts it in the forwarding table.

`source_v4`/`source_v6` must match what the resolver sources from, or a learned
default that wins without a matching preferred source silently moves the node's
egress address somewhere else.

## 4. The PE

A session per node per family, originating a default and accepting only the
anycast prefix:

```
/routing bgp connection add name=ns1-v4 instance=cgdns as=65000 \
  remote.address=160.30.37.200 .as=65001 local.address=160.30.37.201 .role=ebgp \
  output.default-originate=always input.filter=cgdns-in

/routing filter rule add chain=cgdns-in \
  rule="if (dst in 160.30.37.96/28 && dst-len==32) { set bgp-communities no-export; accept; }"
/routing filter rule add chain=cgdns-in rule="reject;"
```

`no-export` keeps the anycast address inside your routing domain. Leaking it
further draws traffic toward a node that may not be the nearest one.

## 5. Order of operations

1. Interfaces on both nodes. Confirm each reaches its PE in both families.
2. PE sessions and filter.
3. gobgpd. Sessions establish; each node learns a default per family.
4. cgdns. It announces the anycast prefixes once health checks pass.

## 6. Verify at the far end, not the near end

Every check that matters is made somewhere other than the daemon reporting on
itself. `cgdns_anycast_advertised` reports the node's internal health decision
and says nothing about whether a route ever left the box.

```bash
# on the PE — the only place that proves the announcement landed
/ip route print where bgp
/ipv6 route print where bgp                  # expect one /32 and one /128 per node

# on the node — what it learned and installed
gobgp neighbor
ip -4 route show default proto bgp
ip -6 route show default proto bgp

# on the wire — which family and source address are really in use
tcpdump -ni eth0 'udp port 53'

# withdrawal actually works
systemctl stop cgdns                         # the PE should lose exactly
                                             # this node's two prefixes
```

A packet capture is the only honest answer to "which path is it using". A `dig`
against the anycast address proves an answer came back, not which family or
source address produced it.

## How the lab differs

The lab pair predates this model and reaches the same behaviour by other means.
Read it as one worked example, not as the reference.

| Lab | This model |
|---|---|
| Both nodes peer with one CHR over a shared /29 | one node per PE |
| A separate `loopback0` holds the query source | `eth0` is the query source; no loopback |
| ULA and RFC1918 addressing, masqueraded out by the router | public space, no NAT |
| Static return routes on the router to each loopback | not needed — eth0 is natively routed |
| `eth3` carries v6 on its own VLAN | v6 rides eth0 alongside v4 |
| One POP | the same anycast addresses announced from every POP |

The lab's `eth3` was a workaround for that environment having no v6 on the BGP
path, not a part of the design.
