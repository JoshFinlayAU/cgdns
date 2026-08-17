# Provisioning a POP pair

How to bring up two resolver nodes and their BGP sessions from nothing. Every
config below is what the lab pair actually runs.

## The address plan comes first

Four roles per node, and keeping them apart is what makes the rest work.

| Role | Example (ns1) | Announced? | Purpose |
|---|---|---|---|
| BGP VLAN | `10.255.255.1/29`, `fd51:13:1::1/64` | no, connected | carries the eBGP sessions to the router |
| `loopback0` | `10.255.0.1/32`, `fd51:13::1/128` | see below | the node's identity — outbound queries are sourced here |
| `anycast0` | `10.255.0.53/32`, `fd51:13:53::53/128` | yes, health-gated | the service address subscribers query |
| management | `10.51.13.146` | no | operator API, metrics, SSH |

The two dummy interfaces exist for different reasons and must not be merged.

`anycast0` is the service address. It is identical in role across every POP —
though **each node owns a distinct one** (ns1 `.53`, ns2 `.54`), so BGP can
steer a subscriber to the nearer node rather than to a coin flip. It is
announced only while the node is healthy, and withdrawn the moment it is not.

`loopback0` is unique per node and is never anycast. Outbound queries source
from it, and that is the whole point: a query sourced from an anycast address
invites the reply back to whichever node the return path happens to pick, which
is not necessarily the one that asked.

The eBGP sessions run over the BGP VLAN addresses, **not** over `loopback0` —
single-hop eBGP to the directly attached router.

## 1. Interfaces

`/etc/netplan/60-cgdns.yaml` on ns1. ns2 is the same with `.2`/`::2` and
`.54`/`::54`.

```yaml
network:
  version: 2
  ethernets:
    eth0:                                    # management, kept off the service path
      routes:
      - {to: "default", via: "10.51.13.254", table: 100}
      routing-policy:
      - {from: "10.51.13.146/32", table: 100}
    eth1:                                    # pair link to the sibling
      addresses: ["100.127.255.1/30", "fd51:13:2::1/64"]
    eth2:                                    # BGP VLAN
      addresses: ["10.255.255.1/29", "fd51:13:1::1/64"]
      routes:
      - {to: "default", via: "10.255.255.3", from: "10.255.0.1", metric: 10}
  dummy-devices:
    loopback0:
      addresses: ["10.255.0.1/32", "fd51:13::1/128"]
    anycast0:
      addresses: ["10.255.0.53/32", "fd51:13:53::53/128"]
```

Two details that are easy to get wrong:

- Management needs its own routing table and a policy rule, or replies to
  management traffic take the service path out and arrive from the wrong
  address.
- The static default on `eth2` carries `metric: 10` and pins `from:`. It is the
  fallback beneath the BGP-learned default, which installs at metric 5.

## 2. gobgpd on the node

One session per address family. The import filter accepts only a default and
the sibling's loopback — everything else the upstream might send is rejected
before it can reach the agent that installs routes.

```toml
[global.config]
  as = 65001
  router-id = "10.255.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.255.255.3"
    peer-as = 65000
  [neighbors.transport.config]
    local-address = "10.255.255.1"
  [neighbors.timers.config]
    hold-time = 9
    keepalive-interval = 3
  [neighbors.apply-policy.config]
    import-policy-list = ["import-upstream"]
    default-import-policy = "reject-route"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

# ... the v6 neighbour is the same shape: fd51:13:1::3, local fd51:13:1::1,
#     ipv6-unicast, same apply-policy block.

[[defined-sets.prefix-sets]]
  prefix-set-name = "upstream-v4"
  [[defined-sets.prefix-sets.prefix-list]]
    ip-prefix = "0.0.0.0/0"
  [[defined-sets.prefix-sets.prefix-list]]
    ip-prefix = "10.255.0.2/32"        # the sibling's loopback

# ... upstream-v6 likewise: "::/0" and "fd51:13::2/128"

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
nothing, and the node reports itself advertised while the router has no route
to it at all.

Nothing here originates the anycast prefix — cgdns does that over gobgpd's gRPC
API, so the advertisement follows health rather than the config file.

## 3. cgdns

```yaml
resolver:
  outbound_source_v4: "10.255.0.1"           # loopback0, never anycast0
  outbound_source_v6: "fd51:13::1"

health:
  anycast_prefixes:                          # what gets announced when healthy
    - "10.255.0.53/32"
    - "fd51:13:53::53/128"
  gobgp_target: "127.0.0.1:50051"

route_agent:                                 # installs what gobgpd learns
  gobgp_target: "127.0.0.1:50051"
  accept:                                    # matched exactly
    - "0.0.0.0/0"
    - "::/0"
    - "10.255.0.2/32"
    - "fd51:13::2/128"
  source_v4: "10.255.0.1"                    # prefsrc on the installed route
  source_v6: "fd51:13::1"
  metric: 5                                  # beats the static fallback at 10
```

`route_agent` exists because gobgpd is a BGP speaker, not a routing daemon: it
holds a learned route in its RIB and never puts it in the forwarding table.

`source_v4`/`source_v6` must match what the resolver sources from. A learned
default that wins without a matching preferred source silently moves the node's
egress address off the loopback.

## 4. The router

Sessions, one per node per family:

```
/routing bgp connection add name=ns1-v4 instance=cgdns as=65000 \
  remote.address=10.255.255.1 .as=65001 local.address=10.255.255.3 .role=ebgp \
  output.default-originate=always input.filter=cgdns-in
```

…and the same for `ns1-v6` (`fd51:13:1::1`), `ns2-v4`, `ns2-v6`.

Accept only what these nodes should ever announce, and keep it local:

```
/routing filter rule add chain=cgdns-in \
  rule="if (dst in 10.255.0.0/24 && dst-len==32) { set bgp-communities no-export; accept; }"
/routing filter rule add chain=cgdns-in \
  rule="if (dst in fd51:13::/32 && dst-len==128) { set bgp-communities no-export; accept; }"
/routing filter rule add chain=cgdns-in rule="reject;"
```

`no-export` matters: an anycast address is only meaningful inside the POP's
routing domain, and leaking it further draws traffic toward a node that may not
be the nearest one.

### The router must be able to reach the loopbacks

Whatever the node sources queries from, the upstream needs a route back to it.
In production the node announces its own loopback and this is automatic. Where
the loopbacks are private and NATed, add explicit routes:

```
/ip route add dst-address=10.255.0.1/32 gateway=10.255.255.1
/ip route add dst-address=10.255.0.2/32 gateway=10.255.255.2
/ipv6 route add dst-address=fd51:13::1/128 gateway=fd51:13:1::1
/ipv6 route add dst-address=fd51:13::2/128 gateway=fd51:13:1::2
```

Omit these and the failure is quiet and confusing: queries leave, the NAT
counter climbs, and no reply ever returns, because each one is un-NATed to a
destination the router cannot reach and dropped.

## 5. Order of operations

1. Interfaces, both nodes. Confirm each node can reach the router over the BGP
   VLAN in both families.
2. Router sessions and filter.
3. gobgpd on the nodes. Sessions should establish and each node should learn a
   default per family.
4. Return routes to the loopbacks (or loopback announcements).
5. cgdns. It advertises the anycast prefixes once its health checks pass.

## 6. Verify at the far end, not the near end

Every check that matters is made somewhere other than the daemon reporting on
itself. `cgdns_anycast_advertised` reports the node's internal health decision
and says nothing about whether a route ever left the box.

```bash
# on the router — the only place that proves the announcement landed
/ip route print where bgp
/ipv6 route print where bgp                  # expect one /32 and one /128 per node

# on the node — what it learned and installed
gobgp neighbor
ip -4 route show default proto bgp
ip -6 route show default proto bgp

# on the wire — which family and source address are really being used
tcpdump -ni eth2 'udp port 53 and not host 10.255.255.3'

# withdrawal actually works
systemctl stop cgdns                         # the router should lose exactly
                                             # this node's two prefixes
```

A packet capture is the only honest answer to "which path is it using". A `dig`
against the anycast address proves an answer came back, not which family or
source address produced it.

## Lab shortcuts, and what production does instead

| Lab | Production |
|---|---|
| ULA (`fd51:13::/48`) and RFC1918 loopbacks | publicly routable loopbacks |
| Router masquerades both families out | no NAT; loopbacks route natively |
| Static return routes to each loopback | the node announces its own loopback |
| One POP | the same anycast address announced from every POP |
