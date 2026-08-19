# Subscriber policy

Nothing is filtered unless somebody says so. A resolver that quietly blocks
things a subscriber did not ask to have blocked is a support problem at best and
a regulatory one at worst, so the default for every client address is: no
policy, resolve everything.

Filtering is built from four pieces.

| | what it is | who chooses it |
|---|---|---|
| **Category** | what is being filtered — security, ads, tracking, gambling, adult, compliance | fixed by the build |
| **List** | one blocklist: a fetched feed or one you maintain here | the operator, from a catalog |
| **Profile** | a named bundle of lists plus what a match does | the operator |
| **Assignment** | a CIDR that gets a profile | the operator, per subscriber |

Categories exist so that nobody assembling a product tier has to know which
upstream list covers what. Swapping the list behind a category later changes
nothing that was configured.

## Building a profile

Start from what you are selling, not from what is available:

```sh
cgdnsctl policy categories                 # what can be filtered
cgdnsctl policy catalog security           # the lists behind one category, and what they cost
```

Then name the categories. Each resolves to its conservative tier, and the feed
records are created for you:

```sh
cgdnsctl policy profile set safe   --category security
cgdnsctl policy profile set family --category security --category adult
cgdnsctl policy profile set clean  --category security --category ads --category adult
```

Pick a specific tier when the default is not what you want:

```sh
cgdnsctl policy profile set strict --category security --feed hagezi-pro-plus
```

Three profiles is usually the whole product. Resist one per customer: a profile
is a tier you can explain on an invoice, and per-customer differences belong in
that subscriber's own allow and block lists.

### What a match does

`--action nxdomain` (the default) is right for almost everything. It is what a
client expects for a name that does not resolve, and with EDE 15 attached a
client that cares can tell policy from a genuine NXDOMAIN.

`--action redirect --redirect 203.0.113.10` sends clients to a page instead.
Worth it when somebody has to be *told* why — a compliance block that must
display a notice, or a captive tier. It costs you a web server that has to hold
up under everything the filter catches, and it breaks non-HTTP traffic in ways
NXDOMAIN does not, so use it where the explanation is the point.

## Assigning it

Policy is applied by CIDR, so the same command covers one address or a /48:

```sh
cgdnsctl policy assign 203.0.113.45/32     family --id "cust-10241"
cgdnsctl policy assign 2001:df4:2040::/48  family --id "cust-10241"
cgdnsctl policy assign 198.51.100.0/24     clean  --id "school-district"
```

Longest match wins, so an exception inside an assigned range is just a more
specific assignment:

```sh
cgdnsctl policy assign 198.51.100.7/32 safe --id "school-it-office"
```

To stop filtering for somebody, remove the assignment. There is no "empty
profile" — an address with no assignment resolves unfiltered, which is the same
outcome with one less thing to get wrong:

```sh
cgdnsctl policy unassign 198.51.100.7/32
```

### Answering "why is this blocked"

Support calls start here, and it reports things in the order the resolver
consults them:

```sh
cgdnsctl policy show 203.0.113.45
```

## Lists you maintain yourself

Some filtering does not come from a feed. A regulator names a site, a court
issues an order, a customer asks for their own blocklist. Those are maintained
here and replicate to the sibling like any other control record:

```sh
cgdnsctl policy list create au-compliance --mandatory
cgdnsctl policy list add au-compliance banned.example --note "s115A order 2026/114"
cgdnsctl policy list add au-compliance notice.example \
    --redirect 203.0.113.10 --note "eSafety notice 2026/115"
cgdnsctl policy list show au-compliance
```

An entry covers the name and everything beneath it. An order naming a site means
the site, not just its apex.

**`--note` is the only field that answers the question anyone will actually ask
later.** Not "is this blocked" — the list shows that — but "on whose authority".
Put the order or notice reference in it.

### Mandatory lists

`--mandatory` applies a list to every client, above every profile and above a
subscriber's own allow list. It is the one thing here that cannot be opted out
of, which is exactly what a legal instruction requires and exactly why it should
be used for nothing else. A subscriber allow-listing the name does not lift it;
an address with no assignment at all is still subject to it.

Without `--mandatory`, a list you maintain behaves like any other and has to be
named by a profile:

```sh
cgdnsctl policy list create customer-blocklist --category compliance
cgdnsctl policy profile set corporate --category security --list customer-blocklist
```

A list can both fetch and be edited. `--url` points it at an RPZ feed, and
entries added here apply on top:

```sh
cgdnsctl policy list create regulator-feed --mandatory --url https://regulator.example/rpz.txt
```

## Where the lists come from

The built-in catalog is [HaGeZi's](https://github.com/hagezi/dns-blocklists),
published as RPZ and rebuilt daily. `cgdnsctl policy catalog` lists them with
measured rule counts and memory.

Nothing is enabled by having a catalog entry — a list is fetched only once a
profile names it.

### Memory

Measured on 2026-08-19, parsed into live rules:

| list | rules | heap |
|---|---|---|
| `hagezi-light` | 85,286 | 14 MiB |
| `hagezi-multi` | 372,906 | 56 MiB |
| `hagezi-pro-plus` | 490,886 | 106 MiB |
| `hagezi-tif-mini` | ~350,000 | 52 MiB |
| `hagezi-tif-medium` | 831,186 | 113 MiB |

**A refresh holds the old and new copy at once**, so budget double a list's size
for the moment it swaps. On a 4 GB node running a 1536 MiB cache under a 2560
MiB `GOMEMLIMIT`, roughly 200 MiB of steady-state rules is comfortable and 400
MiB is not.

These lists grow. Treat the table as an order of magnitude, and watch
`cgdns_policy_rules` rather than trusting it.

### Why a refresh can be refused

A fetched list is a third party deciding what your subscribers can resolve, it
is rebuilt daily so it cannot be pinned to a hash, and it arrives over the
network. So every refresh is checked before it replaces what is live:

- **Change ratio** (`feed_max_change_ratio`, default 0.3) — a list that moves
  more than 30% in one refresh is refused. Real editing does not do that;
  publisher accidents and tampering do.
- **Minimum rules** (`feed_min_rules`, default 50) — a near-empty list is a
  successful fetch of nothing, which switches filtering off without failing.
- **Protected names** (`protected_names`) — rules naming these are stripped and
  counted, and the rest of the feed is kept. A name here protects everything
  beneath it.

A refusal leaves the previous copy serving: filtering goes stale, which is
recoverable, rather than wrong, which is not. Both outcomes are counted —
`cgdns_feed_refreshes_rejected_total` and
`cgdns_feed_protected_rules_dropped_total` — and both have alerts.

Set `protected_names` to the things that must never go dark for every subscriber
at once. Banks, government services, your own infrastructure:

```yaml
policy:
  protected_names:
    - "gov.au"
    - "auspost.com.au"
    - "athenanetworks.com.au"
```

## Metrics

| metric | what it tells you |
|---|---|
| `cgdns_policy_blocked_total` | answers refused by policy |
| `cgdns_policy_redirected_total` | answers sent to a walled garden |
| `cgdns_policy_mandatory_applied_total` | answers decided by the compliance tier |
| `cgdns_policy_override_allowed_total` | subscriber allow-list hits |
| `cgdns_feed_refreshes_rejected_total` | refreshes the guard refused |
| `cgdns_feed_protected_rules_dropped_total` | rules stripped for naming a protected domain |
| `cgdns_feed_last_success_timestamp` | how stale the lists are |

`cgdns_policy_mandatory_applied_total` is separate from the rest because "how
many queries did the mandatory filtering affect" is a question asked by auditors,
not by operations, and it should not have to be inferred from a total that
includes everything a subscriber chose.
