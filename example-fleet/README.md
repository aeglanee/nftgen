# example-fleet — a realistic 3-site router firewall

An opinionated reference: **HQ + two branches**, each a site router running
the same firewall. It shows the primitives *composed* into a system you
would deploy; each primitive is proven on its own by the behavioral tests
(B01–B28), and this fleet by its own matrix (P01–P22, see
[docs/testing.md](../docs/testing.md)). The tiny schema tour is
[example/](../example/).

## The one idea

All three routers run **one identical policy**:
[policies/hosts/hq-r.yaml](policies/hosts/hq-r.yaml) and the two other
`*-r.yaml` files differ only in `site:`. Each site file
([sites/hq.yaml](sites/hq.yaml)) gives every `local_*` name that site's own
subnets, so the same YAML renders three different rulesets:

```text
users -> local services : web    hq-r.nft  -> ip saddr 192.168.1.0/24 ip daddr 10.0.1.0/24 …
                                  br1-r.nft -> ip saddr 192.168.2.0/24 ip daddr 10.0.2.0/24 …
```

Fleet-wide names (`all_users`, `hq_central`, `hq_monitor`) are the same at
every site.

## What nftgen sees

HA pairs, MLAG, bonds and VRRP are the platform's job (networkd,
keepalived), not the firewall's. nftgen sees each router's interfaces and
the rules between them, so an HA pair shares one policy file:

```text
             wan_a  wan_b   (two uplinks: the `wan` interface group)
                \    /
   users ----[ site router ]---- transit  (to the other sites)
 services ------/ | | \--------- nwm       (network management)
      dmz --------/ | \--------- lo
```

Zones aren't a fixed list: each is an interface with a subnet. Another zone
means more `iifname . oifname` vmap entries and more per-pair chains — no
new structure.

| Zone | hq | br1 | br2 |
| --- | --- | --- | --- |
| users | 192.168.1.0/24 | 192.168.2.0/24 | 192.168.3.0/24 |
| services | 10.0.1.0/24 | 10.0.2.0/24 | 10.0.3.0/24 |
| dmz | 10.0.11.0/24 | 10.0.12.0/24 | 10.0.13.0/24 |
| nwm | 10.90.1.0/24 | 10.90.2.0/24 | 10.90.3.0/24 |
| transit | 172.16.0.0/24 (shared) | | |

Traffic is IPv4, but the hygiene layer (icmp, bogon scrub, tcp flags) is
dual-stack: the table is `inet`, and ICMPv6 neighbour discovery must work
for a correct `inet` ruleset anyway.

## The forward chain skeleton

The order *is* the policy
([includes/common/](policies/includes/common/)):

1. **Fast path** — offload established flows to the flowtable, then accept
   them in a second rule (`flow add` and a verdict can't share a rule — see
   [best-practices.md](../docs/best-practices.md) §8c).
2. **Scrub** — `proto tcp jump tcp_scrub` drops malformed flags on **every**
   interface (a compromised inside host scans the same way);
   `iifname wan jump wan_scrub` drops bogon sources **from wan only**
   (rfc1918 is our own LANs). Both counted; each jump gates its whole block.
3. **Live blocklist** — a set updated at runtime, any interface.
4. **icmp** — RFC 4890; neighbour discovery only at hop limit 255.
5. **Dispatch** — one `iifname . oifname` vmap jumps each interface pair to
   its zone chain.
6. **Catch-all** — pairs not in the vmap hit a metered, logged drop.

Every zone chain ends the same way: a **per-source metered log naming the
chain**, then a counted drop. When a flow is blocked,
`journalctl -k | grep fwd-users-services-drop` names the chain to open.
(This tail repeats in ~12 chains, since includes take no parameters; it is
what made `meter:` a key instead of `raw:`.)

The **input** chain is the same shape: conntrack, `lo` and icmp first, then
`nwm` → router ssh/snmp, then a metered drop log.

## Sets: named only where they pay off

Named sets: the bogon lists (`bogons_v4`, `bogons_v6` — long, one family
each), the live `blocklist` and the `dynamic` `log_meter`. Address groups
and services are referenced once per rule, so they stay inline — the same
firewall either way (guardrail 8). `users-services` uses one service bundle
per protocol (`user_svc_tcp: [web, dns, postgres]`) for one inline port set
per rule.

## Scenarios worth reading

| Scenario | Rule shape |
| --- | --- |
| **common** — users → own-site services: web, dns, ntp | `daddr: local_services`, resolved per site |
| **site-local app** — users → postgres | no cross-site rule, so unreachable from other sites |
| **central** — every site's users → the HQ directory (ldaps) | `saddr: all_users` over transit |
| **metrics pull** — `hq_monitor` → every site's exporters (:9100) | `nwm → services` at HQ, transit at branches |
| **cross-site app** — `br1_app` → `hq_db` :5432 | one specific flow, nothing else crosses |
| **egress / inbound** | masquerade out `wan`; :80/:443 dnat to the site's dmz web host |

Metrics pull and cross-site only mean something composed: they run through
transit dispatch, fleet groups and site files together.

## Choices worth knowing

- **`iifname`, not `iif`.** `iif` is faster, but resolves the name at load,
  so `nft -c` fails without the real interfaces — and this fleet is
  rendered and checked in CI without them. `iifname` checks anywhere and
  survives interface flaps.
- **Overlapping bogon entries fail at load.** `255.255.255.255/32` inside
  `240.0.0.0/4` made nft reject the set ("conflicting intervals"); nftgen
  passes sets through as written, so drop the covered entry.
- **Check hygiene lists against the RFCs.** The first bogon list missed
  `192.168.0.0/16`.

## Build and check

```bash
nftgen build example-fleet            # → generated/<host>.nft per site
nftgen build example-fleet --check    # also nft -c each file
```

The `generated/` files are committed; `tests/test_fleet.py` and CI fail when
they don't match a fresh render. Edit the YAML, never the `.nft`.
