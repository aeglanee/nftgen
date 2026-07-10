# Reference fleet — a realistic 3-site deployment

Status: **built (2026-07-10).** The project is [`example-fleet/`](../example-fleet/)
— generates, `nft -c` clean, drift-pinned by `tests/test_fleet.py` (9
tests, suite 200). This doc is the design record; the project's own
[README](../example-fleet/README.md) is the reader's tour.

**As-built decisions** (were open in the draft): 3 sites, **one identical
policy per site** specialised only by the `site:` overlay (cleaner and a
stronger overlay demo than 6 near-duplicate HA host files — the HA pair
shares the policy); icmp after ct, before dispatch; log metering via
`raw:` (a structured `meter:` key is queued — see Findings); dmz added as
a first-class zone; `example-poc/` **retired** (example-fleet took over
its showcase + P-matrix role). **Still open:** the cross-site behavioral
harness — flagged below.

## Why this exists

Three jobs, kept separate so none muddles the others:

1. **Teach the schema** — the tiny [`example/`](../example/). Unchanged.
2. **Prove every primitive** — the isolated `tests/behavioral/` B01–B26
   fixtures. This *is* the capability-coverage artifact; rare features
   (hand-tuned concat tuples, etc.) live here and in
   [capabilities.md](capabilities.md)/[RAW.md](../RAW.md), not in the
   reference.
3. **Show a realistic, opinionated, composed system** — this doc / the
   new `example-fleet/` project. Only the ~80% you'd actually deploy.

`example-poc/` is retired; its still-realistic includes (icmp, conntrack,
bogon, the zone forward pairs) are absorbed here.

## What nftgen models (and what it doesn't)

The physical topology (from the sessrumnir enterprise diagram) has MLAG
switch pairs, bonds, trunk/access ports, and VRRP VIPs. **None of that is
nftgen's** — it's networkd/keepalived (sessrumnir). nftgen sees only each
router's **interface set** and the **rules** between them. So every site
collapses to one router policy (the HA pair shares it):

```text
             wan_a  wan_b   (2 ISP uplinks — multi-WAN, an iface group)
                \    /
   users ----[ site router ]---- transit  (to the other sites)
 services ------/ | | \--------- nwm       (network management / monitoring)
      dmz --------/ | \--------- lo
                    (zones are free — add as many segments as the site has)
```

Zones are **not a fixed list** — each is just an interface with a subnet,
so a site can carry as many segmented networks as it needs (users,
services, **dmz** for public-facing hosts, nwm, storage, iot, …). The
reference uses users / services / dmz / nwm / transit; the dmz holds the
dnat targets and is isolated from users and services (only specific
allows in). More zones just mean more `iifname . oifname` vmap entries and
more per-pair chains — the skeleton scales without new structure.

## Topology

- **3 sites:** `hq` (site1), `br1` (site2), `br2` (site3).
- **HA:** two routers per site (`<site>-r1`, `<site>-r2`) running the same
  policy. **DECISION:** model both hosts (6 host files sharing one site
  include — shows the host/site-overlay split) vs one router per site (3
  files, simpler). *Recommend both* — it's cheap (identical rules) and
  demonstrates the real fleet shape.
- **Multi-WAN:** each site has two ISP uplinks in a `wan` interface group;
  egress masquerades out the group, bogon scrub inbound.
- **Transit:** a shared L3 segment all site routers sit on — carries the
  inter-site flows.
- **HQ role:** central services + monitoring collector. Branches reach HQ
  for the shared central service and are scraped by HQ monitoring.

## Addressing & interface plan

Device last-octet convention (from the diagram): `r1 = .252`, `r2 = .253`,
`server = .10`, `vip-gw = .254`.

| Zone / vlan | Interface | hq (site1) | br1 (site2) | br2 (site3) |
| --- | --- | --- | --- | --- |
| users (100) | `users` | 192.168.1.0/24 | 192.168.2.0/24 | 192.168.3.0/24 |
| services (200) | `services` | 10.0.1.0/24 | 10.0.2.0/24 | 10.0.3.0/24 |
| dmz (250) | `dmz` | 10.0.11.0/24 | 10.0.12.0/24 | 10.0.13.0/24 |
| netmgmt (900) | `nwm` | 10.90.1.0/24 | 10.90.2.0/24 | 10.90.3.0/24 |
| transit (50) | `transit` | 172.16.0.252 | 172.16.0.2xx | 172.16.0.3xx |
| wan uplinks | `wan_a`,`wan_b` | dhcp (sim) | dhcp (sim) | dhcp (sim) |
| loopback | `lo` | 172.16.127.0/24 | — | — |

Interface **groups**: `wan = [wan_a, wan_b]`. Network **groups** compose
site subnets: `all_users = [users_hq, users_br1, users_br2]`, likewise
`all_services`. Site overlays (`sites/<site>.yaml`) map `local_users` /
`local_services` to the site's own subnet.

## The opinionated base-chain skeleton (reusable include)

Every site router's **forward** chain, top to bottom — the order *is* the
policy:

1. `ct established,related flow-offload ft` — offload the fast path.
2. `ct established,related accept` — accept it (separate rule: `flow add`
   NFT_BREAKs mid-handshake, so the verdict can't share the rule — see
   [best-practices.md](best-practices.md) §8c).
3. `iifname wan` + bogon saddr → `counter bogon_drops drop`.
4. `saddr @blocklist` → `counter blocklist_drops drop` (live set, updated
   at runtime — the "bad address drop you can update").
5. icmp: icmpv6 ND accept; echo-request rate-limited accept. **DECISION:**
   place here (after ct, before dispatch) — ND must stay reliable or v6
   breaks. *Recommend as shown.*
6. `iifname . oifname vmap { <pair> : jump fwd_<a>_<b>, … }` — one lookup
   dispatches each interface pair to its zone chain.
7. **catch-all:** metered log (`fwd-unmatched-pair`) + `counter` + `drop`
   — traffic whose interface pair isn't in the vmap dies here, logged.

Every **zone chain** (`fwd_users_services`, `fwd_transit_services`, …):

- the specific allow rules for that pair (the scenario), then
- **end-of-chain drop attribution:** metered log
  (`fwd-<a>-<b>-drop`) + `counter` + `drop`, so a rejected flow is logged
  *with the exact chain that dropped it* — you know which pair to open.

**Log metering** (so one noisy source can't flood the log): a `dynamic`
set keyed on `ip saddr` with a per-key rate, e.g.
`add @log_meter { ip saddr limit rate 6/minute } log prefix "…"`.
**DECISION:** author via `raw:` now (works, `nft -c`-valid) vs promote a
structured `meter:` key first. *Recommend raw: now* — the reference is the
real usage that should drive the promotion later (guardrail 4).

The **input** chain mirrors this: ct/lo/icmp early, then `nwm` →
router ssh/snmp for management, then a metered `input-drop` log + drop.

## Sets & vmaps (author for them deliberately)

**Named sets everywhere they earn it** (guardrail 8: a definition becomes a
named set only when a table lists it under `sets:`). The composition tree:

- **Address groups**, composed bottom-up:
  - per-site `users_hq` / `users_br1` / `users_br2`,
    `services_hq` / … ;
  - fleet unions `all_users = [users_hq, users_br1, users_br2]`,
    `all_services = [services_hq, users_br1, …]`;
  - site overlays map `local_users` / `local_services` to the site's own
    subnet, so one shared include says `saddr: local_users
    daddr: local_services` and resolves per site.
  Materialise the ones a rule references as named sets (e.g. `all_users`,
  `all_services`, `blocklist`, `bogons_v4`, `bogons_v6`); leave one-shot
  groups inline.
- **Service port sets:** `web = [80/tcp, 443/tcp]`, `dns = [53/tcp,
  53/udp]`, `ntp = [123/udp]`, plus a `transit_allowed` service set for
  what may cross the transit link. So "users → local services on web" is
  `saddr @all_users daddr @local_services tcp dport @web` — three set
  lookups, no rule-per-combination.
- **Single-family rule** (guardrail 6): `bogons_v4` and `bogons_v6` are
  separate sets; a rule referencing one is family-scoped.

**vmaps where the combinations pile up.** The `iifname . oifname` dispatch
is the spine (skeleton step 6). Inside a busy zone chain with many
`saddr`/`daddr`/`dport` specifics — e.g. the services-access chain, or the
transit chain fanning per destination site — use a `dport` vmap or a
concat `[saddr, daddr, dport]`-style dispatch to a per-service subchain
instead of a long rule ladder. Be creative: the goal is few base chains,
O(1) dispatch, and a readable per-pair chain you can point a drop-log at.

## Address families

**Real traffic is IPv4 only** — every users/services/nwm/transit subnet is
v4, so the address groups and scenario rules are v4. But the **hygiene
layer is dual-stack**: the filter tables are `inet`, and icmp, bogon
scrub, and the tcp-flags scrub are defined for **both v4 and v6** (icmpv6
ND/PMTUD must work even in a v4-addressed network for a correct `inet`
ruleset, and it's the honest reference). Authoritative lists for all
three — ICMPv6 per RFC 4890, ICMPv4, IANA special-use v4 + v6 bogons, and
the invalid-tcp-flag set — are **pending research (running)** and will be
filled in here before build.

## Traffic-scenario catalog (what makes it interesting)

| Scenario | Rule shape | Realistic? |
| --- | --- | --- |
| **common** — users → *own-site* services :80/443, dns, ntp | site-scoped `daddr: local_services` via overlay; one shared include | the bread-and-butter |
| **local-only** — users → a site-local extra service | site-defined group; no cross-site rule ⇒ unreachable elsewhere | per-site apps |
| **cross-site specific** — br1 app host → hq db :5432 | one scoped `saddr → daddr : dport` allow over transit | the "specific to specific" case |
| **central** — *all* sites' users → hq shared service :636 | `saddr: all_users` → hq central host, off the services vlan | shared auth/dir |
| **metrics pull** — hq monitoring → each site's exporters :9100 | hq `nwm` → per-site `services`/`nwm` :9100 over transit | HQ collects, per-site |
| **egress** — any site → internet | masquerade out `wan`; bogon scrub inbound | every router |

The metrics-pull and cross-site rows are the ones that only *mean*
anything at the composed layer — they exercise the transit dispatch, the
fleet groups, and the site overlays together.

## Build & test phasing

1. **Generate + validate.** Author the project; `nftgen build` → 3 (or 6)
   host `.nft`; `nft -c` clean; drift-pinned like `example-poc` was. This
   alone is a high-value reference and is fully in scope.
2. **Single-site behavioral (P-matrix).** Reuse the current one-router
   harness for intra-site flows: common allow, local-only isolation,
   egress + bogon, and the end-of-chain drop logging.
3. **Real logging test (NFLOG).** One dedicated row: bind an
   `nfnetlink_log` socket in the router ns, drive a dropped flow, assert
   the metered log group actually received it — proving the troubleshoot
   story end to end (the log→webui integration is out of scope; we prove
   the *production* of logs). NFLOG socket opens in the userns (verified).
4. **Cross-site behavioral.** Needs a **multi-router harness** (three
   router namespaces linked over transit) — new machinery.
   **DECISION:** build it, or leave cross-site flows proven by `nft -c` +
   the single-site behavior only? *Recommend* staging it last, after 1–3
   land, so the reference + most tests aren't blocked on it.

## Findings from building it

- **Drop-log tails repeat.** Every zone chain ends with the same two-rule
  metered-log + drop, differing only in the log prefix. Includes can't be
  parameterised, so the pattern is copy-pasted ~12×. This is the concrete
  case for a structured **`meter:` key** (and/or a parameterised drop-log
  include) — queued in [TODO.md](../TODO.md). For now it's `raw:`, which
  is honest (guardrail 4) but verbose.
- **Interval-set overlaps error at build.** `255.255.255.255/32` inside
  `240.0.0.0/4` made `nft -c` reject the bogon set ("conflicting
  intervals"). nftgen passes the set through as-authored; the fix is to
  drop the covered entry (an `auto-merge` set flag would be a future
  convenience). Worth a note in [sets-and-performance.md](sets-and-performance.md).
- **Research gap caught in review:** the v4 bogon list initially omitted
  `192.168.0.0/16` (RFC 1918). Always cross-check generated hygiene lists.

## Still-open decisions

1. **Cross-site behavioral** needs a multi-router harness (three router
   namespaces over transit). *Rec: build the single-site P rows + the NFLOG
   log test first (they cover most of P01–P22); stage the multi-router
   harness last.* `example-poc/` retirement — **done** (2026-07-10).
