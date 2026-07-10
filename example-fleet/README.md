# example-fleet — a realistic 3-site router firewall

An opinionated reference deployment: **HQ + two branches**, each a site
router (HA pair) enforcing the same firewall. It's the "does a real,
composed policy stay manageable" showcase — the design rationale is in
[docs/reference-fleet.md](../docs/reference-fleet.md). Every primitive is
proven in isolation by the behavioral suite; this shows them *composed*.

## The one idea

All three site routers run **one identical policy**
([policies/hosts/hq-r.yaml](policies/hosts/hq-r.yaml) and the two `*-r.yaml`
copies differ only in `site:`). The site overlay
([sites/hq.yaml](sites/hq.yaml)) resolves every `local_*` name to that
site's own subnets, so the same YAML generates three different rulesets:

```text
users -> local services : web    hq-r.nft  -> ip saddr 192.168.1.0/24 ip daddr 10.0.1.0/24 …
                                  br1-r.nft -> ip saddr 192.168.2.0/24 ip daddr 10.0.2.0/24 …
```

Write once, deploy to the fleet. Fleet-wide names (`all_users`,
`hq_central`, `hq_monitor`) stay fixed across sites.

## Topology & addressing

Physical HA/MLAG/VRRP is the platform's job — nftgen sees each router's
interfaces. Per site: `users`, `services`, `dmz`, `nwm` (net-mgmt),
`transit` (inter-site), and a two-uplink `wan` group (multi-WAN).

| Zone | hq | br1 | br2 |
| --- | --- | --- | --- |
| users | 192.168.1.0/24 | 192.168.2.0/24 | 192.168.3.0/24 |
| services | 10.0.1.0/24 | 10.0.2.0/24 | 10.0.3.0/24 |
| dmz | 10.0.11.0/24 | 10.0.12.0/24 | 10.0.13.0/24 |
| nwm | 10.90.1.0/24 | 10.90.2.0/24 | 10.90.3.0/24 |
| transit | 172.16.0.0/24 (shared) | | |

Real traffic is IPv4; the hygiene layer (icmp, bogon scrub, tcp-flags) is
dual-stack because the filter table is `inet`.

## The base-chain skeleton (every forward chain)

The order *is* the policy — see
[includes/common/](policies/includes/common/):

1. **fast path** — offload established flows to the flowtable, then accept
   (two rules: `flow add` NFT_BREAKs mid-handshake, so the verdict can't
   share the rule — see best-practices §8c).
2. **wan scrub** — one `iifname wan jump wan_scrub` gates the whole scrub
   block (bogon source drop v4+v6 + invalid tcp-flag drop, counted), so
   non-wan traffic skips it in a single interface test instead of
   re-testing the interface on every scrub rule.
3. **live blocklist** — a runtime-updatable drop set, any interface.
4. **icmp** — RFC 4890 policy; NDP permitted only at hop-limit 255.
5. **dispatch** — one `iifname . oifname` vmap jumps each interface pair
   to its own zone chain.
6. **catch-all** — unmatched pairs hit a metered, attributed drop-log.

Every zone chain ends the same way: a **per-source metered log naming the
chain** (the structured `meter:` key), then a counted drop. So when a flow
is blocked, `journalctl -k | grep fwd-users-services-drop` tells you
exactly which `iifname→oifname` chain to open — the drop is
self-documenting. Multi-service allows collapse into one rule per proto
via composed service groups (`user_svc_tcp` → an anon `{ 80, 443, 53,
5432 }` port set).

## Scenarios worth reading

- **common** — users reach their own site's services (web/dns/ntp) and a
  site-local app (postgres) that no other site can touch.
- **central** — any site's users reach the HQ directory (`hq_central`,
  ldaps) over transit — one fleet-wide service.
- **metrics pull** — `hq_monitor` scrapes every site's exporters (:9100);
  at HQ that's an `nwm→services` hop, at branches it arrives over transit.
- **cross-site app** — `br1_app` → `hq_db` (:5432), a single specific
  flow, and nothing else crosses.
- **egress** — masquerade out the multi-WAN group; **inbound** :80/:443
  dnat to the site's dmz web host.

## Build & verify

```bash
nftgen build example-fleet            # -> generated/<host>.nft per site
nftgen build example-fleet --check    # generate + nft -c
```

The `generated/` artifacts are committed and drift-pinned by
`tests/test_fleet.py`; edit the YAML, never the `.nft`.
