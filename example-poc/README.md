# example-poc — the best-practice showcase pair

A deliberately rich two-site router pair that exercises the full nftgen
surface *the way we recommend using it*. Every pattern here is the worked form
of a section in [docs/best-practices.md](../docs/best-practices.md) /
[docs/maps.md](../docs/maps.md), and the behavioral test matrix in
[docs/testing-plan.md](../docs/testing-plan.md) §2 asserts this firewall's
runtime meaning flow-by-flow.

```text
                 wan0 ── uplink 1 ┐
                 lte0 ── uplink 2 ┤ (group: uplinks)
users    lan0 ───────────────────┤
servers  svc0 ───────────────────┤  poc-gw1 (site1)     poc-gw2 (site2)
mgmt    mgmt0 ───────────────────┤  + dmz0 (DMZ)        no DMZ, dynamic uplink
iot      iot0 ───────────────────┤
transit xsite0 ── site1 ⇄ site2 ─┘
```

Build: `nftgen build example-poc --check` → `generated/poc-gw{1,2}.nft`
(committed; the test suite fails if they drift from the YAML).

## What each piece demonstrates

**Definitions (`definitions/`, `sites/`)**

- **Zones are interface groups** (`interfaces.yaml`) — rules never name raw
  devices; `uplinks` composes two one-device groups and every vmap row that
  matches it expands over both members (see the 10 authored forward pairs
  render as 15).
- **Coherent services** (`services.yaml`, best-practices §7) — one name per
  service, protos carried per port, `mgmt_services` shows service composition.
- **Two naming planes for networks** (`networks/fleet.yaml` + `sites/*.yaml`):
  `siteN_*`/`all_*` are fleet-visible compositions for shared rules;
  `local_*` is the per-site overlay contract — the *same* include text
  resolves to each site's values. site2 deliberately defines fewer names
  (no DMZ, no static NAT address): a site only declares what it has, and a
  host that references a name its site lacks fails its build loudly.
- **Single-family sets** (`networks/bogons.yaml`) — `bogons_v4`/`bogons_v6`,
  never mixed; the scrub include states both rules explicitly.

**Structure (`policies/includes/`, both hosts)**

- **Conntrack-early skeleton** (best-practices §1): established/related accept
  then invalid drop, first in every stateful chain — authored via include,
  never auto-injected.
- **Zone dispatch with verdict maps** (docs/maps.md): input fans out on
  `iif`; forward fans out on the **`[iif, oif]` concatenation** — enumerate
  the *meaningful* zone pairs and let every unlisted combination (49 possible
  with these devices) fall to the chain's drop policy. `iot` is absent from
  the input vmap on purpose: unlisted zone → policy drop, visible in the text.
- **Per-service dispatch inside a zone**: `in_servers` is a `dport` vmap to
  per-service guard chains (`svc_ssh` rate-limits + logs fleet admins;
  `svc_mon` admits only the monitors group).
- **Includes compose, recursively**: `fwd-xsite.yaml` nests
  `fwd-users-servers.yaml` — the user→server policy is written once and serves
  local traffic on both gateways *and* the inter-site path.
- **Paired flows vs cartesian** (best-practices §2): `mon_flows` is a
  concatenation set of exact `(saddr, daddr, dport)` tuples — the monitor may
  scrape both DMZ hosts, with no cartesian bleed. Contrast with the
  independent-match rules in the zone includes, where cartesian *is* the
  intent.
- **Observable scrubbing**: bogon and bad-TCP drops go through named counters
  (`nft list counters`); IoT's egress denial is logged before the drop.
- **Runtime blocklist**: a bare `ipv4_addr` set with `flags: [timeout]` —
  empty in git, fed live (`nft add element … { <ip> timeout 10m }`), entries
  age out. Referenced early in both input and forward.

**NAT (`poc-gw1` vs `poc-gw2`)**

- **Port-forward data map** (docs/maps.md): one dnat rule maps WAN ports
  80/443/2222 to inside hosts; targets are single-address groups from the
  site overlay. Unmapped ports fall through (nat chains are `policy accept`
  — the type-aware default since v0.2.0) and die in forward.
- **The dnat forward leg**: `fwd-inet-dmz.yaml` allowlists the *post-rewrite*
  daddr per published service — dnat alone does not grant passage.
- **Static snat vs masquerade**: site1 has a fixed address behind
  `local_snat_ip` (snat); site2's uplink is dynamic (masquerade). Same
  structure, per-site mechanics.

## Deliberate omissions (also best practice)

- **No output chain** — router-originated traffic is trusted here; adding a
  hookless chain nobody jumps to would be dead text. Add it when you mean it.
- **Forward-chain flowtable offload only on gw1** — gw2 has no flowtable, so
  its forward uses the plain conntrack include; the offload rule lives with
  the host that owns the flowtable.
- **The blocklist is v4-only** — a v6 twin is a second set, not a mixed one.
