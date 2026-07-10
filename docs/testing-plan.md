# Behavioral testing plan (R1) — what we test, how, and against what

The layered gates below build on each other. Layers 1–3 exist; this doc
specifies **layer 4 — behavioral**: prove generated rulesets *behave* as
authored, not merely parse. `nft -c` demonstrably passes dead rules, empty
rulesets, and type-mismatched set references — syntax is not semantics.

| # | Layer | Proves | Where |
| --- | --- | --- | --- |
| 1 | unit + golden | YAML → exact expected text | `tests/` |
| 2 | `nft -c` | the text is a valid ruleset | `tests/test_validate.py` etc. |
| 3 | drift | committed artifacts == regeneration | CI (R2), manual today |
| 4 | **behavioral** | packets are accepted/dropped **as authored** | this plan |
| 5 | deploy | role ships/applies/rolls back safely | sessrumnir molecule (R3/R4) |

## Harness design (implementation target)

Linux network namespaces — no VM. Already proven on this box (`unshare -rn`)
and available on CI runners.

- Topology per test class: a **router** namespace holding the ruleset under
  test, with one veth per firewall zone into peer namespaces
  (`client`/`server`/`wan`/…). Static addrs from the fixture's definitions;
  default routes point at the router.
- Apply the **generated artifact verbatim** (`nft -f generated/<host>.nft`,
  the flush form) inside the router ns — testing the deploy artifact, not a
  hand-mangled copy.
- Probes: `ping -c`, `nc -z/-l` (TCP/UDP), `socat` where needed; assertions
  read back `nft list counters/sets/ruleset` for state-based checks.
- pytest, marked like the `nft -c` tests: auto-skip when namespaces are
  unavailable; a fixture builds/tears down the topology per class.
- Negative probes assert **timeout** (drop) vs **refused** (reject) vs
  **success** — three distinct outcomes, not two.

## §1 Primitive behavior matrix

Small dedicated fixture policies (one concern each) under
`tests/behavioral/fixtures/`. Each row = one test.

| ID | Behavior under test | Probe | Expected |
| --- | --- | --- | --- |
| B01 | base-chain default drop | unsolicited TCP SYN to router | timeout (not refused) |
| B02 | ct established/related return path | client→server conn through forward | handshake completes both directions |
| B03 | unsolicited inbound on same port as B02 | server→client SYN, no prior flow | timeout |
| B04 | ct invalid drop | out-of-state ACK injection | timeout, `ct state invalid` counter rises |
| B05 | input vmap `key: iifname` dispatch | same dport probed from two zones | zone A accepted, zone B dropped |
| B06 | zone absent from input vmap | probe from unlisted zone | falls to chain policy (drop) |
| B07 | concat vmap `key: [iifname, oifname]` pair dispatch | same flow via allowed pair, then reversed pair | allowed passes; reverse times out |
| B08 | group expansion in vmap match | probe via both members of a 2-device group | both hit the same verdict chain |
| B09 | named set membership (`saddr @set`) | member IP vs non-member IP | member matched, non-member falls through |
| B10 | bogon drop + named counter | spoofed rfc1918 saddr into wan veth | timeout + `counter bogon_drops` incremented |
| B11 | concat set paired-flow tuple | exact (saddr,daddr,dport) tuple, then right saddr/wrong dport | exact passes; near-miss drops (no cartesian bleed) |
| B12 | live set (`type ipv4_addr; flags timeout`) | `nft add element` a client IP at runtime, probe, wait past timeout, probe again | blocked while present, unblocked after expiry |
| B13 | dnat rewrite (single target) | wan client → router:8080 | lands on inner server; server sees original client saddr |
| B14 | dnat **map** multi-target | wan → :80 and → :2222 | :80 reaches web ns, :2222 reaches jump ns |
| B15 | dnat map fall-through | wan → unmapped port | nat accept → forward policy drops (timeout) |
| B16 | forward leg of dnat (post-rewrite daddr) | as B13/B14 with fwd-inet-dmz allowlist | only dnat'd services pass forward |
| B17 | masquerade / snat source rewrite | lan client → wan server; server logs peer | peer == router wan addr (snat: the fixed `local_snat_ip`) |
| B18 | icmp family correctness | v4 ping and v6 ping through same policy | both answered; icmpv6 ND still functional (v6 neigh resolves) |
| B19 | rate limit | ping flood N > limit | ≈limit replies, excess dropped |
| B20 | quota | stream > quota bytes over accepted port | conn stalls once quota exhausted |
| B21 | counter (unnamed + named) | pass M packets on counted rule | `nft list counters`/ruleset shows ≥ M |
| B22 | dport vmap service dispatch | ssh port vs metrics port to servers zone | each lands in its per-service chain (observed via that chain's counter) |
| B23 | flowtable smoke | long-lived flow with `flow-offload` | flow uninterrupted; `nft list flowtables` shows ft; no functional regression. **Found a real bug:** `flow-offload` + `action:` in one rule → NFT_BREAK skips the verdict → handshake dies on `policy drop`. Build now rejects it (best-practices §8c) |
| B24 | tcp-flags scrub | crafted fin+syn + null-scan segments (raw socket, no scapy) | dropped silent + `bad_tcp` rises; a normal SYN still replies |
| B25 | log statement | structural only (assert rule renders; kernel log capture in ns is not portable) | n/a |
| B26 | artifact reapply idempotence | `nft -f` the same artifact twice | second apply succeeds; ruleset identical (`nft list ruleset` stable) |

## §2 PoC firewall end-to-end (reachability truth table)

Fixture: [`example-poc/`](../example-poc/) — the best-practice showcase router
pair (see its README). The harness stands up **poc-gw1** (site1) with one veth
per zone and walks the matrix. This is the "does the whole composed policy
mean what we think" layer — every row exercises includes + site overlay +
groups end-to-end.

| ID | Flow | Expected |
| --- | --- | --- |
| P01 | users → inet: web/dns/ntp | accept |
| P02 | users → inet: anything else (e.g. 25/tcp) | drop |
| P03 | iot → inet: ntp | accept |
| P04 | iot → inet: web | drop (iot egress is ntp-only) |
| P05 | iot → users (any) | drop (pair not in vmap) |
| P06 | users → servers: web, ssh, node_exporter | accept |
| P07 | users → dmz: web, ssh | accept |
| P08 | dmz → users (any) | drop (no return pair; only ct-established) |
| P09 | wan → router input (any port) | drop (input vmap → in_wan: bogons only, then policy) |
| P10 | wan spoofed rfc1918 saddr → forward | drop + `bogon_drops` counter |
| P11 | wan → :80 / :443 | dnat → dmz web host, forward allowlisted, served |
| P12 | wan → :2222 | dnat → dmz jump host ssh |
| P13 | wan → :23 | drop (unmapped; nat falls through, forward drops) |
| P14 | mgmt → router: ssh/snmp from `local_mgmt` | accept |
| P15 | admins (either site's admin host) → router ssh | accept (fleet `admins` group) |
| P16 | users@site1 → servers@site2 via transit link | accept (`all_users`→`all_servers` shared include) |
| P17 | monitoring tuple (mon host → dmz web :9100) | accept via concat set; same host to :9101 drops |
| P18 | lan egress source seen by wan peer | == site1 `local_snat_ip` (static snat); gw2 variant: masqueraded |
| P19 | runtime blocklist add of a users IP | that client loses all reachability until timeout |
| P20 | icmp: users can ping router + inet; wan echo to router rate-limited | per icmp include |

## §3 What layers 1–3 already pin (don't re-test behaviorally)

Exact rendering (goldens), single-family enforcement, strict-surface build
errors, `nft -c` validity of every artifact, byte-identical regeneration.
Behavioral tests assert *traffic outcomes only* — never text.

## §4 sessrumnir hooks (R3/R4, for reference)

- molecule verify upgrades: `nft list ruleset` == shipped file (kernel state),
  refused-port probe, counter movement (R4).
- rollback drill: deploy, skip confirm, assert dead-man revert restored the
  previous ruleset (R3).

## Execution order

1. ~~Harness fixture (`netns` builder + apply/teardown) with B01–B03 to prove
   it.~~ **Done 2026-07-05** — `tests/behavioral/` (agent under
   `unshare -r -n`, anonymous zone namespaces via holder pids + `setns`,
   JSON-line driven from pytest; probes discriminate
   connected/refused/timeout and the suite self-validates all three).
   B01–B03 green in ~5s; skips cleanly where userns/veth/nft/ct are missing.
   **B04–B17 landed 2026-07-10** (ct invalid via raw ACK with counter; vmap
   zone/pair/group dispatch; named-set membership; bogon scrub; concat
   no-bleed; live blocklist add/block/expire; NAT: dnat single/map/
   fall-through, post-rewrite forward leg, snat — peer-echo listeners).
   Note: iproute2 7.x needs `ip link add name X type veth …` (explicit
   `name`).
2. §1 matrix, cheapest first; B24 last (needs packet crafting).
3. §2 PoC matrix as one parametrized class over the truth table.
4. Wire both into CI (R2) behind the namespace-availability mark.
