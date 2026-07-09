# Step 1 — walkthrough + critical structure review

The output of [PLAN.md](../PLAN.md) **Step 1**: a module-by-module review plus the
three required artifacts (coverage map, test audit, real `nft -c` path). Written
2026-06-26. Two real bugs surfaced the moment `nft -c` actually ran — see below.

---

## TL;DR

- The generator's structure is sound (IR-in-the-middle holds; renderer is the
  source of truth for what's structured).
- **Getting `nft -c` to actually run found two invalid-nft strings the 80-green
  suite had pinned**: `quota over … gbytes` (**fixed**) and `dnat to …` in an
  `inet` table (**fix pending** — see §Bugs).
- A `nft -c` path **exists on this dev box** via `unshare -rn` (no VM needed).
- Ranked against a real multi-zone router, the top promotion is
  **concatenations**, then `reject with` and `icmp type`.

---

## Deliverable 1 — Capability / coverage map

Source of truth: [`nftgen/rules.py`](../nftgen/rules.py) (`RuleRenderer`) +
[`nftgen/ir.py`](../nftgen/ir.py).

### Generates structured (native, family-aware, validated)

| Area | Keys |
| --- | --- |
| Match | `iif`/`oif`, `saddr`/`daddr` (family-aware; named `@set` / inline anon / literal), `ct`, `proto`, `sport`/`dport` (service→ports), `flags` (match/mask, list multiplies) |
| Statements | `limit`, `quota`, `log` (prefix/level/group), `set-mark`, `set-mss` (incl. `pmtu`→`rt mtu`), `flow-offload`, `counter` (anon + named) |
| Verdicts | `accept`/`drop`/`reject`/`masquerade`, `jump:`/`goto:`, `dnat:`/`snat:` ⚠ (see Bugs — broken in `inet`) |
| Structure | tables; base+regular chains; named sets (`ipv4_addr`/`ipv6_addr`/`inet_service`/`ifname`; `interval`/`timeout`); bare/live sets; `counters:`; `flowtables:` (devices from iface groups); inline `vmap:` (iif/oif/proto); per-table + per-rule `raw:`; includes; `site:` overlay; recursive definitions |

### Works only via `raw:` (no structured key yet)

DSCP set (deferred, DECISIONS §4.2) · **concatenations** (`daddr . dport @set`)
· `reject with <type>` · meta matches beyond mark (`pkttype`/`skuid`/`mark`
match) · ct mark/helper/label · `redirect`/`tproxy` · non-verdict **maps**
(dnat-target maps) · dynamic set ops (`add @set {…}`) · `icmp type …` matching ·
vmap on keys ≠ iif/oif/proto · rule `comment`.

### Can't express even via `raw:` (structural gaps)

`netdev`-family per-device ingress base chains (no `device:` on `Chain`) · set
tuning (`size`/`gc-interval`/per-element timeout) · the `map` object type (only
inline vmap) · named stateful objects other than counters (named quota, synproxy,
ct count).

---

## Deliverable 2 — Critical test audit

| Bucket | ~Count | Proves | Does **not** prove |
| --- | --- | --- | --- |
| Transform unit tests | ~70 | renderer emits the **exact string a human authored** | that the string is **valid nft** |
| Golden `==` tests | 3 | no drift vs committed `.nft` | validity (pure self-referential pin) |
| Presence/substring tests | ~4 | the feature fired | validity |
| `nft -c` tests | 3 | **real validity** | …they skip in-sandbox **and only cover router1/router2** (gateway excluded) |

**Conclusion:** the oracle for almost every test is a hand-written nft string. The
suite regression-protects but assumes nft-validity — and twice that assumption was
wrong (see Bugs). Goldens stay as drift-detection; the **real gate** must be
`generate(host) → nft -c` over **every** host.

### Recommendations

1. Make `nft -c` run in dev (wire the `unshare` fallback into `validate.py`), so
   the 3 skipped tests become active here, not just on a future CI box.
2. Parametrize the nft-check over **all** hosts (incl. gateway), not a subset.
3. Add a dnat-bearing golden that goes through `nft -c` (guards the §Bugs fix).

---

## Deliverable 3 — Real `nft -c` validation path (solved on this box)

`nft` 1.1.6 is already in `/nix/store` (no install). Plain `nft -c` fails here
with `cache initialization failed: Operation not permitted` because `NoNewPrivs`
is set (persists even with the harness sandbox disabled) — so
`validate.can_check()` correctly skips.

**The workaround that works:** run the check inside a user+net namespace, which
hands `nft` a private netlink it can initialize against:

```bash
NFT=$(echo /nix/store/*-nftables-*/bin/nft | tr ' ' '\n' | head -1)
unshare -rn "$NFT" -c -f <ruleset.nft>      # exit 0 = valid, prints nft errors otherwise
```

This is a faithful `-c` (it caught both real bugs). It needs no privileged host,
so the same recipe drops into a CI container. **Proposed:** teach
`validate.check()` to retry under `unshare -rn` when direct netlink is blocked.

---

## Bugs found by actually running `nft -c`

Both are the audit's thesis in action: structured output that was never run
through nft.

1. **`quota over … gbytes` — invalid unit. FIXED.** nft 1.1.6 quota accepts only
   `bytes`/`kbytes`/`mbytes`. Was pinned in `gateway.yaml`, the golden, the
   showcase assertion, *and* `test_statements.test_quota`. Fix: `gbytes`→`mbytes`
   (10 GiB = `10240 mbytes`). Verified via `nft -c`.

2. **`dnat to …` / `snat to …` in an `inet` table — invalid. FIXED.** nft
   requires a family qualifier in dual-stack tables: `dnat ip to …` /
   `dnat ip6 to …`. nftgen uses `inet` everywhere, so this was the *default* case,
   not an edge. Never caught because no example used dnat (only masquerade, which
   takes no address). The unit test `test_actions_jump_dnat` pinned the broken
   form. Fix: `RuleRenderer._verdict` now infers the family from the target
   address (`_nat_family`) and emits the qualifier — required in `inet`,
   harmlessly accepted in `ip`/`ip6`. A dnat port-forward was added to the gateway
   showcase (golden + `nft -c`). **Bigger picture (still open):** verdicts were
   family-blind while matches are family-aware; the fix is pragmatic, a consistent
   threading of family is the longer-term cleanup.

---

## Multi-zone VLAN router sketch (intent benchmark)

No real config existed to port, so we sketched a realistic multi-zone router
(zones: lan/iot/guest/dmz/mgmt), generated it with nftgen, and validated via
`nft -c`. The structured backbone — **vmap zone dispatch**, interface-group
composition (`internal: [lan,iot,guest,mgmt]`), per-zone leaf chains, composed
`internal_nets`, masquerade — all rendered and validated cleanly.

**Gaps ranked by real frequency (not theory):**

| Rank | Gap | Where it bit |
| --- | --- | --- |
| 1 | **dnat in inet** (a BUG, above) | every port-forward |
| 2 | **concatenations** (`daddr . dport @set`) | "these hosts on these ports" rules; also can't compose the set from defs |
| 3 | **`reject with <type>`** | nice boundary rejects vs silent drop |
| 4 | **`icmp type` matching** | echo-request-only + rate limit |
| 5 | dnat/nat **maps** | multi-port-forward keyed by port |

So [concatenations](concatenations.md) is confirmed as the top à-la-carte
promotion, with `reject with` / `icmp type` as cheap high-value follow-ons.
