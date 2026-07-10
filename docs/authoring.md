# Authoring guide — structure, workflow, and picking the right tool

The hub for *how to build and extend a firewall with nftgen*: the shape a
router ruleset takes, the step-by-step for adding a rule, and a decision
table for which primitive to reach for. It links the deep-dives rather
than repeating them — [best-practices.md](best-practices.md) (the
cookbook), [sets-and-performance.md](sets-and-performance.md) (set
internals + the complexity math), [maps.md](maps.md) (vmaps/data maps),
and [capabilities.md](capabilities.md) (the full YAML→nft render table).
The worked reference is [example-fleet/](../example-fleet/).

## 1. The shape of a router firewall

A router policy is a few **base chains** (hooked into the kernel) that do
as little as possible, dispatching into **regular chains** (reached by
`jump`/`goto`) that hold the specifics. Few base chains, branch early —
that keeps the per-packet path short and the policy readable.

The opinionated **forward** skeleton, top to bottom (the order *is* the
policy — full version in [best-practices.md](best-practices.md) §8d, live
in [example-fleet](../example-fleet/)):

```text
forward (base, policy drop)
  1. ct established,related  flow-offload ft      # fast path (own rule)
  2. ct established,related  accept               # …then accept
  3. ct invalid              drop
  4. iifname wan  jump wan_scrub                  # one test gates all scrub
  5. saddr @blocklist        drop                 # runtime-updatable
  6. icmp / icmpv6 policy                         # RFC 4890
  7. iifname . oifname vmap { <pair> : jump … }   # O(1) zone dispatch
  8. <catch-all metered drop-log>                 # unmatched pairs, logged
```

Each `(in, out)` interface pair jumps to its own **zone chain**
(`fwd_users_services`, …) holding that pair's allow rules and ending in an
attributed drop-log. **input** mirrors this (ct/lo/icmp early, then
management, then a drop-log); **nat** carries prerouting dnat + postrouting
masquerade/snat. Why this order: cheapest and most common first (the fast
path and established traffic), security scrub before dispatch, one lookup
to branch, everything else denied-and-logged.

## 2. How to add a rule (the workflow)

Say you need: *site users may reach an internal app on the services vlan,
tcp 8080.*

1. **Describe the flow** — source zone (users), destination zone
   (services), proto+port (tcp 8080), direction (users→services).
2. **Find the chain from the `(iif, oif)` pair.** users→services is the
   `users_if . services_if` vmap entry → chain `fwd_users_services`. The
   chain name *is* the interface pair. (If the pair has no vmap entry yet,
   add it to the dispatch vmap and create the chain — that's a new zone
   adjacency, a deliberate act.)
3. **Add the allow to that chain's include.** In
   `includes/zones/users-services.yaml`, before the drop-log tail:

   ```yaml
   - saddr: local_users
     daddr: local_services
     proto: tcp
     dport: app        # a services: entry, or a literal 8080
     action: accept
   ```

4. **When something is unexpectedly blocked in production, the firewall
   tells you where.** Every zone chain's drop-log prefix names it —
   `journalctl -k | grep fwd-users-services-drop` shows the flows that
   chain rejected (saddr, daddr, dport), so you know exactly which chain
   to open. For a live trace, arm `meta nftrace set 1` on the test source
   and watch `nft monitor trace` (see [RAW.md](../RAW.md)). This is the
   payoff of the per-chain attributed logging: **the structure and the
   logs together turn "why is this blocked" into a grep.**

The same shape scales: a cross-site flow goes in the `transit`-facing
chain; a new public service is a dnat in prerouting + an allow in
`fwd_wan_dmz`. You never hunt through a flat rule list — the pair picks
the chain.

## 3. Picking the right tool

"I want to express X" → reach for Y. Each renders the nft on the right;
follow the link for the reasoning.

| You want… | Use | YAML → nft | Why |
| --- | --- | --- | --- |
| match any of a **list of addresses/ports** | a **group** (anonymous set) | `saddr: mgmt` → `ip saddr { a, b, c }` | one O(1) set lookup, not N rules; anon = fine when used in one rule |
| the same group in **many rules**, or **updated at runtime** | a **named set** (list it under `sets:`) | `saddr: blocklist` → `ip saddr @blocklist` | one shared kernel object (anon re-instantiates per rule); runtime `add element`; shows in `nft list sets` |
| **dispatch** one key to **different chains** | a **vmap** | `vmap: {key: [iifname, oifname], map: […]}` → `iifname . oifname vmap { … : jump … }` | one lookup replaces a rule-per-branch ladder ([maps.md](maps.md)) |
| **one condition → one chain** | a **jump** (not a vmap) | `iifname: wan` + `action: {jump: wan_scrub}` | a vmap to a single target is pointless; the jump gates a whole block in one test |
| **specific src↔dst↔port tuples** (no cross-product) | a **concat set** | `sets: [{concat: [saddr, daddr, dport], tuples: […]}]` + `set:` rule | independent matches would allow the cross-combinations; the tuple set matches only the exact rows ([best-practices.md](best-practices.md) §2) |
| key → a **data value** (dnat target, mark) | a **data map** | `action: {dnat: {map: {80: web, …}}}` → `dnat to tcp dport map { … }` | one map instead of a dnat-per-port ([maps.md](maps.md)) |
| big **CIDR / range** sets, longest-prefix | an **interval set** (automatic) | a network group with CIDRs → `flags interval` | nft picks the pipapo interval structure for you; see below |
| **rate-limit per source** (log sampling, throttle) | a **`meter:`** on a dynamic set | `meter: {set, key: saddr, rate}` → `update @set { ip saddr limit rate }` | each key gets its own bucket; one noisy host can't crowd the sample |
| collapse **many services** on one flow | a **composed service group** | `svc: [web, dns]` then `dport: svc` → `dport { 80, 443, 53 }` | service groups compose; one rule per proto instead of per service |

### On sets: anonymous vs named, and pipapo

There is **no per-lookup speed difference** between an anonymous set
(`{ a, b, c }` inlined) and a named one (`@name`) — both are the same
hash-or-interval lookup. The difference is *object management*: a named set
is one shared kernel object, is runtime-updatable, and is visible in
`nft list sets`; an anonymous set is re-instantiated per rule. So **name a
set only when it's shared across rules or mutated at runtime** (the
blocklist, the meter) — otherwise the anonymous form is equal and simpler.

You never choose the *algorithm*. nftgen tags CIDR/range groups with
`flags interval`, and nft implements interval sets with **pipapo** (a
longest-prefix structure that stays fast at scale); exact-value groups use
a hash. The data picks the structure. The complexity math and how to size
sets for performance is in
[sets-and-performance.md](sets-and-performance.md).

## 4. Efficiency — when it actually matters

- **Jump-gate repeated prefixes.** N rules that all start `iifname wan …`
  cost a non-wan packet N interface tests; `iifname wan jump wan_scrub`
  costs it one. Factor a shared leading match into a jump.
- **Dispatch with a vmap, not a rule ladder.** 40 zone pairs as 40
  `iifname X oifname Y jump` rules is O(40) per packet; one
  `iifname . oifname vmap` is O(1).
- **Offload established flows.** A flowtable moves the millions of packets
  after connection setup off the slow path — your policy still governs the
  *first* packets of every connection ([best-practices.md](best-practices.md)
  §8c). Author `flow-offload:` in its own rule, never sharing the verdict.
- **Interval sets scale.** A threat-intel feed of 100k CIDRs is one pipapo
  lookup, not 100k rules — the interval set is the mechanism.
- **`iif` vs `iifname`.** The index form is a cheaper compare but fails to
  load if the interface is absent and needs a reload if recreated. Use it
  only for statically-named, always-present interfaces
  ([best-practices.md](best-practices.md) §8a).

Reach for these when the ruleset is large or the box is pushing real pps —
not reflexively. A readable ten-rule chain doesn't need optimizing.

## 5. Anti-patterns

- **`flow-offload:` + a verdict in one rule** — the kernel NFT_BREAKs
  mid-handshake and the verdict is skipped; the connection dies on policy.
  nftgen rejects this at build ([best-practices.md](best-practices.md) §8c).
- **A rule ladder where a vmap belongs** — many `iifname X … jump` rules
  instead of one dispatch vmap: slower and harder to read.
- **Unlimited drop-logging** — `log` on a drop path with no `limit:`/
  `meter:` lets a flood DoS your logger; gate it ([best-practices.md](best-practices.md)
  §8b/§8d).
- **Naming sets you never share** — extra kernel objects and noise for no
  gain; use the anonymous form.
- **`iif` on dynamic interfaces** — silently stops matching after a ppp/
  wireguard/USB-NIC recreate; use `iifname` there.

---

For the render reference (every key → its nft), see
[capabilities.md](capabilities.md); for the escape hatch when a feature
isn't structured yet, [RAW.md](../RAW.md); for the design rationale behind
the model, [DECISIONS.md](../DECISIONS.md).
