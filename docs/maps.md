# nftables maps & verdict maps

A **map** is a key → value lookup: nft takes a field, looks it up, and uses the
matched value in **one** operation instead of a ladder of rules. There are two
flavours, by *what the value is*. Every nft block below is `nft -c`-verified.

> nftgen status: **inline verdict maps are done** (Phase 6D), keyed on
> `iifname`/`oifname`/`proto`/`dport`/`sport`/`mark`/`state`/`saddr`/`daddr`, plus
> **concatenated** keys (`key: [iifname, oifname]`). **Inline dnat data
> maps** are done
> too; **named/reusable** maps (verdict + data) are the open
> "named/reusable maps" backlog item.

---

## 1. Verdict maps (vmaps) — value is a *verdict*

Key → a verdict (`jump`/`goto`/`accept`/`drop`/…). This is **dispatch**:
branch to the right chain in one lookup.

**Inline (anonymous)** — what nftgen emits today:

```nft
iifname vmap { "wan0" : jump wan_in, "lan0" : jump lan_in }
```

replaces the rule ladder:

```nft
iifname "wan0" jump wan_in
iifname "lan0" jump lan_in
```

**Named (declared once, referenced anywhere, live-updatable):**

```nft
map zone {
    type ifname : verdict
    elements = { "wan0" : jump wan_in, "lan0" : jump lan_in }
}

chain input {
    type filter hook input priority 0; policy drop;
    iifname vmap @zone
}
```

**Why:** it's the clean, fast way to send a packet to its per-zone/per-interface
chain — the standard routing/zoning pattern. Named adds **reuse** (same dispatch
in several chains) and **live update** (`nft add element @zone …`).

---

## 2. Data maps — value is *data* (an address, port, mark, …)

Key → a value that a **statement** consumes. The headline use is **dnat targets**
(multi-port-forward).

**Inline:**

```nft
dnat to tcp dport map { 80 : 10.0.0.10, 443 : 10.0.0.20 }
```

"forward incoming :80 → the web box, :443 → the other box" — **one** map lookup.

**Named:**

```nft
map portmap {
    type inet_service : ipv4_addr
    elements = { 80 : 10.0.0.10, 443 : 10.0.0.20 }
}

chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    dnat to tcp dport map @portmap
}
```

**Why:** compact multi-port-forward — one map instead of N separate `dnat` rules,
and the forward table reads as a single reviewable list. The same machinery does
`snat … map`, `meta mark set … map`, etc.

---

## 3. Concatenated keys (advanced)

A map key can itself be a **concatenation**, combining tuple-matching with a
lookup — e.g. dispatch by `(saddr, dport)`:

```nft
ip saddr . tcp dport vmap { 10.0.0.1 . 22 : jump admin_in }
```

nftgen supports this for verdict maps via a **list key** —
`key: [iifname, oifname]` →
`iifname . oifname vmap`. The `map:` becomes a list of `{match: [...], <verdict>}`
entries; each match value resolves like a normal `iif`/`oif`, so **interface
groups expand** and cartesian-product into elements:

```yaml
- vmap:
    key: [iifname, oifname]
    map:
      - match: [users, uplinks]    # users=lan0, uplinks=wan0+wwan0
        jump: fwd_users_inet        #   -> "lan0"."wan0", "lan0"."wwan0"
      - match: [users, servers]
        jump: fwd_users_servers
```

---

## How the two flavours differ

| | Verdict map (vmap) | Data map |
| --- | --- | --- |
| Value is | a **verdict** (`jump`/`drop`/…) | **data** (address/port/mark) |
| Used for | **dispatch** (branch to a chain) | feeding a **statement** (`dnat`/`snat`/`mark`) |
| Declared as | `type K : verdict` | `type K : V` |
| Referenced as | `<key> vmap @name` / `{ … }` | `… map @name` / `map { … }` |

---

## nftgen plan

- ✅ **Inline vmaps** — `vmap:` rule → verdict. Keys: `iif`/`oif` (interface
  groups expand; strict — unknown names error), `proto`, `dport`/`sport`
  (`th dport`; **services resolve** via `services.yaml`, a bundle expands to its
  ports; a numeric port/range stays literal, anything else errors), `mark`,
  `state` (`ct state`), and `saddr`/`daddr` (network groups, single-family). (done.)
- ✅ **Concat verdict maps** — `vmap: {key: [iifname, oifname], map: [{match, verdict}]}`
  → `iifname . oifname vmap { … }`; groups/services expand, and `saddr`/`daddr`
  positions are allowed (family inferred, single-family enforced). (done.)
- ✅ **Inline dnat data map** —
  `action: {dnat: {proto: tcp, map: {80: web, 443: db}}}`
  → `dnat ip to tcp dport map { … }` (multi-port-forward; address-only
  targets for now).
- ☐ **Named verdict maps** — a table-level `maps:` declaration referenced from rules
  (DRY + live-update). Low value at our scale.
- ☐ **Named data maps + port-translation** in a map (concat value `addr . port`).

## Gotcha (found while verifying)

Don't name a set/map after an **nft keyword** (`fwd`, `last`, …) — it breaks the
parse with a confusing error. nftgen should reject keyword names (TODO).
