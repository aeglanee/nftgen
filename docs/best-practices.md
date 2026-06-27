# Best practices & matching patterns (cookbook)

Worked patterns for authoring nftgen policies, each shown as **YAML → generated
nft**, every example verified with `nft -c`. The big idea to internalise is in
§2: **independent matches give a cartesian product; specific flows need a
concatenation.** Getting that wrong is the classic firewall footgun.

Definitions used below:
```yaml
networks:
  web_clients: [10.0.1.10, 10.0.1.11]
  web_servers: [192.0.2.10, 192.0.2.11]
  lan:  [10.0.0.0/16]
  dmz:  [192.0.2.0/24]
  mgmt: [10.0.9.0/24]
services:
  ssh: [22/tcp]
  https: [443/tcp]
  web: [80/tcp, 443/tcp]
```

---

## 1. Base-chain hygiene (the conntrack-early skeleton)

The shape every base chain should start with. **Order matters** — it's both
correctness and performance.

```yaml
chains:
  - name: input
    hook: input
    priority: filter
    policy: drop                 # default-deny: anything not accepted is dropped
    rules:
      - iif: lo                  # 1. trust loopback
        action: accept
      - ct: [established, related]   # 2. accept replies to flows we allowed
        action: accept
      - ct: [invalid]            # 3. drop nonsense early
        action: drop
      - proto: icmp              # 4. diagnostics
        action: accept
      - proto: icmpv6
        action: accept
      - saddr: mgmt              # 5. management access, scoped to mgmt only
        proto: tcp
        dport: ssh
        action: accept
```
→
```nft
chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto icmpv6 accept
    ip saddr @mgmt tcp dport @ssh accept
}
```

**Why this order:**
- **`policy drop`** makes the chain default-deny — you list what's *allowed*.
- **`ct established,related` first** — the vast majority of packets belong to an
  already-allowed flow; accepting them up front means most traffic clears in two
  rules instead of walking the whole chain (the conntrack-early best practice).
- **`ct invalid drop`** sheds malformed/out-of-state packets before any accept logic.
- **`iif lo`** — local processes talk over loopback; never filter it.
- Specific allows (SSH from `mgmt`) come last, **scoped** — never `tcp dport ssh accept` open to the world.

> These are *easy defaults you choose*, not magic — nftgen never injects them.
> You author the conntrack-early rule yourself (DECISIONS §1.5).

---

## 2. Independent matches vs paired flows (the important one)

### 2a. Independent matches = **cartesian product**

When you put several match keys on one rule, they're **AND-ed independently**:

```yaml
sets: [web_clients, web_servers, https]
rules:
  - saddr: web_clients      # {10.0.1.10, 10.0.1.11}
    daddr: web_servers      # {192.0.2.10, 192.0.2.11}
    proto: tcp
    dport: https
    action: accept
```
→
```nft
ip saddr @web_clients ip daddr @web_servers tcp dport @https accept
```

This means **(saddr ∈ clients) AND (daddr ∈ servers) AND (dport = 443)** — i.e.
**any** client may reach **any** server on 443. With clients `{A, B}` and servers
`{X, Y}` it allows **all four** flows: A→X, A→Y, B→X, B→Y.

**Use it when** that's what you mean: "this group of sources may reach this group
of destinations on these ports." It's the common case and nftgen does it natively.
CIDR ranges work identically:

```yaml
rules:
  - saddr: lan              # 10.0.0.0/16
    daddr: dmz              # 192.0.2.0/24
    proto: tcp
    dport: web
    action: accept
```
→ `ip saddr @lan ip daddr @dmz tcp dport @web accept` — any LAN host → any DMZ host on 80/443.

### 2b. Paired flows = **concatenation**

But if you want **specific pairings** — client A may reach **only** server X (on
443), client B **only** server Y (on 5432) — independent matches are **wrong**:
they'd also allow A→Y and B→X. You need the source, destination, and port matched
as **one tuple**, which is a **concatenated set**:

```yaml
sets:
  - name: flows
    type: "ipv4_addr . ipv4_addr . inet_service"
    elements:
      - "10.0.1.10 . 192.0.2.10 . 443"      # A → X:443  only
      - "10.0.1.11 . 192.0.2.11 . 5432"     # B → Y:5432 only
chains:
  - name: forward
    hook: forward
    priority: filter
    policy: drop
    rules:
      - raw: "ip saddr . ip daddr . tcp dport @flows accept"
```
→
```nft
set flows {
    type ipv4_addr . ipv4_addr . inet_service
    elements = { 10.0.1.10 . 192.0.2.10 . 443, 10.0.1.11 . 192.0.2.11 . 5432 }
}
chain forward {
    type filter hook forward priority 0; policy drop;
    ip saddr . ip daddr . tcp dport @flows accept
}
```

Now **only** the two exact flows are allowed; A→Y is denied. This is your "list of
x,y,z machines, each with its own saddr→daddr:dport" case — it is a concatenation,
**not** independent matches.

**This is the one place nftgen isn't structured yet** — concatenation works only
via `raw:` + a hand-written bare set (above). It's the **#1 promotion**
([docs/concatenations.md](concatenations.md)): a `match: [saddr, daddr, {dport: tcp}]`
+ `set:` key that builds the tuple set *from definitions*. Note the pairing is
**author-defined** — the tool can't infer which source pairs with which
destination (that's policy, not derivable), so a concat key would let you *compose*
the tuples, not guess them.

---

## 3. Pattern catalog (saddr/sport → daddr/dport)

| Pattern | Semantics | nftgen today |
| --- | --- | --- |
| host → host | one flow | ✅ inline literal |
| set → host, dport | any source → host | ✅ independent |
| CIDR → CIDR, dport | any-in-range → any-in-range | ✅ independent (§2a) |
| set × set × dport | cartesian (any-to-any) | ✅ independent (§2a) |
| `sport` + `dport` | source-port + dest-port match | ✅ (`proto:` + `sport:`/`dport:`, same as dport) |
| **specific (saddr→daddr:dport) flows** | **paired tuples** | ⚠️ `raw:` + bare concat set (§2b) — promotion #1 |

---

## 4. When to use what

- **Inline literal** — a one-off host/port. No set ceremony.
- **Named set + independent matches** — "this group → that group on these ports,"
  *any-to-any within the groups* is acceptable. The 90% case.
- **Concatenation** — when the cross-combinations would be *too permissive* and you
  need exact source↔destination↔port tuples. Per-flow allow-lists, micro-segmentation.
- **vmap** — not for membership but for **dispatch** (branch to a per-zone chain by
  interface/proto in one lookup) — see the multi-zone example.

Rule of thumb: reach for concatenation the moment you catch yourself wanting to say
"…but only *these* pairings," not "any of these to any of those."

---

## 5. What this means for nftgen

Everything in §1–§3 except paired flows is **structured and validated today**.
Paired flows are reachable via `raw:` (verified above) but lose
validation/family-awareness/definition-composition — which is exactly why
concatenation is the top promotion on the [roadmap](../TODO.md). See
[capabilities.md](capabilities.md) for the full render reference.

---

## 6. The overall structure (the mental model)

A whole policy is three layers:

1. **Chain skeleton** — base chains, conntrack-early, default `drop`, and any
   `jump`/`vmap` dispatch (§1). The structure the rules live in.
2. **Group-to-group rules — the bulk.** Regular rules with sets:
   `ip saddr @users ip daddr @services tcp dport @web accept`. Use these whenever
   you want **all combinations** of the groups — the common case (~90%).
3. **Specific paired flows — the exceptions.** A **concatenation** set of tuples,
   for flows where only exact pairings are allowed and cross-combinations must be
   denied.

**The one question that picks layer 2 vs 3:** *do I want all combinations of the
fields, or only specific pairings?*
- all combinations → **group-to-group rule with sets** (layer 2).
- only specific pairings → **concatenation** (layer 3).

Never lump heterogeneous specific flows into one group-to-group rule — that allows
the whole cross-product (too permissive). Either give them their own rules or a
concat set.

**Practical notes on concatenations:**
- **One set per *shape*** (field combo) — a set's type is fixed. In practice that's
  usually just `saddr.daddr.dport`; source-port matching is rare. So 1–2 sets, not many.
- **tcp vs udp splits at the match** (`tcp dport` / `udp dport`) — separate rules/sets.
- **A few specific flows?** Plain separate rules are just as fine; a concat set
  earns its keep when there are **many**.
- **Ranges/CIDRs in a concat are fine** — stored as ranges (interval/pipapo), not
  expanded into individual addresses. No memory blowup; same as a normal interval set.
