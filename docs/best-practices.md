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
      - iifname: lo               # 1. trust loopback
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
- Specific allows (SSH from `mgmt`) come last, **scoped** — never
  `tcp dport ssh accept` open to the world.

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

→ `ip saddr @lan ip daddr @dmz tcp dport @web accept` — any LAN host → any
DMZ host on 80/443.

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

Now **only** the two exact flows are allowed; A→Y is denied. This is your
"list of x,y,z machines, each with its own saddr→daddr:dport" case — it is a
concatenation, **not** independent matches.

**Structured since the concat promotion** — define the set with `concat:`
fields + `tuples:` rows (values resolve from definitions) and reference it
with a `set:` rule key:

```yaml
sets:
  - name: flows
    concat: [saddr, daddr, dport]
    proto: tcp
    tuples:
      - [10.0.1.10, 192.0.2.10, 443]     # A → X:443  only
      - [10.0.1.11, 192.0.2.11, 5432]    # B → Y:5432 only
rules:
  - set: flows
    action: accept
```

The pairing stays **author-defined** — the tool can't infer which source
pairs with which destination (that's policy, not derivable); the concat set
lets you *compose* the tuples, never guess them. Decision + options:
[concat-authoring.md](concat-authoring.md).

---

## 3. Pattern catalog (saddr/sport → daddr/dport)

| Pattern | Semantics | nftgen today |
| --- | --- | --- |
| host → host | one flow | ✅ inline literal |
| set → host, dport | any source → host | ✅ independent |
| CIDR → CIDR, dport | any-in-range → any-in-range | ✅ independent (§2a) |
| set × set × dport | cartesian (any-to-any) | ✅ independent (§2a) |
| `sport` + `dport` | source-port + dest-port match | ✅ (`proto:` + `sport:`/`dport:`, same as dport) |
| **specific (saddr→daddr:dport) flows** | **paired tuples** | ✅ `concat:`/`tuples:` set + `set:` rule (§2b) |

---

## 4. When to use what

- **Inline literal** — a one-off host/port. No set ceremony.
- **Named set + independent matches** — "this group → that group on these ports,"
  *any-to-any within the groups* is acceptable. The 90% case.
- **Concatenation** — when the cross-combinations would be *too permissive*
  and you need exact source↔destination↔port tuples. Per-flow allow-lists,
  micro-segmentation.
- **vmap** — not for membership but for **dispatch** (branch to a per-zone
  chain by interface/proto in one lookup) — see the multi-zone example.

Rule of thumb: reach for concatenation the moment you catch yourself
wanting to say "…but only *these* pairings," not "any of these to any of
those."

---

## 5. What this means for nftgen

Everything in §1–§3, **including paired flows**, is structured and
validated today — paired flows via `concat:`/`tuples:` sets and the `set:`
rule key (family-aware, definition-composing). See
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

- **One set per *shape*** (field combo) — a set's type is fixed. In practice
  that's usually just `saddr.daddr.dport`; source-port matching is rare. So
  1–2 sets, not many.
- **tcp vs udp splits at the match** (`tcp dport` / `udp dport`) — separate
  rules/sets.
- **A few specific flows?** Plain separate rules are just as fine; a concat
  set earns its keep when there are **many**.
- **Ranges/CIDRs in a concat are fine** — stored as ranges (interval/pipapo),
  not expanded into individual addresses. No memory blowup; same as a
  normal interval set.

---

## 7. Defining services — keep them coherent

A service's ports should be **one proto**, or the **same port(s) across
protos** — not a grab-bag of unrelated ports:

```yaml
https: [443/tcp]            # ok — single proto
dns:   [53/tcp, 53/udp]     # ok — same port, both protos
mixed: [53/udp, 80/tcp]     # avoid — unrelated ports under one name
```

Why: a rule/concat states one `proto:`, which selects *that proto's* ports
from the service. nftgen **errors** if the service has **zero** ports for
the chosen proto, but it won't second-guess a *partial* match — so a
grab-bag service silently gives you only the matching-proto subset. Keep
services coherent and that never surprises you.

---

## 8. Operational hygiene (verified upstream)

Practices that keep a generated router firewall healthy in operation.
Sourced — numbered links at the end of the section.

### 8a. `iifname` (name) vs `iif` (index)

nftgen renders interface matches as `iifname`/`oifname` — a per-packet
string compare on the interface *name*. nft also offers `iif`/`oif`,
matching the interface *index*: a 32-bit integer resolved from the name
once at ruleset load — "faster than iifname as it only has to compare a
32-bit unsigned integer instead of a string" [1].

The index is dynamically allocated, and the same page warns not to use
`iif` "for interfaces that are dynamically created and destroyed, eg.
ppp0" [1]: delete + recreate an interface (PPP reconnect, WireGuard
restart, USB NIC replug) and the rule silently stops matching until the
ruleset is reloaded. That failure mode is why nftgen defaults to the name
form; an opt-in index form for static-NIC, PPS-critical hosts is on the
backlog ([TODO.md](../TODO.md)). Claims that `iifname` "performs system
calls per packet" (seen in optimization writeups) are false — it is an
in-kernel string compare.

### 8b. Rate-limit your log rules

A rule's statements evaluate **left to right** [2], and `log` writes a
kernel log entry for every packet that reaches it — so a drop rule that
logs a flood *logs at flood rate*; the logger becomes the amplifier.
nftgen renders `limit:` before `log:` precisely so the limit gates the
log. The safe idiom (common practice) splits logging from the verdict:

```yaml
rules:
  - saddr: local_iot        # log a sample of the drops…
    limit: 6/minute
    log:
      prefix: "iot-egress-drop "
  - saddr: local_iot        # …drop unconditionally, count everything
    counter: true
    action: drop
```

Putting `limit:` in the *same* rule as the verdict gates the verdict too
— over-limit packets fall through the rule — which is only safe when the
chain `policy:` already drops. The two-rule split keeps the drop
unconditional and the counter accurate. For high-rate auditing, nft can
log to userspace instead of the kernel ring (`log group N` → NFLOG,
consumed by e.g. ulogd2) [2] — structured as `log: {group: N}`; only the
batching knobs (`queue-threshold` etc.) still need `raw:`
([RAW.md](../RAW.md)).

### 8c. Flowtables — what the fast path actually skips

`flowtables:` + `flow-offload:` are structured ([DESIGN.md](../DESIGN.md)).
Once a conntrack-established flow is offloaded, its packets are picked up
at the **ingress** hook and "bypass the classic forwarding path" [3]:
no per-packet routing lookup (the flowtable caches the routing decision —
output device + next hop) and no forward-chain traversal [4] [5]. L3
semantics are preserved (TTL is still decremented) [4]. Only established
flows offload — every connection's *first* packets still traverse the
forward chain, so your policy fully applies to connection setup.

**Never put a verdict in the same rule as `flow-offload:`.** When the
kernel declines to offload — the TCP connection hasn't reached
`ESTABLISHED` yet, the packet carries `fin`/`rst`, the conntrack entry
isn't confirmed — `nft_flow_offload_eval()` falls to its `out:` label and
sets `regs->verdict.code = NFT_BREAK` [6]. NFT_BREAK aborts the **rest of
the current rule** and "chain traversal continues with the next rule" [7],
so an `accept` written after `flow-offload:` **never executes**. In a
`policy: drop` forward chain the reply packet of every handshake is then
dropped and *no connection ever establishes* — while `nft -c` reports the
ruleset perfectly valid. Only traffic reveals it (this cost us a real bug;
see B23 in [testing-plan.md](testing-plan.md)).

nftgen therefore **rejects the combined form at build time**. Author it as
two rules — which is also what the wiki's own example does, deciding the
verdict from conntrack state independently of whether the offload took [3]:

```yaml
- ct: [established, related]     # offload if the kernel is willing…
  flow-offload: ft
- ct: [established, related]     # …and accept regardless
  action: accept
```

### Sources

- [1] [Matching packet metainformation — nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation)
- [2] [Logging traffic — nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Logging_traffic)
- [3] [Flowtables — nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Flowtables)
- [4] [Flowtables Part 1: a Netfilter/nftables fastpath — thermalcircle.de](https://thermalcircle.de/doku.php?id=blog%3Alinux%3Aflowtables_1_a_netfilter_nftables_fastpath)
- [5] [Netfilter's flowtable infrastructure — kernel docs](https://docs.kernel.org/networking/nf_flowtable.html)
- [6] [`nft_flow_offload.c` — `nft_flow_offload_eval()`, the `out:` label](https://elixir.bootlin.com/linux/latest/source/net/netfilter/nft_flow_offload.c)
- [7] [Ruleset debug / VM code analysis — nftables wiki (NFT_BREAK)](https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/VM_code_analysis)

### 8d. Zone dispatch: where drops happen and how to see them

The multi-zone forward layout (§6) dispatches with one `[iifname, oifname]` vmap
lookup: key found → `jump` to that zone-pair chain; key not found → the
vmap rule is a no-match and the packet falls through to the *next* rule
in the base chain. Structure the drops so every one is attributed:

- **Every zone-pair chain ends with its own tail** — the §8b split with
  the chain's name in the prefix:

  ```yaml
  - limit: 6/minute
    log:
      prefix: "fwd-user2wan-drop: "
  - counter: true
    action: drop
  ```

  `journalctl -k | grep fwd-user2wan-drop` then shows exactly the flows
  that zone pair rejected — what you need to author the missing allow
  rule — and the counter keeps the true drop count when the log is
  rate-capped.
- **After the vmap, a catch-all tail** (same two rules, no match keys —
  a rule with no matches matches everything that reaches it) with its
  own prefix, e.g. `"fwd-unmatched-pair: "`. Only traffic whose
  interface pair isn't in the vmap ever reaches it: "unknown zone pair"
  and "known pair, rule missing" land in different buckets.
- **Dispatch with `jump`, not `goto`.** With disciplined tails they
  behave identically; the difference is the mistake case (a chain that
  ends without a verdict). `jump` returns such packets to the base
  chain, where the catch-all logs them. `goto` never returns — the
  packet dies against the base chain's `policy:`, and a policy is a
  chain attribute, not a rule: **no `log` or `counter` can attach to
  it**. `policy: drop` stays as the backstop that should see zero
  traffic.
- **Per-source log sampling (meters).** A tail's `limit:` is global to
  the rule — one noisy host can crowd the sample. nft's current idiom
  for per-key limits is a `dynamic` set plus an `add`/`update`
  expression; each key (e.g. saddr) gets its own token bucket, idle
  entries expire via `timeout`:

  ```nft
  set log_meter {
      type ipv4_addr
      flags dynamic
      timeout 1m
  }
  ```

  ```yaml
  - raw: 'add @log_meter { ip saddr limit rate 6/minute } log prefix "fwd-user2wan-drop: "'
  ```

  Raw-only today; promotion queued ([TODO.md](../TODO.md)) — the rule
  key will mirror nft's `add`/`update` verbs (the standalone `meter`
  keyword is deprecated upstream).
- **Live debugging beats logs for "why":** arm `meta nftrace set 1` on
  the traffic you're testing (a `raw:` rule, temporary) and watch
  `nft monitor trace` — it prints every chain and rule the packet
  traverses and the exact rule that issued the verdict.
