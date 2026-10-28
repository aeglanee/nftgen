# Best practices & matching patterns (cookbook)

Worked patterns for authoring nftgen policies, each shown as **YAML → generated
nft**, every example verified with `nft -c`. The big idea to internalise is in
§2: **independent matches give a cartesian product; specific flows need a
concatenation.** Getting that wrong is the classic firewall footgun.

New here? Start with [authoring.md](authoring.md) — the structure, the
add-a-rule workflow, and the decision table for which primitive to use;
this doc is the detailed cookbook it links into.

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
    ip saddr @mgmt meta l4proto tcp meta l4proto . th dport @ssh accept
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
ip saddr @web_clients ip daddr @web_servers meta l4proto tcp meta l4proto . th dport @https accept
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

→

```nft
ip saddr @lan ip daddr @dmz meta l4proto tcp meta l4proto . th dport @web accept
```

— any LAN host → any DMZ host on 80/443.

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
lets you *compose* the tuples, never guess them. Why:
[DECISIONS.md](../DECISIONS.md) §2.7.

---

## 3. Pattern catalog (saddr/sport → daddr/dport)

| Pattern | Semantics | In nftgen |
| --- | --- | --- |
| host → host | one flow | inline literals |
| set → host, dport | any source → host | independent matches |
| CIDR → CIDR, dport | any-in-range → any-in-range | independent matches (§2a) |
| set × set × dport | cartesian (any-to-any) | independent matches (§2a) |
| `sport` + `dport` | source port + destination port | `proto:` + `sport:` + `dport:` |
| **specific (saddr→daddr:dport) flows** | **paired tuples** | `concat:`/`tuples:` set + `set:` rule (§2b) |

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

## 5. Anti-spoofing (reverse-path filter)

Drop a packet whose source address isn't routed back out the interface it
arrived on — a spoofed source. One rule replaces per-interface bogon lists
for your own subnets:

```yaml
- name: rpfilter
  hook: prerouting
  priority: -140          # mangle + 10: after marks set at mangle
  policy: accept          # not the filter default — drop would drop everything
  rules:
    - raw: "fib saddr . mark . iif oif missing counter name rpf_drops drop"
```

```nft
chain rpfilter {
    type filter hook prerouting priority -140; policy accept;
    fib saddr . mark . iif oif missing counter name rpf_drops drop
}
```

- **`policy: accept` is required.** nftgen defaults a `filter` chain to
  `drop`; this chain only removes spoofed packets, the filtering happens
  later.
- **`. mark`** makes the lookup use the packet's fwmark, so policy routing
  by mark (`ip rule fwmark …`) is honoured; without such rules it changes
  nothing.
- **Strict vs loose.** `. iif` demands the route back uses the same
  interface. With asymmetric routing or multi-WAN, where replies may leave
  another uplink, use loose mode — "some route back exists":
  `fib saddr . mark oif missing drop`.
- **No exceptions needed** for DHCP or neighbour discovery on current
  kernels (checked in the kernel source, 2026-10): a `0.0.0.0` source to
  broadcast or link-local multicast (DHCPDISCOVER), an ICMPv6 packet from
  `::` to link-local (duplicate address detection) and loopback all pass.
  firewalld's `icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept`
  exemption worked around a 4.16–4.17 kernel bug.
- The rule is `raw:` until it gets a key ([TODO.md](../TODO.md)).

Sources: `man nft` (FIB expressions);
[nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_routing_information);
Linux `net/ipv4/netfilter/nft_fib_ipv4.c`, `net/ipv6/netfilter/nft_fib_ipv6.c`,
`include/net/netfilter/nft_fib.h`; firewalld
[`nftables.py`](https://github.com/firewalld/firewalld/blob/main/src/firewall/core/nftables.py).
Checked with `nft -c` and behavioral test B28 (a spoofed source is dropped,
a DHCPDISCOVER passes); the IPv6 cases are checked in the kernel source only.

---

## 6. The overall structure (the mental model)

A whole policy is three layers:

1. **Chain skeleton** — base chains, conntrack-early, default `drop`, and any
   `jump`/`vmap` dispatch (§1). The structure the rules live in.
2. **Group-to-group rules — the bulk.** Regular rules with sets:
   `ip saddr @users ip daddr @services … dport @web accept`. Use these
   whenever you want **all combinations** of the groups — the common case
   (~90%).
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
- **One protocol per concat set** — a concat set's `proto:` is fixed, so
  tcp and udp flows go in separate sets.
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

Why: with `proto:` on the rule, nftgen takes only *that protocol's* ports
from the service — an error if it has none, but a grab-bag silently gives
you a subset (`proto: tcp` + `dport: mixed` → `tcp dport 80`). Without
`proto:`, every port keeps its own protocol
(`meta l4proto . th dport { udp . 53, tcp . 80 }`), which is exact. Either
way a name that means one thing reads better in a rule.

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
ruleset is reloaded. There's also a **load-order** cost: `iif "vlan100"`
resolves the name to an index *at load time*, so the ruleset **fails to
load** if the interface doesn't exist yet — which is a double-edged sword
(it catches missing/typo'd interfaces at load, but is fragile to boot
ordering). Claims that `iifname` "performs system calls per packet" (seen
in optimization writeups) are false — it is an in-kernel string compare.

**Both forms are available:** `iifname:`/`oifname:` (name, the robust
default) and `iif:`/`oif:` (index, faster). Use the index form when the
interfaces are statically named and always present — a wired router's
VLANs and physical ports — and the name form for anything dynamic or
where load ordering isn't guaranteed. They author identically
(`iif: wan` vs `iifname: wan`); only the emitted keyword differs.

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
([raw.md](raw.md)).

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
see B23 in [testing.md](testing.md)).

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
  the rule — one noisy host can crowd the sample. The `meter:` key gives
  each key (e.g. saddr) its own token bucket via a `dynamic` set, idle
  entries expiring via `timeout`. Declare the set, then meter the log:

  ```yaml
  sets:
    - name: log_meter
      type: ipv4_addr
      flags: [dynamic, timeout]
  # …in the chain tail:
  - meter:
      set: log_meter
      key: saddr
      rate: 6/minute
      timeout: 1m
    log:
      prefix: "fwd-user2wan-drop "
  ```

  renders `update @log_meter { ip saddr timeout 1m limit rate 6/minute }
  log prefix "fwd-user2wan-drop "` — one noisy source can no longer
  crowd the sample out for everyone else.
- **Live debugging beats logs for "why":** arm `meta nftrace set 1` on
  the traffic you're testing (a `raw:` rule, temporary) and watch
  `nft monitor trace` — it prints every chain and rule the packet
  traverses and the exact rule that issued the verdict.

### 8e. One-way flows through a router pair: return them with connection marks

Two routers that share a LAN (VRRP, or an ESI-LAG anycast gateway) and a
pair link have a trap for traffic to one router's own address, such as its
loopback: the client's packets may arrive at the *other* router, which
routes them over the pair link, while the owner answers the client directly
on the LAN. The forwarding router then sees the SYN and never the SYN-ACK,
so conntrack marks the client's next packets `invalid`, and a base chain
that drops `ct state invalid` (§1) kills the connection.

Fix the path, not the firewall: mark connections that arrive over the pair
link, and route their replies back the same way.

```yaml
chains:
  - name: prerouting
    hook: prerouting
    type: filter
    priority: mangle
    policy: accept
    rules:
      - iifname: peer
        ct: [new]
        set-ct-mark: "0x1" # remember: this connection came over the pair link
  - name: output
    hook: output
    type: route # a mark change re-routes the packet
    priority: mangle
    policy: accept
    rules:
      - ct-mark: "0x1"
        set-mark: ct-mark # the reply carries the mark again
```

renders

```nft
iifname "peer0" ct state new ct mark set 0x1
ct mark 0x1 meta mark set ct mark
```

and an `ip rule` sends marked packets to a table whose route points back
over the pair link (`ip rule add fwmark 0x1 lookup 100` with
`ip route add default via <partner> dev peer0 table 100`). Every router on
the path now sees both directions, conntrack stays strict everywhere, and
no rule has to accept invalid packets. `output` must be `type route`: only
a route chain re-runs the routing decision after the mark changes.
