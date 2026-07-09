# Capabilities — what nftgen can render

The authoritative reference for what the generator turns YAML into, grounded in
[`rules.py`](../nftgen/rules.py), [`ir.py`](../nftgen/ir.py), and
[`definitions.py`](../nftgen/definitions.py). Three buckets: **renders structured**
(a real key), **works only via `raw:`** (no key yet), **can't express yet**
(structural gap). The spec is [DESIGN.md](../DESIGN.md); the backlog is
[TODO.md](../TODO.md); the gap ranking comes from [step1-review.md](step1-review.md).

> Deploy-side capabilities (the `.nft` → apply pipeline) live in
> [DEPLOYMENT.md](../DEPLOYMENT.md), not here. This file is **generation only**.
>
> **Strict authoring surface (v0.2.0):** unknown keys are a `BuildError` at
> every level — policy (`tables:`/`site:`), table, chain, set entry, vmap spec,
> and rule (e.g. `dprot:` for `dport:`) — never a silently-weaker or empty
> ruleset. A policy with no `tables:` refuses to generate (the flushing deploy
> artifact would wipe the firewall). `raw:`/`vmap:` must be a rule's only key.
> Name resolution is strict too: `iif`/`oif`/flowtable devices must be defined
> interface groups (a one-off device gets a one-device group, e.g. `eth0:
> [eth0]`); a non-numeric `dport:` must be a defined service; a group that
> resolves to no elements errors at use.

---

## 1. Structure — tables, chains, sets, objects

| Construct | YAML | Renders to |
| --- | --- | --- |
| Table | `family: inet` / `name: filter` | `table inet filter { … }` |
| Base chain | `hook:`/`type:`/`priority:`/`policy:` | `type filter hook input priority 0; policy drop;` |
| Regular chain | a chain with no `hook:` | `chain name { … }` (no header; reached by jump/goto) |
| Named set (network) | `sets: [webhosts]` | `set webhosts { type ipv4_addr; flags interval; elements = { … } }` |
| Named set (service) | `sets: [web]` | `set web { type inet_service; elements = { 80, 443 } }` |
| Named set (interface) | `sets: [wan]` | `set wan { type ifname; elements = { "wan0", "wwan0" } }` |
| Bare / live set | `{name: blocklist, type: ipv4_addr, flags: [interval, timeout]}` | empty set, filled at runtime via `nft add element` |
| Concat set | `{name: f, concat: [saddr, daddr, dport], proto: tcp, tuples: [...]}` | `set f { type ipv4_addr . ipv4_addr . inet_service; elements = { a.b.c, … } }` (paired flows; rule refs it with `set: f` → `ip saddr . ip daddr . tcp dport @f`) |
| Named counter | table `counters: [bad_tcp]` | `counter bad_tcp { }` |
| Flowtable | table `flowtables: [{name: ft, devices: [wan]}]` | `flowtable ft { hook ingress priority 0; devices = { "wan0" } }` |
| Table-level raw | table `raw: ["…"]` | verbatim object declaration inside the table |

**Priorities** (`priority:` accepts a name or a number): `raw=-300`, `mangle=-150`,
`dstnat=-100`, `filter=0`, `security=50`, `srcnat=100`.

**Family rule:** a named set is single-family; mixed v4/v6 in one set is a
`BuildError` (split `_v4`/`_v6`).

---

## 2. Match keys

| Key | YAML | nft | Notes |
| --- | --- | --- | --- |
| `iif` / `oif` | `iif: wan` | `iifname @wan` / `{ "wan0", … }` / `"wan0"` | named set or interface group (strict — unknown names error); one device inlines bare |
| `saddr` / `daddr` | `saddr: webhosts` | `ip saddr @webhosts` | **family-aware**; named set, group, or IP/CIDR literal; renders once per common family |
| `ct` | `ct: [established, related]` | `ct state established,related` | authored, never auto-injected |
| `mark` | `mark: "0x1"` | `meta mark 0x1` | match an fwmark (set one with `set-mark:`) |
| `icmp-type` | `proto: icmpv6` / `icmp-type: [nd-neighbor-solicit, …]` | `icmpv6 type { … }` | family from `proto:` (icmp/icmpv6); single or list |
| `proto` (standalone) | `proto: icmp` | `meta l4proto icmp` | |
| `dport` / `sport` | `proto: tcp` / `dport: web` | `tcp dport @web` (or `{ 80, 443 }`) | needs `proto:`; service name → ports |
| `flags` | `flags: {match: [syn], mask: [syn, ack]}` | `tcp flags & (syn\|ack) == syn` | a list of clauses multiplies into several lines |

---

## 3. Statements (non-terminal)

| Key | YAML | nft |
| --- | --- | --- |
| `limit` | `limit: 4/minute` | `limit rate 4/minute` |
| `quota` | `quota: over 10240 mbytes` | `quota over 10240 mbytes` |
| `log` | `log: {prefix: "ssh ", level: info, group: 2}` | `log prefix "ssh " level info group 2` (or bare `log`; `group` = NFLOG) |
| `set-mark` | `set-mark: "0x1"` | `meta mark set 0x1` |
| `set-mss` | `set-mss: pmtu` / `set-mss: 1460` | `tcp flags syn tcp option maxseg size set rt mtu` / `… set 1460` |
| `flow-offload` | `flow-offload: ft` | `flow add @ft` |
| `counter` | `counter: true` / `counter: bad_tcp` | `counter` / `counter name bad_tcp` (named must be declared) |

A rule may be **statement-only** (no verdict) — e.g. an MSS clamp or a fwmark.

---

## 4. Verdicts / actions

| YAML | nft |
| --- | --- |
| `action: accept` / `drop` / `reject` / `masquerade` | bare verdict |
| `action: {jump: input_wan}` | `jump input_wan` |
| `action: {goto: lan_to_wan}` | `goto lan_to_wan` |
| `action: {dnat: "192.168.10.50:443"}` | `dnat ip to 192.168.10.50:443` (family from target) |
| `action: {snat: "203.0.113.7"}` | `snat ip to 203.0.113.7` |
| `action: {snat: wan_ip}` | a single-address network group resolves — per-site NAT addresses live behind one shared name (site overlay) |
| `action: {dnat: {proto: tcp, map: {80: web, 443: db}}}` | `dnat ip to tcp dport map { 80 : …, 443 : … }` (inline multi-port-forward; address-only targets) |

---

## 5. Rule-level forms

| Form | YAML | nft |
| --- | --- | --- |
| `raw:` | `raw: "udp dport 5060 ip dscp set ef"` | verbatim (the escape hatch) |
| `vmap:` (inline) | `vmap: {key: iif, map: {wan0: {jump: wan_in}}}` | `iifname vmap { … }` — keys `iif`/`oif`/`proto`/`dport`/`sport`/`mark`/`state`/`saddr`/`daddr`; groups & services resolve; `key: [iif, oif]` concatenates |
| `include:` | `- include: includes/common-input.yaml` | inlined rules/sets at build time |

---

## 6. Definitions & composition

| Feature | YAML | Behaviour |
| --- | --- | --- |
| networks | `lan: [192.168.1.0/24]` | IP/CIDR literals + composition |
| services | `dns: [53/tcp, 53/udp]` | `port/proto`; emits proto-agnostic `inet_service`; proto stated on the rule |
| interfaces | `wan: [wan0, wwan0]` | device names + composition |
| composition | `trusted: [lan, mgmt]` | names expand recursively (cycle-guarded, deduped) |
| site overlay | host `site: site1` | `definitions/` + `sites/<site>.yaml` (additive; collision = error) |
| includes | `- include: …` | shared rule/set fragments, nested-resolvable |
| named vs inline | listed in a table's `sets:` or not | named `@set` vs inline anonymous `{ … }` — author's call per table |

---

## 7. Works only via `raw:` (no structured key yet)

| Feature | `raw:` example | Promotion rank |
| --- | --- | --- |
| `reject with <type>` | `raw: "… reject with icmpx type admin-prohibited"` | **#1** |
| DSCP set | `raw: "udp dport 5060 ip dscp set ef"` | deferred (family-specific, DECISIONS §4.2) |
| meta beyond mark (`pkttype`/`skuid`), ct mark/helper/label, `redirect`/`tproxy`, dynamic set ops (`add @set`), rule `comment` | `raw: …` | unranked |

`raw:` bypasses validation, family-awareness, and definition resolution — that's
the cost, and the reason to promote a recipe once it earns a key.

---

## 8. Can't express even via `raw:` (structural gaps)

| Gap | Why |
| --- | --- |
| `netdev`-family per-device ingress chains | no `device:` attribute on `Chain` |
| set tuning (`size` / `gc-interval` / per-element timeout) | only `interval`/`timeout` flags modelled |
| the `map` object type (key→value) | only inline `vmap`; no reusable/named maps |
| named stateful objects other than counters (named quota, synproxy, ct count) | only `counter` objects modelled |

(A single *rule line* is always reachable via `raw:`; these are gaps in the
**structure** the IR can build, not in rule text.)

---

## 9. Promotion queue (ranked, from real use)

- ✅ **concatenations** · **`icmp type`** · **inline dnat data map** · **`mark`**
  (read+write) · **expanded vmap keys** (`dport`/`sport`/`mark`/`state`/`saddr`/
  `daddr` + concat `key: [iif, oif]`; groups/services resolve) — **done**.

1. **`reject with <type>`** — nicer zone-boundary rejects than silent drop.
2. **set-dscp** (family-aware) — promote the deferred DSCP statement.
3. **named / reusable maps** — table-level `maps:`; reusable vmaps + named
   data maps.
4. **more meta matches** (`pkttype`/`skuid`), `redirect`, ct mark.
5. **JSON emitter** — second emitter on the same IR (libnftables JSON).
6. **concat follow-ons** — `proto: [tcp,udp]` list, per-row `proto` field,
   family auto-split.

See [TODO.md](../TODO.md) for the full backlog; the top ranks came from
porting the multi-zone router sketch, not speculation.
