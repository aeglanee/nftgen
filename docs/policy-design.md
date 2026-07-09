# nftgen policy layer — design (normative spec)

Status: draft proposal — not yet discussed or agreed, not implemented.
Not linked from the docs map or TODO.md/PLAN.md until it's been reviewed.
Implementation order and per-phase acceptance criteria (if adopted) would
live in [implementation-phases.md](implementation-phases.md). The base
("mirror") layer is specified in [../DESIGN.md](../DESIGN.md) and is
unchanged by this document.

## What this adds and why

An **opt-in typed policy layer**: zones, hard-typed services, named
network lists, and zone-pair policies — in the spirit of Aerleon/Capirca
(typed definitions + policy terms), but nftables-only and router-grade.
Aerleon's nftables generator emits stateful input/output host filters
and nothing else: no FORWARD chains, no zones, no NAT/SNAT/DNAT/
masquerade, no mangle, no sets/vmaps/flowtables, no custom chains. The
policy layer's entire purpose is that missing backend.

The policy layer is a **compiler, not a new renderer**:

```text
policy doc ──compile_policy()──► mirror-layer dict ──existing IR/renderer──► .nft
```

Everything it emits is expressible in the mirror layer — the mirror
schema is the forcing function that keeps both layers honest, the
debugging surface (`--emit-mirror` dumps the lowered dict), and the
escape hatch: a host may carry `policy:` and hand-authored `tables:`
side by side, merged into one output.

The mirror layer's "no auto-injected rules" rule still governs the
mirror layer. The policy layer is _generative by definition_ — the
author asks for a compiled policy, and the compiler owns the skeleton
it emits (documented exhaustively below; nothing is emitted that this
spec doesn't name).

## Module placement

```text
nftgen/policy/
  __init__.py
  schema.py      # document validation: shapes, enums, token existence
  compiler.py    # compile_policy(doc, defs) -> mirror-layer dict
```

The mirror modules (`ir.py`, `rules.py`, `definitions.py`,
`generate.py`) gain only the prerequisite features listed in
IMPLEMENTATION-PHASES.md (concat matches, named maps, NAT/statement
gaps) — all independently useful in mirror-layer YAML.

## Definitions extensions

Definitions stay the existing three categories (`networks`, `services`,
`interfaces`, recursive composition, site overlays) plus one new one:

```yaml
zones:
  users:
    interfaces: [users_vlan] # interface tokens (groups compose)
    networks: [users_net] # optional; enables anti-spoof + zone-addr terms
  servers:
    interfaces: [servers_vlan]
    networks: [servers_net]
  inet:
    interfaces: [uplinks] # e.g. uplinks: [wan, wan_backup]
  mgmt:
    interfaces: [mgmt_vlan]
```

- A zone is a compile-time concept — the "virtual interface" a policy
  references. `interfaces:` is required (≥1 token); `networks:` is
  optional.
- Reserved zone names: `local` (this host itself; the implicit `to:` of
  `input:` and `from:` of `output:`) and `any` (no interface match —
  for simple hosts and catch-alls). Defining either in `zones:` is a
  `BuildError`.
- Zones participate in site overlays exactly like other categories
  (a site file may override or add zones).

### Services: named tokens + `PORT_PROTO` literals

Named service tokens work as today (`ssh: [22/tcp]`,
`web: [http, https]`). Additionally, anywhere a policy term accepts a
service token, a token matching `^(\d{1,5})_(tcp|udp)$` — `80_tcp`,
`6000_udp` — resolves as that literal port/protocol **without needing a
definitions entry**. Rules:

- The port must be 1–65535; else `BuildError`.
- If a definitions entry with the same name exists, the definition wins
  (and the collision is worth a warning comment in the rendered output).
- Any other undefined token is a `BuildError` naming the term (Aerleon
  behavior: undefined token = build failure, never silent).

### Named lists are just network tokens

The "typed list" workflow is the existing `networks:` category — no new
mechanism. Worked example (the canonical one for docs and tests):

```yaml
# definitions/networks.yaml
networks:
  allow_web_servers_to_internet:
    - 10.0.20.11
    - 10.0.20.12
```

```yaml
# policy (see below)
forward:
  - from: servers
    to: inet
    terms:
      - name: web-servers-out
        source: allow_web_servers_to_internet
        services: [web, dns]
        action: accept
```

Adding a server = appending one line to the list; the compiler
re-derives the named set (or concat set) and nothing else changes.

## Policy document schema

A host file is routed through the compiler when it has a top-level
`policy:` key. `tables:` may coexist (merged after compilation; name
collisions between compiled and hand-authored tables/chains are a
`BuildError`).

```yaml
site: site1
policy:
  options:
    family: inet # inet (default) | ip | ip6
    default: drop # base-chain policy for input + forward
    drop_invalid: true # emit `ct state invalid drop` in base chains
    dispatch: vmap # vmap (default) | ladder | index
    log_default_drop: false # trailing log+drop per leaf (see Logging)
    icmpv6_nd: auto # auto (default) | off  — see ICMPv6 section
    flowtable: # optional; omitted = no fast path
      name: fastpath
      devices: [uplinks, users_vlan] # interface tokens
      offload: false # hw offload flag

  forward: # zone-pair sections, order preserved
    - from: users
      to: inet
      terms: [...]
    - from: users
      to: servers
      terms: [...]

  input: # to-zone implicitly `local`
    - from: mgmt
      terms: [...]
    - from: any # no iif match — simple-host / catch-all
      terms: [...]

  output: [] # optional; omitted → output chain policy accept

  nat:
    snat:
      - from: users # optional source zone (iifname scope)
        to: inet # required egress zone (oifname)
        masquerade: true # XOR with `snat: <addr literal or network token>`
    dnat:
      - in: inet # ingress zone (iifname scope)
        forwards:
          - { name: web, match: 80_tcp, to: "10.0.10.5:8080" }
          - { name: game, match: 6000_udp, to: gamesrv } # token → single addr required

  mangle: # optional; zone-pair scoped statements
    - from: users
      to: inet
      terms:
        - { name: clamp, set-mss: pmtu }
        - { name: voip, services: [sip], set-dscp: ef }
        - { name: marked, dest: cdn_nets, set-mark: "0x1" }
```

### Term fields

| Field                               | Meaning                                  | Notes                                                              |
| ----------------------------------- | ---------------------------------------- | ------------------------------------------------------------------ |
| `name`                              | required, unique per section             | used in set names, counter names, log prefixes                     |
| `source` / `dest`                   | network token(s)                         | string or list; composes                                           |
| `services`                          | service tokens / `PORT_PROTO`            | destination ports                                                  |
| `source-services`                   | same, source ports                       | rare, supported                                                    |
| `protocol`                          | `tcp`\|`udp`\|`icmp`\|...                | only needed without `services`                                     |
| `icmp`                              | named ICMP types                         | per-family (see ICMP section)                                      |
| `action`                            | `accept`\|`drop`\|`reject`               | also `{jump: <chain>}` / `{goto: <chain>}` to hand-authored chains |
| `log`                               | bool or `{prefix, level}`                |                                                                    |
| `counter`                           | bool (anonymous) or name (named counter) |                                                                    |
| `limit`                             | rate string (`4/minute`)                 | mirrors the mirror-layer key                                       |
| `set-mss` / `set-dscp` / `set-mark` | mangle statements                        | mangle sections only                                               |

Every token is resolved at compile time; any unknown token, zone,
action, or field is a `BuildError` carrying the section + term name.

### Simple-host mode

A policy with only `input:` (typically a single `from: any` section)
and no `zones:` definitions is valid: the compiler emits just the input
base chain. Nothing router-specific is required — this keeps nftgen
usable for plain hosts.

## Compiler output contract

For `family: inet` (dual-stack; the renderer already splits v4/v6 per
rule) the compiler emits, deterministically and completely:

```nft
table inet filter {
    map zone_fwd_dispatch {
        type ifname . ifname : verdict
        elements = { "lan0" . "wan0" : goto users_to_inet,
                     "lan0" . "svc0" : goto users_to_servers }
    }
    set p_users_to_servers_app_access_v4 {
        type ipv4_addr . inet_service
        elements = { 10.0.10.5 . 5432 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop                       # drop_invalid
        iifname "lo" accept
        # icmpv6_nd: auto → ND essentials here (see ICMPv6 section)
        iifname vmap @zone_in_dispatch              # or ladder
        # `from: any` terms render inline after the dispatch
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related flow add @fastpath   # only with flowtable
        ct state established,related accept
        ct state invalid drop
        iifname . oifname vmap @zone_fwd_dispatch
    }
    chain users_to_inet   { ... }     # one regular chain per zone-pair
    chain users_to_servers { ... }
    chain in_mgmt          { ... }    # input zone leaves
}
table inet nat {                      # only when policy.nat present
    chain prerouting  { type nat hook prerouting  priority dstnat; policy accept; ... }
    chain postrouting { type nat hook postrouting priority srcnat; policy accept; ... }
}
table inet mangle {                   # only when policy.mangle present
    chain forward { type filter hook forward priority mangle; policy accept; ... }
}
```

Naming rules (deterministic, stable across runs):

- forward leaves: `{from}_to_{to}`; input leaves: `in_{from}`;
  output leaves: `out_{to}`.
- per-term concat/named sets: `p_{leaf}_{term}` with `_v4`/`_v6`
  suffixes when family-split.
- dispatch maps: `zone_fwd_dispatch`, `zone_in_dispatch`,
  `zone_out_dispatch`.

### Dispatch strategies

- **`vmap` (default):** `iifname . oifname vmap @zone_fwd_dispatch`
  against a table-level named verdict map whose elements are the
  cartesian expansion of each zone-pair's interface groups → `goto
<leaf>`. One hash lookup per packet regardless of zone count — the
  O(1) structure from sessrumnir's
  `docs/discussion/nftables-optimization-ideas.md`. Input/output use
  single-key `ifname : verdict` maps.
- **`ladder`:** the proven `iifname "x" oifname "y" goto leaf` line per
  interface pair (the pre-policy-layer prototype output). O(pairs), fine
  for small hosts; useful for diff-reading.
- **`index`:** same shapes but `iif`/`oif` numeric matches. Fastest, but
  index matching breaks when interfaces are created after ruleset load
  or recreated (VLANs, tunnels) — the ruleset either fails to load or
  silently matches nothing. Only for hosts whose interfaces all exist at
  boot and never churn. `iifname` is the default for a reason; this is
  the documented trade-off knob.

`goto` (never `jump`) is used for leaf dispatch so fall-through lands on
the base chain's `policy drop` without re-walking dispatch.

### Term rendering

- A term with **paired dimensions** (source/dest addresses AND
  services, where the pairing matters) compiles to a **concatenated
  named set** and a single lookup:
  `ip daddr . tcp dport @p_{leaf}_{term}_v4 accept` (per family).
- A term with a single dimension compiles to a plain named-set or
  literal match.
- ICMP terms: `icmp:` names render per family — `icmp type X` and/or
  `icmpv6 type Y` — from a compiler-owned name table (echo-request,
  echo-reply, destination-unreachable, time-exceeded, packet-too-big,
  parameter-problem, router/neighbor solicitation+advertisement).
- Intra-zone pairs (`from: users, to: users`) are **not** special: if
  unauthored, such traffic falls to the base `policy drop` like any
  other unlisted pair. No magic.

### NAT

- `dnat` forwards render in `prerouting`:
  `iifname <in-zone ifaces> tcp dport 80 dnat ip to 10.0.10.5:8080`.
  Inside inet-family tables the family-qualified `dnat ip to` /
  `dnat ip6 to` form is **mandatory** — a v4-only target emits only the
  `ip` rule (and vice versa); a dual-stack target token emits both.
- `snat`/`masquerade` render in `postrouting`:
  `iifname <from ifaces> oifname <to ifaces> masquerade` (iifname is
  valid in postrouting) or `... snat ip to <addr>`.
- HA twins that differ only in NAT (active/standby routers) express the
  difference as per-host `nat:` sections over an otherwise shared
  policy.

### Mangle

Rendered as a `priority mangle` (-150) forward chain scoped by
zone-pair `iifname`/`oifname` matches inline (mangle sections are
small; no dispatch tier). `set-mss: pmtu` → `tcp flags syn tcp option
maxseg size set rt mtu`; `set-dscp` renders per family
(`ip dscp set` / `ip6 dscp set`).

### Flowtable

`options.flowtable` compiles to the mirror `flowtables:` declaration
plus a `ct state established,related flow add @<name>` rule placed
_before_ the est/related accept in `forward` — the fast-path pattern.
Devices resolve from interface tokens. Off by default.

### ICMPv6 ND (`icmpv6_nd: auto`)

When the family covers v6, `auto` (default) injects into `input` the ND
essentials — `icmpv6 type {nd-neighbor-solicit, nd-neighbor-advert,
nd-router-solicit, nd-router-advert} accept` plus
`packet-too-big`/`parameter-problem` — immediately after the invalid
drop. This is a **deliberate deviation** from the mirror layer's
no-injection rule: forgetting ND on a default-drop router silently
bricks IPv6, the failure is delayed and miserable to debug, and the
policy layer is generative by contract. `icmpv6_nd: off` disables it
for authors who want full manual control (the term snippet to copy is
documented). The injected rules are always emitted with a
`# icmpv6_nd: auto` comment so a ruleset reader can see their origin.

### Anti-spoof (zones with `networks:`)

Per-zone opt-in knob (`zones.<name>.anti_spoof: true` in definitions or
a policy option — settle at implementation to whichever reads better in
tests): for each interface of the zone, emit an early `forward`/`input`
rule dropping packets arriving on that interface whose source address
is not within the zone's networks (`iifname <ifaces> ip saddr !=
@zone_users_nets_v4 drop`, per family). Requires `networks:` on the
zone; asking for anti-spoof on a zone without networks is a
`BuildError`.

### Logging & counters

- `log_default_drop: true` appends `log prefix "{leaf}-drop: " drop` to
  every leaf (and the base chains) — off by default; inline syslog
  logging is a known packet-path cost (see the optimization notes); an
  nflog group option is a planned follow-up knob.
- Term `counter: true` → anonymous counter; `counter: <name>` →
  table-level named counter (auto-declared).

## API

```python
# nftgen/generate.py
def generate_from_data(
    policy: Mapping[str, Any],
    definitions: Mapping[str, Any] | Sequence[Mapping[str, Any]] | Definitions,
) -> str:
    """Dicts in, complete ruleset text out. No filesystem access.
    `include:` entries raise BuildError — callers pre-merge (Ansible does)."""
```

- `generate(policy_path, defs_dir, include_base, sites_dir)` keeps its
  signature and becomes: load YAML → resolve includes + site overlay →
  call the same core `generate_from_data` uses.
- The core routes through `compile_policy()` when the doc has `policy:`.
- CLI unchanged; policy-layer hosts just work. A `--emit-mirror` flag
  prints the lowered mirror dict as YAML for debugging.

## Packaging & versioning

- No new dependencies (PyYAML only); `nftgen/policy/` ships in the same
  wheel — no extra.
- Semver tags on `github.com/life-f0rm/nftgen`:
  - **v0.4.0** — mirror prerequisites (N1–N4) + `generate_from_data`.
  - **v0.5.0** — policy layer (N6–N8).
- Consumers pin tags:
  `nftgen @ git+https://github.com/life-f0rm/nftgen.git@v0.5.0`.
  Tags are never mutated; breaking schema changes bump minor (pre-1.0).

## Extensibility contract

How to add capability later without re-architecting (this is a promise
the implementation must keep):

- **New match key or statement**: one entry in `RuleRenderer`'s
  key→expression vocabulary (shared with `_vmap()`/`_concat()`), plus a
  unit test and a golden update. Match keys must never be interpreted
  positionally.
- **New action/verdict**: extend `_verdict()`; verdict mappings are the
  only place actions are interpreted.
- **New definitions category**: a new top-level key in
  `Definitions` with the same recursive-composition loader; categories
  are independent namespaces.
- **New policy section**: a new `compile_policy` sub-compiler that emits
  mirror-layer constructs only — if the mirror layer can't express it,
  extend the mirror layer first (that's what keeps `raw:` and hand
  authoring at parity).
- **New emitter** (e.g. libnftables JSON): implement against the IR
  (`Table`/`Chain`/`NamedSet`/`Map`), never against rendered text.
- **Schema versioning**: policy docs may carry `policy.version` (int,
  default 1); the compiler rejects versions it doesn't know. Additive
  fields don't bump the version; semantic changes do.

## Relationship to the mirror layer (unchanged guarantees)

- Mirror-only hosts work forever; the policy layer is opt-in per host.
- `raw:` remains the never-blocked escape hatch at rule and table level.
- A policy host may add hand-authored `tables:`/chains and `jump`/`goto`
  into them from terms — the compiler validates the referenced chain
  names exist somewhere in the merged doc.
