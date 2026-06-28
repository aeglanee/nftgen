# nftgen — design (the "ideal")

A small, **nftables-only** firewall-as-code generator. YAML definitions +
host policies → a native `.nft` ruleset you commit to git and apply with
`nft -f`. Draft — we iterate on this before writing code.

## Philosophy

1. **Mirror nftables, don't hide it.** The YAML's shape follows nft's real
   object model (tables → chains → rules; sets; maps). You author your own
   chains and rules — the tool doesn't invent structure for you. This is what
   makes it both *learnable* (you're learning nft) and *fully customizable*.
2. **High-level where it helps, raw where you need it.** Definitions are named
   and composable; matches read in plain terms (`dport: ssh`); but a `raw:`
   escape hatch means anything nft can express, you can write — today.
3. **Explicit over magic.** No optimizer, no auto-generated chains, no
   auto-injected rules. What you write is what you get. Best practices are
   *easy defaults you choose*, not things forced on you.
4. **An IR in the middle.** YAML → typed objects (Table/Chain/Rule/Set/Map) →
   text. Robust output now; a JSON emitter later from the same IR.
5. **Tested at every step.** Golden files (YAML → exact `.nft`) + `nft -c -f`.

## Project layout

A project is a directory (`<root>`) with a fixed convention. `nftgen build
<root>` reads it and writes one complete `.nft` per host:

```text
<root>/
├── definitions/            # global named definitions (merged: every *.yaml)
│   ├── networks.yaml        #   networks:   name -> [cidr | name ...]
│   ├── services.yaml        #   services:   name -> [port/proto ...]
│   └── interfaces.yaml      #   interfaces: name -> [ifname ...]
├── sites/                   # per-site definition overlays
│   ├── site1.yaml           #   a host's `site: site1` merges this over definitions/
│   └── site2.yaml
├── policies/                # the include base (`include:` paths resolve here)
│   ├── includes/            #   reusable rule/set fragments
│   │   ├── common-input.yaml
│   │   ├── scrub.yaml
│   │   └── ...
│   └── hosts/               # one file per host — the entry points
│       ├── gateway.yaml
│       ├── router1.yaml
│       └── router2.yaml
└── generated/               # OUTPUT — nftgen writes <host>.nft here
    ├── gateway.nft
    └── ...
```

- **`definitions/`** — global definitions. Every `*.y{,a}ml` is merged by category
  (`networks` / `services` / `interfaces`); a duplicate name across files is an
  error. Filenames are organizational only — the loader merges by the top-level
  key inside.
- **`sites/`** — per-site overlays. A host with `site: site1` gets
  `sites/site1.yaml` merged *over* `definitions/`, so a shared name (e.g. `local_users`)
  resolves to that site's value.
- **`policies/includes/`** — fragments holding a `sets:` and/or `rules:` list,
  pulled into a host via `- include: includes/<file>.yaml`. Paths resolve
  relative to `policies/`; includes may nest.
- **`policies/hosts/<name>.yaml`** — the per-host policy (tables → chains →
  rules). One file = one host = one output.
- **`generated/<name>.nft`** — the deploy artifact: a complete ruleset with
  `flush ruleset`, shipped verbatim as `/etc/nftables.conf`. Committed for
  review; **never hand-edited** (the YAML is the only source).

**The naming contract** (load-bearing for deployment — DEPLOYMENT §10.2):

```text
inventory_hostname  ==  policies/hosts/<name>.yaml  ==  generated/<name>.nft
```

`nftgen build <root>` globs `policies/hosts/*.y{,a}ml`, generates each (with
`flush ruleset`), and writes `generated/<stem>.nft` — override the output dir
with `--out-dir`, build one host with `--host`, validate with `--check`. The
worked example lives under [example/](example/).

## The nftables model (what the YAML mirrors)

- **Table** — a container, tied to a **family**: `ip` (v4), `ip6` (v6),
  `inet` (dual-stack). Holds chains, sets, maps. You can have several.
- **Chain** — two kinds:
  - **base chain**: hooked into the kernel — has `type` (filter/nat/route),
    `hook` (prerouting/input/forward/output/postrouting), `priority`, `policy`
    (accept/drop). Packets enter here.
  - **regular chain**: not hooked; reached by `jump`/`goto`. **Free until
    jumped** — used to organize. (Best practice: few base chains, branch into
    regular chains.)
- **Rule** — ordered list in a chain: **matches** (`ip saddr`, `tcp dport`,
  `ct state`, `iifname`, …) + optional **statements** (counter, log) +
  a terminal **verdict** (accept/drop/reject/jump/goto/return). First match wins.
- **Set** — a *typed* named collection: `ipv4_addr` / `ipv6_addr` /
  `inet_service` (ports) / `ifname`. Flags: `interval` (CIDR/ranges),
  `timeout` (dynamic). Referenced as `@name`. Set names are unique per table.
- **Map / vmap** — key → value. A **verdict map** dispatches by a key to a
  verdict in one lookup: `iifname vmap { "wan0": jump wan_in }`.
- **Flowtable** — offloads established flows off the slow path.

## Definitions (composable, merged across files)

```yaml
# definitions/networks.yaml
networks:
  lan:      [192.168.1.0/24]
  mgmt:     [192.168.9.0/24]
  webhosts: [192.0.2.10, 192.0.2.11]
  trusted:  [lan, mgmt]            # composition: names expand, literals stay
```
```yaml
# definitions/services.yaml   (port carries proto; emitted as a proto-agnostic set,
#                      the protocol is stated on the rule — kills tcp/udp mixups)
services:
  ssh: [22/tcp]
  web: [80/tcp, 443/tcp]
  dns: [53/tcp, 53/udp]
```
```yaml
# definitions/interfaces.yaml
interfaces:
  wan:    [wan0, wwan0]
  lan_if: [lan0]                   # named distinctly from network `lan`
```

## Host policy (tables → sets → chains → rules)

A host policy is `tables` → each table has `sets` (which definitions to
materialise as named sets) → `chains` (base chains have a `hook`; regular chains
don't) → `rules`. Rules are block-style mappings (no flow braces). The full
worked example lives in [`example/policies/hosts/router1.yaml`](example/policies/hosts/router1.yaml)
— a filter table (input + forward) plus a separate nat table, a live-populated
`blocklist` set, an include, and conntrack-early written explicitly. Shape:

```yaml
tables:
  - family: inet
    name: filter
    sets:
      - lan
      - webhosts
      - name: blocklist          # bare set, filled live via `nft add element`
        type: ipv4_addr
        flags: [interval, timeout]
    chains:
      - name: input
        hook: input               # presence of `hook` => base chain
        priority: filter          # name (filter=0, raw=-300, srcnat=100…) or number
        policy: drop
        rules:
          - ct: [established, related]
            action: accept
          - saddr: mgmt
            proto: tcp
            dport: ssh
            action: accept
          - include: includes/common-input.yaml
```

## Rule syntax — structured, with a raw escape hatch

A rule is a small mapping of **match keys** + an **action** (the recommended
form), or a `raw:` string for full nft power.

Match keys: `iif` / `oif` (interface), `saddr` / `daddr` (address),
`proto`, `sport` / `dport` (service or port), `ct` (state list),
`counter` (bool), `log` (bool/opts). `action`: `accept` / `drop` / `reject` /
`masquerade`, or a mapping — `jump: chain` / `goto: chain` /
`dnat: 10.0.0.5` / `snat: 1.2.3.4` (written as an indented block under `action:`).

```yaml
- iif: lan_if
  saddr: trusted
  proto: tcp
  dport: web
  counter: true
  action: accept
- proto: tcp
  dport: 8443
  action:
    dnat: "192.168.1.50:443"
- raw: "ip saddr . tcp dport @webmap accept"     # anything not yet modelled
```

A **verdict map** (a native primitive, authored — not inferred):

```yaml
- vmap:
    key: iifname
    entries:
      wan0: jump wan_input
      lan0: jump lan_input
```

## How nftables best practices map onto this YAML

| Best practice | How you express it here |
| --- | --- |
| conntrack early | you write a `ct: [established, related]` → `accept` rule first (explicit, not auto) |
| sets over rule lists | list the group under `sets:` → emitted as a named set, referenced `@name` |
| verdict maps | a `vmap:` rule |
| few base chains, branch via regular | author base chains with `hook:`; put the rest in hookless chains and `jump` |
| named priorities | `priority: raw|mangle|filter|srcnat…` or a number |
| flowtables | a `flowtable:` block on the table (later phase) |
| live blocklists | a bare `sets:` entry with no elements + `flags: [timeout]`; push with `nft add element` |
| counters selectively | `counter: true` only where you want it (never auto) |

## Non-goals

- No optimizer / structure inference (you author it).
- No multi-vendor abstraction (nftables only).
- No auto-generated chains or auto-injected rules.

## Open decisions (to settle before code)

1. **Rule form** — structured mapping + `raw:` (proposed), vs a terser nft-like
   string DSL. Proposed: structured, because it's readable, validatable, and
   composable, with `raw:` covering the rest.
2. **`sets:` entries** — flat names (auto-categorised by which definition table
   they're in; names unique per table, as nft requires) + dict form for bare
   sets. Proposed as above.
3. **Multi-host variables** (per-site `local_*`) — a later phase, modelled on
   the aerleon-fork `local-definitions` idea.
