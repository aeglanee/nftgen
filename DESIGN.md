# nftgen — reference

nftgen turns YAML definitions and host policies into one native nftables
ruleset per host. This is the reference: the layout, every YAML key and what
it renders to, what nftgen derives for you, and what fails the build. The
*why* is in [DECISIONS.md](DECISIONS.md); how to structure a firewall is in
[docs/authoring.md](docs/authoring.md).

## Principles

1. **Mirror nftables.** The YAML has nft's shape (tables → chains → rules;
   sets; maps), and you write your own chains. You are learning nft.
2. **What you write is what you get.** No optimizer, no generated chains, no
   injected rules — conntrack, counters and `ct state` only where you write
   them.
3. **Strict.** A typo, an unknown name or a value of the wrong shape fails the
   build; nftgen never renders a weaker or empty ruleset in its place.
4. **Deterministic.** The same input gives byte-identical output, so a diff of
   the generated file is a real rule change.
5. **`raw:` is the escape hatch** for anything without a key yet
   ([docs/raw.md](docs/raw.md)).

## Project layout

```text
<root>/
├── definitions/          # networks, services, interfaces (every *.yaml merged)
├── sites/<site>.yaml     # per-site definitions, picked by a host's `site:`
├── policies/
│   ├── includes/         # shared rule and set fragments (`- include:`)
│   └── hosts/<host>.yaml # one file per host
└── generated/<host>.nft  # the output: one complete ruleset per host
```

- **`definitions/`**: every `*.yaml` / `*.yml` below it is merged by category;
  file names are organisational only.
- **`sites/`**: a host with `site: s1` also gets `sites/s1.yaml`. It adds
  names; a name defined in both is an error.
- **`policies/includes/`**: files with a `rules:` and/or `sets:` list, pulled
  in with `- include: includes/<file>.yaml` (paths from `policies/`, may
  nest). The include's position picks the section: under a chain's `rules:`
  it reads the file's `rules:`, under a table's `sets:` its `sets:`. That
  section must exist and be a list (`rules: []` for a deliberately empty
  file); any other top-level key is an error.
- **`generated/<host>.nft`**: `#!/usr/sbin/nft -f` + the host's reset + the
  host's tables — directly applyable, shipped as `/etc/nftables.conf`. A
  render, never hand-edited.
- **`reset:`** (host policy, next to `site:` and `tables:`): what the file
  clears first. `flush` (default) → `flush ruleset`, everything. `own-tables`
  → one `destroy table <family> <name>` per distinct rendered table, so other
  tools' tables (Docker, Kubernetes, fail2ban) survive; needs nft ≥ 1.0.7 and
  kernel ≥ 6.3. A table dropped from `tables:` stays on the host — the
  ansible-firewall role removes it ([docs/coexistence.md](docs/coexistence.md)).

  ```nft
  destroy table inet filter
  destroy table inet nat

  table inet filter { … }
  ```

**Naming contract:** `inventory_hostname == policies/hosts/<name>.yaml ==
generated/<name>.nft`.

### CLI

```bash
nftgen build <root>                       # every host → <root>/generated/
nftgen build <root> --host fw1            # one host
nftgen build <root> --host fw1 --stdout   # print it, write nothing
nftgen build <root> --check               # also run `nft -c` on each output
nftgen <policy.yaml> --defs <dir> [--out f.nft] [--check]   # one file, tables only (`reset:` ignored, with a warning)
```

- `--host` is a plain host name (no path, no pattern); two files for one host
  (`fw1.yaml` + `fw1.yml`) and a root with no host policies are errors.
- `--check` fails (exit 2) when `nft -c` can't run here, instead of skipping.
- Errors are one line (`nftgen: error: …`, exit 1); a closed stdout pipe exits
  quietly (141); anything else is a bug (`internal error`, exit 70).

### As a library

The CLI's renderer is `render_tables(tables, defs, resolver, *, source, reset,
annotate)`; `reset` is `"flush"`, `"own-tables"` or `None` (tables only), and
`flush=True` still means `reset="flush"`. With `PathResolver` it reads include
files; with `DictResolver` includes are named fragments in a dict — the Ansible
vars mode in [DEPLOYMENT.md](DEPLOYMENT.md) uses that.
`Definitions.from_named_mappings` builds definitions from named layers and names
both origins of a duplicate. `annotate` (optional) returns a note per rule,
appended as a `# <note>` file comment on every line the rule renders to (dropped
by nft on load).

## Definitions

```yaml
networks:
  mgmt:     [192.168.9.0/24, fd00:9::/64]
  webhosts: [192.0.2.10, 192.0.2.11]
  trusted:  [mgmt, webhosts]        # composition: names expand, literals stay
services:
  ssh: [22/tcp]
  dns: [53/tcp, 53/udp]
  web: [http, https]                # composition of other services
interfaces:
  wan: [wan0, wwan0]
  lo:  [lo]                         # a one-device group for a single device
```

- **networks**: IP addresses and CIDRs, v4 and v6 mixed if you like.
- **services**: `port/protocol` pairs; the port may be a range (`8000-8100/tcp`),
  the protocol a name or a number (stored as its name: `53/17` = `53/udp`).
  Only protocols with ports: tcp, udp, sctp, dccp, udplite.
- **interfaces**: device names. Rules refer to interface **groups**, never to
  devices directly, so a typo can't become a device that never matches.
- Composition is recursive, cycle-checked, and deduplicated (first-seen order).
- A name is unique within a category; a duplicate is an error naming both
  origins.

## Tables

| Key | Meaning |
| --- | --- |
| `family`, `name` | `table inet filter { … }` — required |
| `sets` | named sets (below) |
| `chains` | base and regular chains (below) |
| `counters` | named counters, one name or a list: `counters: [bad_tcp]` → `counter bad_tcp { }` |
| `flowtables` | `{name, devices, hook?, priority?}` — `devices` is one interface group or a list (a device in two groups is listed once); hook defaults to `ingress`, priority to `0` |
| `raw` | object declarations copied into the table verbatim, one line or a list |
| `comment` | nft `comment "…"` on the table |

## Sets

A definition becomes a **named set** only when listed in a table's `sets:`;
otherwise a rule writes its values inline (`{ … }`). The author chooses per
table; the firewall behaves the same either way.

| `sets:` entry | Renders |
| --- | --- |
| a network | `type ipv4_addr` or `ipv6_addr`, `flags interval` (one family only; split `_v4`/`_v6`) |
| a service | `type inet_proto . inet_service`, elements `tcp . 22` — each port keeps its protocol; `flags interval` if any range |
| an interface group | `type ifname`, elements `"wan0"` |
| `{name, type, flags?, elements?}` | a hand-written set, e.g. an empty `timeout` blocklist filled with `nft add element`; `flags` from `constant`, `interval`, `dynamic`, `timeout`; each key one value or a list |
| `{name, concat, proto?, tuples, family?}` | a concatenation set of exact pairs (see below) |

Any entry may carry `comment:`. A set with `flags: [dynamic]` can back a
`meter:`.

**Concatenation sets** hold exact combinations, matched in one lookup:

```yaml
sets:
  - name: db_flows
    concat: [saddr, daddr, dport]   # saddr, daddr, sport, dport, iifname, oifname, mark
    proto: tcp                      # needed with a port field
    tuples:
      - [app_host, db_host, postgres]
rules:
  - set: db_flows                   # → ip saddr . ip daddr . tcp dport @db_flows
    action: accept
```

Each tuple field takes one value (a single-value group or a literal). The
family comes from the tuples; a set filled at runtime (no tuples) with an
address field needs `family: ip` or `ip6`.

## Chains

| Key | Meaning |
| --- | --- |
| `name` | required; not a reserved nft keyword |
| `hook` | makes it a base chain (`input`, `forward`, `output`, `prerouting`, `postrouting`, `ingress`) |
| `type` | `filter` (default), `nat`, `route` — base chains only |
| `priority` | a number or `raw`, `mangle`, `dstnat`, `filter` (0, default), `security`, `srcnat` — base chains only |
| `policy` | defaults to `drop` for `filter`, `accept` otherwise — base chains only |
| `rules` | the rules, in order (first match wins) |
| `comment` | nft `comment "…"` on the chain |

A chain without `hook` is a regular chain, reached by `jump`/`goto`;
`type`/`priority`/`policy` on it are an error.

## Rules

A rule is a mapping of match keys, statements and one action — or one of the
forms below. Rule order is kept exactly.

### Matches

| Key | Example | Renders |
| --- | --- | --- |
| `iifname` / `oifname` | `iifname: wan` | `iifname { "wan0", "wwan0" }` (name match) |
| `iif` / `oif` | `iif: lan` | `iif "lan0"` (index match: faster, but the ruleset fails to load if the interface is missing; not with a named set) |
| `saddr` / `daddr` | `saddr: mgmt` | `ip saddr 192.168.9.0/24` + `ip6 saddr fd00:9::/64` — one line per family the addresses share |
| `proto` | `proto: icmp` | `meta l4proto icmp` (a name, or a number 0–255) |
| `sport` / `dport` | `proto: tcp` + `dport: ssh` | `tcp dport 22` |
| `ct` | `ct: [established, related]` | `ct state established,related` |
| `mark` | `mark: "0x1"` | `meta mark 0x1` (a number, `0x…`, or a range; quote hex, or YAML reads `0x1` as `1`) |
| `ct-mark` | `ct-mark: "0x1"` | `ct mark 0x1` (the connection's mark; a number, `0x…`, or a range) |
| `icmp-type` | `proto: icmpv6` + `icmp-type: [nd-neighbor-solicit]` | `icmpv6 type nd-neighbor-solicit` (needs `proto: icmp`/`icmpv6`, no ports) |
| `flags` | `flags: {match: [syn], mask: [syn, ack]}` | `tcp flags & (syn\|ack) == syn` (a list makes one line each) |

**One value or a list:** `saddr`/`daddr`, `sport`/`dport`, the interface keys,
`ct` and `icmp-type` take one value or a list (`dport: [ssh, 8080]` →
`tcp dport { 22, 8080 }`). Each element resolves as it would alone; a named
set can't go inside a list.

**Named or inline:** a value that is a set listed under `sets:` renders
`@name`; a definition renders its values inline; a literal renders itself.

**Ports and protocols:**

- With `proto:`, a service contributes its ports for that protocol only (an
  error if it has none). A number is checked as its name: `proto: 17` +
  `dport: dns` → `udp dport 53`.
- Without `proto:`, ports from services keep their own protocol: one protocol
  renders `tcp dport 22`; several render
  `meta l4proto . th dport { tcp . 53, udp . 53 }` (named: `@dns`). A bare
  port number, a hand-written port-only set, or `sport` + `dport` together
  still need `proto:`.
- `icmp` renders only IPv4 lines and `icmpv6` only IPv6 lines.

### Statements

| Key | Example | Renders |
| --- | --- | --- |
| `counter` | `true` / `bad_tcp` | `counter` / `counter name bad_tcp` (named: declared in the table) |
| `log` | `true` / `{prefix: "ssh ", level: info}` | `log prefix "ssh " level info`; `group: 2` logs to NFLOG instead (not with `level`); `false` = none |
| `limit` | `4/minute` | `limit rate 4/minute` |
| `meter` | `{set: m, key: saddr, rate: 4/minute, timeout: 1m}` | `update @m { ip saddr timeout 1m limit rate 4/minute }` (a `dynamic` set; keys saddr/daddr/iifname/oifname) |
| `quota` | `over 10 mbytes` | `quota over 10 mbytes` |
| `set-mark` | `"0x1"` / `ct-mark` | `meta mark set 0x1` / `meta mark set ct mark` (restore the connection's mark) |
| `set-ct-mark` | `"0x1"` / `mark` | `ct mark set 0x1` / `ct mark set meta mark` (save the packet's mark) |
| `set-mss` | `pmtu` / `1452` | `tcp flags syn tcp option maxseg size set rt mtu` / `… 1452` (1–65535) |
| `flow-offload` | `ft` | `flow add @ft` (a declared flowtable; a separate rule from the verdict) |
| `comment` | `"admins → router ssh"` | `comment "…"`, last on every line of the rule; kept by the kernel; no `"`, ≤ 128 bytes |

A rule may have statements and no action (e.g. an MSS clamp).

### Actions

| `action:` | Renders |
| --- | --- |
| `accept`, `drop`, `reject`, `return`, `continue`, `masquerade` | the word |
| `reject with tcp reset` (any `reject with …`) | the text |
| `{jump: chain}` / `{goto: chain}` | `jump chain` / `goto chain` |
| `{dnat: 192.168.10.5:443}` / `{snat: wan_ip}` | `dnat ip to 192.168.10.5:443` — family from the address; a single-address network group resolves |
| `{dnat: {proto: tcp, map: {80: web, 443: db}}}` | `dnat ip to tcp dport map { 80 : …, 443 : … }` (address-only targets) |

Anything else (`queue`, `notrack`, …) is a `raw:` rule.

### Other rule forms

- **`raw: "<nft rule>"`**: copied verbatim; the rule's only key.
- **`include: <file>`**: replaced by the file's rules.
- **`set: <concat set>`**: the concatenation lookup (above); may carry
  statements and an action, not other matches.
- **`vmap:`**: a verdict map, the rule's only key (plus `comment`):

  ```yaml
  - vmap:
      key: iifname                  # iifname, oifname, iif, oif, proto, dport, sport, mark, state, saddr, daddr
      map:
        wan:
          jump: wan_in
        lo: accept
  - vmap:
      key: [iifname, oifname]       # concatenated keys: groups expand to every pair
      map:
        - match: [lan, wan]
          jump: lan_to_wan
        - match: [wan, lan]
          action: drop
  ```

  Values are verdicts only: `accept`, `drop`, `return`, `continue`, `jump`,
  `goto` (nft refuses reject or NAT in a vmap). `dport`/`sport` keys are
  protocol+port lookups (`ssh` → `tcp . 22`; a bare number needs `/tcp`); with
  a `proto` column the port column takes that row's protocol, and
  `sport` + `dport` need one. Address keys are single-family. The same key
  twice with different verdicts is an error.

## What nftgen derives, and what it leaves to you

Derived (mechanical, always the same answer, `nft -c` would reject a wrong
one):

- **Set types and flags** from the members (table above).
- **Family split:** one line per family the addresses share; no shared family
  is an error, never a silently widened rule.
- **Syntax:** family prefixes, `meta l4proto`, protocol-qualified ports.
- **Dedup and order:** duplicate elements dropped (first-seen order kept),
  `ip` lines before `ip6`, files merged by name. Rule order is never changed.

Left to you, because it is intent: which flows are allowed, the chain
structure, default policies, named vs inline sets, conntrack and counters,
rule order. An empty chain stays empty.

## What fails the build

- Unknown keys at any level; a policy without `tables:`; a `reset:` other
  than `flush` or `own-tables` (blank too).
- Values of the wrong shape (`ct: bogus`, `log: {prefx: …}`, a two-key
  `action`, `set-mss: 0`) — checked against one schema before rendering.
- Undefined names; a group that resolves to nothing; definition and include
  cycles; an include with a missing or misnamed section.
- A named set mixing v4 and v6; a rule whose addresses share no family.
- Object names that are reserved nft keywords (`counter`, `fwd`, `map`, …).
- `flow-offload:` and an action in one rule (the verdict would never run).
- `set-mark:` and `set-ct-mark:` in one rule when one copies the other
  (`ct-mark` / `mark`): the result would depend on their order.
- Duplicate map keys; reject/NAT inside a vmap; a port on a protocol without
  ports.

**Not caught at build** (nft refuses them at load or `nft -c`, loudly):
overlapping prefixes in a named set or a vmap (`10.0.0.0/8` and
`10.1.0.0/16`), a port inside a range in a vmap. Merge or drop the covered
entry.

**Not modelled** (use `raw:` at table level): `netdev` per-device chains, set
tuning (`size`, `gc-interval`), named maps, named stateful objects other than
counters.
