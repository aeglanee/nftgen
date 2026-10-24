# Decisions

Why nftgen is built the way it is: each entry is a decision, the reason, and
the alternative we rejected. Read the entry before changing a design choice;
add one when you make a new choice. What nftgen does is in
[DESIGN.md](DESIGN.md).

## 1. Core

### 1.1 Mirror nftables

The YAML has nft's structure: tables → chains → rules, named sets, maps. You
write your own base chains (hook, priority, policy) and regular chains.
*Why:* nft's model is good and learnable. An abstraction over it is a second,
lossier model to learn and fight at the edges; the mirror lets anyone who
knows nft read the YAML, and the YAML documents the ruleset.
*Rejected:* a high-level intent language that generates chains — forever
patched, and it hides what an operator must understand to debug a firewall.

### 1.2 No optimizer

No set-vs-linear decisions, no reordering, no merging of rules: the author
decides the structure.
*Why:* at homelab and small-fleet scale an optimizer buys nothing (sets beat
linear matching only in the hundreds of entries) and is a large, bug-prone
surface that takes control away from the operator.
*Rejected:* an Aerleon/Capirca-style optimizing backend.

### 1.3 Typed objects in the middle

YAML → typed objects (`Definitions`, `NamedSet`, `Chain`, `Table`,
`Flowtable`, rules via `RuleRenderer`) → text; the objects render themselves.
*Why:* parsing, checking and output stay separate and testable, and a new
primitive is a local change (a rule key, a table object).
*Rejected:* templating YAML straight to text.

### 1.4 `raw:` is the escape hatch

Any rule can be `raw: "<nft>"`; any table can carry `raw:` declarations.
*Why:* it keeps the project small. The common part is modelled; everything
else is never blocked — it goes through `raw:` until it earns a key, so a
missing key is never a release blocker. ([docs/raw.md](docs/raw.md))

### 1.5 Authored, not auto

`ct state`, counters, conntrack, chains: only where the author writes them.
*Why:* a firewall you can't predict from its source can't be trusted;
surprises in generated rules are how lockouts and silent holes happen.

### 1.6 Strict: fail the build, never render a weaker ruleset

Unknown keys, undefined names, empty groups, cycles, wrong value shapes —
all fail the build (since 0.2.0). Where nft would refuse the output at load
and nftgen can tell cheaply (duplicate map keys, reject in a vmap), it fails
at build too.
*Why:* a silently ignored key is a rule wider or narrower than written; an
empty include under `policy: drop` is a lockout. A loud error at build is
the cheapest place to find either.

## 2. Schema

### 2.1 A rule is a structured mapping

Match keys + statement keys + one action (`saddr`, `iifname`, `proto`,
`dport`, `ct`, `counter`, `action`, …), with `raw:` alongside.
*Why:* readable, diffable, checkable, and close to how you'd say the rule
out loud.

### 2.2 Services carry their protocol, and nftgen never drops it

A service is protocol **and** port (`80/tcp`); every render keeps the pair:

- inline → that protocol's ports (`tcp dport { 80, 443 }`);
- named set → a pair set (`type inet_proto . inet_service`,
  `tcp . 80`), matched as `meta l4proto . th dport @web`;
- `dport`/`sport` vmap → a pair lookup (`meta l4proto . th dport vmap`); a
  bare port number there needs `/tcp`.

`proto:` is optional when the ports come from services: each port keeps its
own protocol (`tcp dport 22`, or `meta l4proto . th dport { tcp . 53,
udp . 53 }`). A bare port number, a port-only set, or `sport` + `dport`
together still need `proto:`.
*Why:* a port-only set loses which protocol a port belongs to. With
`web: [80/tcp, 443/tcp, 443/udp]`, the pre-0.7.0 set `{ 80, 443 }` under
`proto: udp` also opened udp/80, and the old port vmap matched any protocol
(udp/22 for `ssh: [22/tcp]`) — both proven on the wire (behavioral tests
B22, B27). Listing a definition under `sets:` must never change what the
firewall lets through (§2.3).
*Rejected:* erroring on the leaky combinations (forces `web_tcp`/`web_udp`
splits nft can express exactly); port-only services (the leak again; a
hand-written `type: inet_service` set covers the rare real need).

### 2.3 A definition becomes a named set only via a table's `sets:`

Listed under `sets:` → a named set, referenced `@name`; not listed → inline
`{ … }`. Per table, the author's choice.
*Why:* named sets pay off when reused or updated live; inline is clearer for
one-offs. The definition doesn't change either way.

### 2.4 Named sets are single-family; rules are family-aware

A named set mixing v4 and v6 is an error (split `_v4`/`_v6`). A rule renders
once per family its addresses share; no shared family is an error.
*Why:* it designs out Aerleon's silent widening, where a restriction quietly
disappeared when families mixed. You get correct per-family rules or an
error.

### 2.5 Deterministic output

Sorted output, first-seen-order dedupe.
*Why:* the same input gives byte-identical output, so a diff of the rendered
ruleset is always a real rule change. Deployment change detection relies on
it; treat it as correctness, not polish.

### 2.6 Values are schema-checked; one value or a list everywhere

Every rule value is checked against one table (`nftgen/schema.py`) before
rendering; the error names the key, what it got, and what it takes. Every
matching key takes one value or a list.
*Why:* values used to be read in ~30 places, each assuming a shape —
`ct: established` rendered `ct state e,s,t,…`, `log: {prefx: …}` dropped the
prefix, `icmp-type` silently dropped `dport` (a wider rule than written).
One table closes the class and can later be exported as a JSON Schema.
Actions are a fixed list plus `reject with …`; others go through `raw:`.
Protocols are a name or 0–255 (`vrrp`, `112`), checked as the name.
*Rejected:* a `jsonschema` dependency (worse messages, no normalising).

### 2.7 Concatenation sets list their tuples

A concat set states each tuple (`concat:` fields + `tuples:` rows); the rule
references it with `set:`.
*Why:* the tuples are the intent — which source may reach which destination
on which port. Building them from groups needs a pairing rule: `zip` drifts
when a list changes, `product` silently allows every combination.
*Later, if reuse appears:* a fleet-wide `flows:` definition category; the
`tuples:` shape lifts into it unchanged.

### 2.8 Interfaces only through groups

Rules name interface groups from `interfaces:`, never devices.
*Why:* a typo'd device name would render a rule that never matches; an
undefined group fails the build. A single device gets a one-device group.

## 3. Composition and integration

### 3.1 Two front ends, one renderer

- **File tree** (`nftgen build <root>`): `definitions/`, `sites/`,
  `policies/includes/`, `policies/hosts/` → `generated/<host>.nft`.
- **Embedded** (`render_tables()` + a resolver): sessrumnir authors the
  firewall as Ansible inventory variables (`nftgen_definitions__*`,
  `nftgen_fragments__*`, `nftgen_tables`), rendered on the controller by the
  ansible-firewall `nftgen_render` plugin, which imports nftgen.

*Why vars mode for sessrumnir:* everything else there is inventory variables
and roles; the firewall can reuse values the inventory already has
(`wan: "{{ router_wan_ifaces }}"`) instead of retyping interfaces and
subnets, and layers through Ansible groups like the rest. nftgen stays
Ansible-agnostic: the resolver interface and
`Definitions.from_named_mappings` are all the plugin uses.
*Rejected (first plan, superseded at 0.6.0):* nftgen owning composition in
its own tree, called as a CLI from a two-play playbook — it kept a second
source of truth beside the inventory.

### 3.2 Layers add; a collision is an error

`definitions/` + the host's `sites/<site>.yaml` (file tree), or the chunk
variables a host resolves (vars mode): names add up, and one name defined
twice is an error naming both origins.
*Why:* per-site values differ while the policy is shared; no silent
override.

### 3.3 Recursive definitions, cycle-checked, deduplicated

A definition can list other definitions; expansion recurses with a cycle
check and first-seen dedupe.

### 3.4 No policy layer (considered, not adopted)

A typed policy compiler (zones, zone-pair policies, generated dispatch and
NAT, Aerleon-style) was specified in 2026 and never built (the spec is in git
history: `docs/policy-design.md`, removed 2026-10).
*Why:* vars mode with shared fragments covered the real need, and a
generative layer breaks §1.2 and §1.5. Revisit only if writing chains by
hand becomes the bottleneck across many sites.

## 4. Output

### 4.1 Statements are rule keys

`limit`, `quota`, `log`, `set-mark`, `set-mss`, `meter`, `flow-offload` are
keys; a rule may have statements and no action (an MSS clamp).
**Named counters** are declared on the table and referenced by name.
*Why named:* readable `nft list counters` and a stable identity across
reloads; the ansible-firewall metrics export only named counters.

### 4.2 Verdict maps are inline for now

`vmap:` builds an inline map; table-level named maps are on the backlog.
*Why:* inline covers dispatch; named maps earn their place with live
updates or reuse across chains.

### 4.3 `set-dscp` stays in `raw:`

DSCP is family-specific (`ip dscp set` vs `ip6 dscp set`) and needs
per-family rendering like addresses.
*Why:* don't ship a key that can silently do the wrong thing on one family;
`raw:` is honest meanwhile.

### 4.4 Comments are native nft comments

`comment:` on a rule, chain, set entry or table renders nft's
`comment "…"`.
*Why:* it lives in the kernel with the object, so `nft list ruleset` on the
router shows why a rule exists; a `#` line in the file is dropped on load.
*Rejected:* copying YAML `#` comments (YAML parsers drop them, and source
prose isn't written for the box).

### 4.5 Per-rule file notes are a hook, not a feature

`render_tables(…, annotate=fn)` calls `fn(rule)` for each authored rule and
appends the returned note as `# <note>` to every line the rule renders to.
The Ansible front end uses it for opt-in git-blame notes
(`# nftgen-blame: <author> · <sha> · <date>`).
*Why a hook:* nftgen stays git- and Ansible-agnostic; `#` comments vanish on
load, so the kernel ruleset is the same with or without notes, and removing
them gives back the plain render byte for byte.
*Why `#`, not `comment:`:* git metadata isn't the author's words, and the
native comment's 128 bytes stay the author's (§4.4).

## 5. Packaging

### 5.1 Point at a directory, no config file

`nftgen build <root>` works from a fixed layout; flags override paths.
*Why:* there's nothing to configure beyond paths, and they follow from the
root. An optional `nftgen.yml` comes only when there's a real setting.

### 5.2 One package, thin CLI

`build(root)` → `{host: text}` and `render_tables()` are the entry points;
the CLI wraps them. CLI, CI and the Ansible plugin share one tested path.

### 5.3 The output is the deploy artifact

`nftgen build` renders every host; each file is complete: shebang + a reset
(§5.4) + the host's tables, shipped verbatim as `/etc/nftables.conf`.
*Why build-all:* rendering is cheap and deterministic, and change detection
needs every host. *Why a reset:* the file is one replaceable, atomic unit,
safe to reapply — without one, `nft -f` appends every rule again. It isn't a
hidden rule (§1.5): it's visible at the top and belongs to the deploy
artifact. The single-file mode and `generate()` stay reset-free for
embedding.
*Rejected:* a wrapper `nftables.conf` that flushes and includes a flush-free
file — one more indirection, and the reviewed file is no longer the one on
the box.

### 5.4 Two reset modes, chosen per host

`reset: flush` (default) starts the file with `flush ruleset`; `reset:
own-tables` with one `destroy table` per distinct rendered table, so other
tools' tables (Docker, Kubernetes, fail2ban) survive an apply.
*Why per host, in the policy:* what else writes rules is a fact about the
host; a CLI flag would make the output depend on how nftgen was run, not on
the YAML. *Why derived, not authored:* leaving a table out of the reset
doubles its rules on every apply, so there's nothing to choose. *Why
`destroy`:* one line, a no-op on a missing table; plain `delete` aborts the
file on a first deploy (`add`+`delete` would cover nft < 1.0.7 / kernel < 6.3,
which the deploy target, Ubuntu 26.04, doesn't need). *Why no `retired:`
key:* a table dropped from the YAML is removed by the ansible-firewall role,
which sees the previous `/etc/nftables.conf`; nftgen can't see the host, and
comparing with its own previous output would make the output depend on more
than the YAML (§2.5). The ownership and takeover rules are in
[docs/coexistence.md](docs/coexistence.md).
*Rejected:* a CLI flag; a hand-written reset list; a `comment` marker on
tables (table comments belong to the author).

## 6. Environment notes

- Plain `nft -c` fails in a `NoNewPrivs` sandbox (netlink); `unshare -rn
  nft -c -f <file>` works, and `validate.py` falls back to it.
- Editor warnings like "Missing property terms" on nftgen YAML are VS Code
  applying **Aerleon's** JSON schema; an nftgen schema export is on the
  backlog.

## Relationship to the Aerleon fork

nftgen is a clean-room, nftables-only rebuild. The earlier Aerleon nftables
fork showed what we wanted; nftgen keeps its definitions model (credited in
the README) and drops the multi-platform model, the optimizer and the silent
family widening (§2.2, §2.4).
