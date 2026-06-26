# Decisions & rationale

Why nftgen is the way it is. Each entry is a decision we made, the reasoning,
and (where relevant) the alternative we rejected. This is the "don't lose
context" record — read it before changing a design choice, and add to it when
you make a new one.

Format: **Decision** → *Why* → *Rejected alternative* (if any).

---

## 1. Core philosophy

### 1.1 Mirror nftables; don't hide it
**Author the real nft structure** in YAML: tables → chains → rules, named sets,
maps. You write your own base chains (hook/priority/policy) and your own regular
chains (jump/goto targets).
*Why:* nft's model is good and learnable. Hiding it behind an abstraction means
re-learning a second, lossier model and fighting it at the edges. Mirroring it
means the YAML *is* documentation for the ruleset, and anyone who knows nft can
read it.
*Rejected:* a high-level "intent" DSL that generates chains for you — that's an
abstraction we'd forever be patching, and it hides the thing operators must
understand to debug a firewall.

### 1.2 No optimizer
We do **not** build an optimizing compiler (no auto set-vs-linear decisions, no
rule reordering, no auto-merging). The author decides structure.
*Why:* at homelab/small-fleet scale the optimizer earns nothing — sets only beat
linear matching in the low hundreds of entries, and east-west volume is owned by
the network fabric, not this. An optimizer is a large, bug-prone surface that
buys nothing here and removes the operator's control. Premature.
*Rejected:* an aerleon/capirca-style optimizing backend. Explicitly out of scope.

### 1.3 IR in the middle
YAML → **typed Python objects** (`Definitions`, `NamedSet`, `Chain`, `Table`,
`Flowtable`, rules via `RuleRenderer`) → text. Objects render themselves.
*Why:* keeps parsing, validation, and emission separable and testable; and it
makes a **second emitter** (JSON, §4) purely additive — the objects already
model the nft entities, so a JSON backend is "render differently," not "re-parse."
*Rejected:* templating YAML straight to text — untestable, and locks us to one
output format forever.

### 1.4 `raw:` is the escape hatch
Any rule can be `raw: "<verbatim nft>"`, and any table can carry a `raw:` block.
*Why:* this is what makes the project **tractable**. We ship the structured 80%
that's worth modelling; everything else is never *blocked* — it drops to `raw:`
until (if ever) it earns a structured key. We're never stuck, and we never have
to model the long tail to be useful.
*This is load-bearing.* Without it, every obscure nft feature becomes a release
blocker. With it, promotion to a key is an optimization, not a gate.

### 1.5 Explicit over magic / authored not auto
`ct state`, counters, conntrack, chains — only where the author writes them.
Nothing is injected behind their back.
*Why:* a firewall you can't fully predict from its source is a firewall you can't
trust. Surprises in generated rules are how you get lockouts and silent holes.

---

## 2. Schema decisions

### 2.1 Rule "form A" — structured mapping
A rule is a mapping of match keys + statement keys + a verdict
(`saddr`/`daddr`, `iif`/`oif`, `proto`/`dport`, `ct`, `counter`, `action`, …).
*Why:* readable, diffable, validatable; maps 1:1 to how you'd describe the rule
out loud. The `raw:` form coexists for the tail.

### 2.2 Services carry proto, emit a proto-agnostic set
A service is `80/tcp` etc., but a referenced service set renders as an
`inet_service` set of *ports*; the **rule** states the proto (`proto: tcp`).
*Why:* kills the **tcp/udp cross-product footgun** — you don't get a set
duplicated per-proto, and you can't accidentally open a UDP port because it
shared a name with a TCP one. Proto lives on the rule, where it belongs.

### 2.3 A definition becomes a named set only via a table's `sets:`
List a definition under a table's `sets:` and it's emitted as a **named set** and
referenced by `@name`; don't list it and the same reference **inlines** as an
anonymous `{ … }`. Per table, the author's call.
*Why:* named sets are worth it when reused or live-updated; inlining is clearer
for one-offs. The author chooses per table without changing the definition. (See
`test_per_table_set_named_vs_inline`: `wan` is named in `filter`, inline in `nat`.)

### 2.4 Named sets are single-family; rules are family-aware
A named set is one family; **mixed v4/v6 in one set is a `BuildError`** ("split
into `_v4`/`_v6`"). A rule renders **once per IP family** common to its address
matches; an inline mixed group expands to v4 + v6 lines; incompatible families
error.
*Why:* this **designs out Aerleon's "E2" silent-widen footgun**, where a
restriction could quietly disappear when families mixed. Here a restriction never
vanishes — you either get correct per-family rules or a loud error.

### 2.5 Deterministic output
Sorted emission, order-preserving dedupe (`list(dict.fromkeys(...))`).
*Why:* same input → byte-identical output. This is the **foundation of
git-diff-based change detection** in deployment (§ DEPLOYMENT.md): a `.nft` diff
means a *real* rule change, not reordering noise. Treat determinism as a
correctness property, not a nicety.

---

## 3. Composition (definitions, sites, includes)

### 3.1 nftgen owns composition — not Ansible vars
Composition is **nftgen's** job, done in its own files:
- **definitions** (`def/networks|services|interfaces`) — shared, defined once;
- **site overlay** (`sites/<site>.yaml`) — a host selects it with `site:`;
- **includes** (`policies/includes/*`) — shared rule/set fragments a host pulls in.
*Why:* nftgen's composition is **richer than Ansible's var layering** and avoids
Ansible's "lists get replaced, not merged" pain. Forcing the firewall config into
group_vars/host_vars would scatter one coherent ruleset and lose includes/site.
The systemd_networkd filter-plugin pattern works *there* because that config is a
flat per-interface dict; nftgen is not flat.
*Consequence:* nftgen integrates as a **generator that emits files**, not as a
vars-in Ansible filter. (See DEPLOYMENT.md.)

### 3.2 Site overlay = additive merge, collision is an error
`def/` is common; `sites/<site>.yaml` overlays it; a host picks one with `site:`.
Merge is additive; a key defined in both that *collides* is an error.
*Why:* per-site values (e.g. `local_users`) differ per location but the policy is
shared. Additive-with-collision-error keeps it predictable — no silent override.

### 3.3 Recursive definitions, cycle-guarded, deduped
Definitions can reference other definitions; expansion recurses with a `seen`
cycle guard and order-preserving dedupe.
*Why:* composable networks/services without infinite loops or duplicate elements.

### 3.4 Integration = two-play playbook, nftgen invoked as a CLI (not a plugin)
nftgen integrates with the sessrumnir collection as a **two-play playbook**: play
one runs `nftgen build <root>` on the controller (localhost) → `generated/
<host>.nft`; play two ships/validates/applies per host. nftgen is called as a
**CLI / standalone lib (shell out)**, not an in-process Ansible filter or lookup
plugin.
*Why:* one tested entry point shared by CLI, CI, and the role (§5.2); preserves
manual-path parity (DEPLOYMENT §7) and committed-render change detection
(DEPLOYMENT §4); avoids coupling nftgen into the collection's plugin path.
*Rejected:* the **filter-plugin-over-vars** pattern the `systemd_networkd` role
uses (`vars | compile_networkd`). That fits flat per-interface vars; nftgen reads
a **directory tree** with its own composition, so a `| filter` is the wrong mold
(§3.1 already rules out vars-in). A lookup plugin *could* read the directory
in-process, but it re-adds coupling for no gain over shelling out.

---

## 4. Output & primitives (Phase 6 forms)

These exist as structured keys; each was a small, independent add (the model
works — a new primitive is a local change).

- **Statements** are rule keys: `limit`, `quota`, `log`, `set-mark`, `set-mss`,
  `flow-offload`. They can be statement-only (no verdict), e.g. an MSS clamp.
- **Counters** — named, declared at table level (`counters: [..]`) and referenced
  by `counter: <name>`; or anonymous via `counter: true`.
  *Why named:* readable `nft list counter` output and stable identity across reloads.
- **Flowtables** — declared at table level (`flowtables:`), devices resolved from
  interface groups; rules opt in with `flow-offload: <ft>`.
- **vmaps** — inline verdict maps dispatching on `iif`/`oif`/`proto`
  (`_VMAP_KEYS`). *Inline only for now;* named/reusable maps are a TODO (§ below).
- **tcp-flags** — `flags:` is a list of `{match, mask}` clauses; expands and
  multiplies across the family loop. Default mask handling lives in the renderer.

### 4.1 JSON emitter (deferred, designed-for)
A second emitter on the same IR (libnftables JSON) is a TODO, not built. The IR
(§1.3) was shaped so it's additive. *Why deferred:* text output + `nft -c` covers
current needs; JSON earns its place when we want `nft -j` apply, round-tripping,
or live `add element`.

### 4.2 set-dscp deferred to `raw:`
DSCP is family-specific (`ip dscp set` vs `ip6 dscp set`), so it needs per-family
rendering like addresses. Until promoted, it lives in `raw:` (see gateway example,
`udp dport 5060 ip dscp set ef`). *Why:* don't ship a primitive that can silently
do the wrong thing across families — `raw:` is honest meanwhile.

---

## 5. Packaging & invocation

### 5.1 Point at a directory (convention), no config file yet
`nftgen build <root>` works by convention from a fixed layout
(`def/`, `sites/`, `policies/includes/`, `policies/hosts/`, output `generated/`).
CLI flags override individual paths.
*Why:* nftgen has ~nothing to configure beyond paths, and the paths are derivable
from the root. A config file whose only job is to repeat the layout is overhead.
*Rejected (for now):* an `aerleon.yml`-style config. Aerleon's was *optional* with
flag equivalents — we'll add an optional `nftgen.yml` **only when** there's
something to configure beyond paths (varying layout, or real settings like default
family / output format). YAGNI until then; `build()` takes resolved paths so a
config loader slots in front later with no refactor.

### 5.2 Importable package + CLI (single entry, `build()`)
nftgen stays an importable package (`from nftgen ... import generate` today;
`build(root) -> {host: text}` next). The CLI is a thin wrapper. The same `build()`
serves manual use, future CI, and the Ansible role.
*Why:* one tested entry point, three consumers. A bundled single-file /
`module_utils` form for Ansible is a *separate, optional* packaging step, not the
primary shape.

### 5.3 `build()` output is the deploy artifact (complete config, `flush ruleset`)
`nftgen build <root>` regenerates **all** hosts → `generated/<host>.nft`; a
`--host <name>` flag builds just one. Each file is a **complete, directly-
applyable config**: shebang + `flush ruleset` + the host's tables. It ships
verbatim as the target's `/etc/nftables.conf` (DEPLOYMENT §10, "Shape A").
*Why build-all:* generation is cheap + deterministic, and change-detection needs
every host regenerated to diff (DEPLOYMENT §4); `--host` is a manual-speed convenience.
*Why `flush ruleset`:* makes the file a complete replaceable unit — directly
`nft -f`-applyable, atomic, reapply-safe (the §5 reconcile). It does **not**
violate §1.5 "explicit over magic": it's the *deploy command's* artifact (that's
`build()`'s job), the flush is visible at the top of the output, and it injects no
firewall *rule* behind the author's back. The lower-level `generate()` (one
policy → text) stays flush-free for composition/embedding.
*Rejected:* a wrapper `nftables.conf` that `flush`+`include`s a flush-free file
(Shape B) — keeps output "purer" but breaks committed==on-box and adds
indirection for no gain.

---

## 6. Environmental notes (not decisions, but don't re-discover)

- `nft -c` **cannot run in this dev sandbox** (`netlink: cache initialization
  failed: Operation not permitted` — no_new_privs blocks the unprivileged check
  too). The 3 validation tests skip cleanly here; they light up on a real box.
  The failure is *environmental, not our syntax* (confirmed via nix-shell).
- The editor's "Missing property terms" / "Network Definition" warnings on
  nftgen YAML are VSCode mis-applying **Aerleon's** JSON schema. False positives;
  an nftgen schema (TODO) fixes them.

---

## Relationship to the earlier Aerleon fork
nftgen is a **clean-room, nftables-only** rebuild, not the fork. The Aerleon
nftables fork (`~/repo/aerleon`, tag `v1.16.0-nft.6`) was the exploration that
taught us what we wanted; nftgen keeps the good ideas (definitions model — hence
the NOTICE attribution) and drops the rest (multi-platform ACL model, optimizer,
silent family widening). Decisions here intentionally diverge from Aerleon where
its behavior was a footgun (§2.2, §2.4).
