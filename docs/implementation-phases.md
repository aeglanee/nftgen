# nftgen — implementation phases for the policy layer (draft)

Status: draft — companion to [policy-design.md](policy-design.md), itself
not yet discussed or agreed. Not linked from the docs map or
TODO.md/PLAN.md until that design is reviewed.

Executable phase plan for [policy-design.md](policy-design.md). Each
phase is sized for one working session, ends with the full test suite
green, and is independently useful. The consuming Ansible collection's
phases (S1–S8) live in
`sessrumnir:docs/discussion/nftgen-zone-policy-plan.md` and depend on
the tags cut here.

Ground rules for every phase:

- Tests first-class: unit tests on renderer output strings, golden
  `.nft` files (`tests/golden/`), and the `nft -c` gated checks
  (`validate.can_check()` skip pattern) — extend all three where the
  phase touches output.
- `python -m pytest` green before and after; goldens updated
  deliberately (review the diff, never regenerate blindly).
- DESIGN.md/RAW.md get a one-line "now structured" note whenever a
  `raw:` recipe is promoted.

## Dependency graph

```text
N1  N2  N3  N4        (independent of each other)
  \  |  |  /
     N5  ── tag v0.4.0
     |
     N6 ─ N7 ─ N8 ── tag v0.5.0
```

## N1 — concat matches + concat-typed named sets

The known blocker (absorbed from the retired `CLAUDE-WEB-PROBLEM?.md`
finding): structured rules can only emit independent matches
(`ip daddr @set tcp dport 5432` — cartesian), not paired lookups
(`ip daddr . tcp dport @svc_pairs`).

- Rule schema: `- match: [daddr, {dport: tcp}]` (ordered field list) +
  `set: <name>` + `action:`. Field tokens reuse the existing match
  vocabulary; share one key→expression table between `_vmap()` and the
  new `_concat()` (`nftgen/rules.py`, `RuleRenderer.render()`).
- Set construction: when `set:` names a concat set, derive
  `type` from the ordered match fields (`daddr` → `ipv4_addr`/
  `ipv6_addr` via the `_classify_family` split; `{dport: tcp}` →
  `inet_service`) and elements from a paired-tuple definitions form
  (`nftgen/ir.py` `build_sets` + new `_concat_set_from_definition`;
  `nftgen/definitions.py` gains the paired-tuple group form).
- Family handling: address fields resolving to both families emit
  per-family sets + rules (`_v4`/`_v6`), mirroring the existing
  family-iteration loop.
- Validation: match field order must equal set key order; element arity
  must match; mixing a concat `set:` with sibling independent match
  keys on one rule is a `BuildError`.
- Tests: unit (render strings, each validation error), golden with a
  concat leaf, `nft -c` gated.

## N2 — table-level named maps + vmap-by-reference

- `maps:` section on tables: name, key type (including concat keys like
  `ifname . ifname`), value type (`verdict` or data), elements
  (including `goto <chain>` verdicts). New `Map` IR class parallel to
  `NamedSet` (`nftgen/ir.py`).
- Rule form `- vmap: {key: [iif, oif], map: <name>}` — `key` becomes a
  list (single-key stays back-compatible); references a declared map
  instead of inlining (`nftgen/rules.py` `_vmap()`).
- Tests: unit + golden (a dispatch map with goto verdicts), `nft -c`.

## N3 — NAT correctness + redirect

`dnat:`/`snat:` render today but are untested and family-broken inside
inet tables.

- Family-qualified forms: `dnat ip to` / `dnat ip6 to` (and snat) are
  mandatory inside `family: inet` tables; render per target family.
- `redirect` action (optional `to :port`).
- First real tests for dnat/snat/masquerade/redirect: unit + a NAT
  golden + `nft -c` (this catches the bare-`dnat to` failure).
- Touch: `nftgen/rules.py` `_verdict()`.

## N4 — statement gaps

- `set-dscp:` structured, rendered per family (`ip dscp set` /
  `ip6 dscp set`) — currently raw-only.
- `ct mark` (set + match) and additional meta matches (`mark`,
  `pkttype`) per TODO.
- Touch: `nftgen/rules.py` statements block; tests as above.
- (`set-mss: pmtu` already exists — Phase 6A; do not redo.)

## N5 — `generate_from_data` + tag v0.4.0

- Refactor `nftgen/generate.py`: extract the data core;
  `generate_from_data(policy, definitions) -> str` (dicts in, no
  filesystem, `include:` → `BuildError`); `generate()` becomes the
  file-loading wrapper with an unchanged signature; CLI untouched.
- `definitions` accepts a mapping, a sequence of mappings (merged in
  order — the Ansible common/site/host triple), or a `Definitions`.
- Tests: file-path vs dict-path equivalence on the existing examples;
  include-rejection; merged-sequence semantics.
- Update README status line (stale "Phase 0"). Tag **v0.4.0**.

## N6 — policy compiler: zones + forward

- `nftgen/policy/schema.py`: validate `zones:` definitions (interfaces
  required, reserved names `local`/`any`), `policy.options`, `forward:`
  sections and terms; every unknown token/zone/field a `BuildError`
  naming section + term. `PORT_PROTO` literal resolution (`80_tcp`).
- `nftgen/policy/compiler.py`: `compile_policy(doc, defs) -> dict`
  emitting the POLICY-DESIGN output contract for `forward:` — filter
  table, forward base chain skeleton (est/related accept, invalid
  drop), dispatch (vmap default; ladder/index knobs), `{from}_to_{to}`
  leaves, term rendering incl. concat sets (`p_{leaf}_{term}`),
  `generate` routing when `policy:` present, `tables:` merge with
  collision errors, `--emit-mirror` CLI flag.
- Tests: schema-error units (message quality asserted), compiler units
  on the lowered dict (stable, refactor-friendly), golden for a
  two-zone router, `nft -c`.

## N7 — input/output/local, simple-host mode, flowtable, anti-spoof, ICMPv6-ND

- `input:` (implicit `to: local`, `from: any` support, `in_{zone}`
  leaves, single-key dispatch), `output:` (optional; absent → policy
  accept), lo accept in input skeleton.
- Simple-host mode golden (input-only, no zones).
- `options.flowtable` → mirror flowtables + `flow add` placement.
- Anti-spoof knob (zones with `networks:`); `BuildError` without them.
- `icmpv6_nd: auto|off` with the `# icmpv6_nd: auto` provenance comment.
- ICMP named-type table (v4/v6).
- Tests: goldens for router-with-input+flowtable and simple host;
  anti-spoof + ND units.

## N8 — `nat:` + `mangle:` sections; reference golden; tag v0.5.0

- `nat.snat` (masquerade | snat addr, from/to zone scoping) →
  postrouting; `nat.dnat` (in-zone + forwards list) → prerouting with
  family-qualified targets (N3).
- `mangle:` zone-pair terms (`set-mss pmtu`, `set-dscp`, `set-mark`) →
  priority-mangle forward chain.
- The **reference router golden**: dual-stack, 3+ zones, forward+input
  policies, DNAT + masquerade, mangle, flowtable, anti-spoof, the
  `allow_web_servers_to_internet` named-list example — this golden is
  the compatibility contract for downstream (sessrumnir molecule
  asserts against the same structures).
- Example tree: add `example/policies/hosts/` policy-layer hosts
  mirroring the golden; update README usage.
- Tag **v0.5.0**.

## Deferred (tracked in TODO.md)

JSON emitter on the IR, JSON schema for editors, nflog logging knob,
Vagrant behavioral harness, own CI venv, `dispatch: index` performance
measurements.
