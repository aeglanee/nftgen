# Working guidance for nftgen

Read this first. It captures the non-negotiable principles and how we work, so
contributors (human or agent) stay aligned. The *why* behind these is in
[DECISIONS.md](DECISIONS.md); the spec is [DESIGN.md](DESIGN.md).

## What nftgen is
A small, **nftables-only** firewall-as-code generator. YAML definitions + host
policies → a native `.nft` ruleset. It is a **generator/compiler**, not a
deployer — Ansible (later) ships and applies the output.

## Non-negotiable principles (guardrails)
1. **Mirror nftables; don't hide it.** The YAML's shape follows nft's real model
   (tables → chains → rules; sets; maps). You author your own chains.
2. **No optimizer. Explicit over magic.** What you write is what you get. No
   auto-generated chains, no inferred structure, no auto-injected rules.
3. **IR in the middle.** YAML → typed objects (`Table`/`Set`/`Chain`/`Rule`/…)
   → text. Never build output strings ad-hoc.
4. **`raw:` is the escape hatch** (per-rule and per-table). Nothing is ever
   blocked; un-promoted features go through `raw:` until they get a key.
5. **Deterministic output.** Same input → byte-identical output (sorted,
   order-preserving dedupe). This is load-bearing for git-diff-based change
   detection downstream — do not introduce nondeterministic ordering.
6. **Named sets are single-family.** Mixed v4/v6 in one named set is an error
   (split `_v4`/`_v6`). Rules are family-aware; a restriction never silently
   vanishes (no Aerleon-style "E2" widening).
7. **Authored, not auto.** `ct state`, counters, conntrack — only where the
   author writes them. Nothing injected behind their back.
8. **A definition becomes a named set only when listed in a table's `sets:`**;
   otherwise it inlines. Per table, the author's choice.
9. **The generated `.nft` is a render, never a source.** It may be committed for
   review, but it is never hand-edited; YAML is the single source of truth.

## How we work
- **Phase-by-phase, small commits.** One feature/increment per commit, each
  green. Adding a primitive should be a *local* change (a new rule key, a table
  object, or a rule type) — if it isn't, reconsider.
- **Test every increment.** Golden tests (`config → exact .nft`) + `nft -c`
  validation (auto-skips where nft is unusable). No increment without tests.
- **YAML examples are block-style** (no `{ }` flow mappings) — author preference.
- **Run tests:** `python -m pytest`. (Dev currently borrows the aerleon venv;
  its own venv is a TODO.)
- **License:** Apache-2.0 + NOTICE (definitions model adapted from Aerleon).

## Pointers
- Spec & schema: [DESIGN.md](DESIGN.md) · raw cookbook: [RAW.md](RAW.md)
- Decisions & rationale: [DECISIONS.md](DECISIONS.md)
- Deployment / Ansible / GitOps vision: [DEPLOYMENT.md](DEPLOYMENT.md)
- Plan & status: [PLAN.md](PLAN.md) · backlog: [TODO.md](TODO.md)

## Later (from sessrumnir)
Adopt sessrumnir's `AGENTS.md` conventions, pre-commit hooks, and lint/CI setup
when we wire nftgen toward the collection. Not yet.
