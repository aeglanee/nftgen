# Plan & status

The agreed order of work from here. Rationale and decisions live in
[DECISIONS.md](DECISIONS.md); the deployment end-state in [DEPLOYMENT.md](DEPLOYMENT.md).

## Status
- **Done:** Phases 0–6 — skeleton → definitions → named sets → rules/chains →
  host→`.nft` + includes + site overlay → `nft -c` validation → primitives A–E
  (statements, counters, flowtables, vmaps, tcp-flags). **80 passed, 3 skipped**
  (the 3 are `nft -c` tests that skip in this sandbox; they run on a real box).
- **Standalone generator works.** No Ansible/CI integration exists yet.

## The plan

### Step 1 — Walkthrough + critical structure review  ⟵ next
Module by module (`definitions → ir → rules → generate → validate → cli`): what
it does, how it fits, what's solid, what to change. Output: shared understanding
+ a concrete cleanup/decision list (incl. the packaging/import shape).
*Why first:* you want to understand it; a critical review is cheapest **before**
we extend it under a role + CI + new features; it's the "get into better shape"
prerequisite. Mostly discussion, maybe tiny fixes.

### Step 2 — Cleanups + `build(<dir>)` + packaging decision
Apply the review's cleanups; add the fleet mode
(`build(root) -> {host: nft}` + `nftgen build <dir>` CLI, convention-based per
DECISIONS.md §5.1); settle the import/single-file question (default: importable
package; optional bundled form for Ansible is separate). Tests for `build()`.

### Step 3 — Ansible role + manual apply
Thin role: ship `generated/<host>.nft` → `nft -c -f` on target → apply with timed
rollback. Manually runnable (`ansible-playbook nftables.yml --limit <host>`). No
CI required. (Decoupled: role deploys files; nftgen makes them — DEPLOYMENT.md §2.)

### Step 4 — Proper testing
Own venv; CI (pytest goldens + `nft -c`); a **Molecule scenario** that applies the
role on a VM/container and probes with testinfra (the behavioral layer).
*Note:* we golden-test every increment along the way regardless — this step is the
**infra + behavioral** layer, which needs the role (Step 3) to exist.

### Step 5 — Feature extras (à la carte, as wanted)
Promote remaining `raw:` recipes and add output formats — each a small,
independent add like Phase 6 A–E. See [TODO.md](TODO.md): `set-dscp` (family-aware),
concatenations, named/reusable maps, more meta matches, the JSON emitter.

## Open question (to answer after this doc)
Do cleanup + extra features + testing get **fully** finished before we even start
the sessrumnir integration, or do we interleave? (Discussed separately.)

## Later (not in this plan yet)
Adopt sessrumnir conventions (`AGENTS.md`, pre-commit hooks, lint/CI), the GitOps
controller mechanics (CI triggers, reconcile cron), and the nftgen JSON schema for
editor support. See DEPLOYMENT.md and TODO.md.
