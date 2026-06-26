# Plan & status

The agreed order of work from here. Rationale and decisions live in
[DECISIONS.md](DECISIONS.md); the deployment end-state in [DEPLOYMENT.md](DEPLOYMENT.md).

---

## ⟶ Resuming in a fresh nftgen session (start here)
This plan was written while the working session was still rooted in the *aerleon*
repo (the build happened cross-repo). The intended next move is to **root a
Claude session in this repo** so `CLAUDE.md` auto-loads and history files here.
To resume: read [CLAUDE.md](CLAUDE.md) + this file. **Step 1 is done** — its
output is [docs/step1-review.md](docs/step1-review.md); pick up the open items below.

**Step 1 outcome (2026-06-26) — see [docs/step1-review.md](docs/step1-review.md):**

- All three artifacts produced: coverage map, test audit, `nft -c` path.
- **Confidence gap resolved:** `nft -c` *does* run on this dev box via
  `unshare -rn <nft> -c -f` (no VM needed). Running it immediately found **two
  invalid-nft strings the suite had pinned green**, both now **fixed**:
  `quota … gbytes` and `dnat to …` in `inet` tables (family qualifier inferred
  from the target). All three goldens now pass `nft -c`.
- **Open question answered:** no real ruleset to port; we sketched a multi-zone
  VLAN router as the intent benchmark. Top gap ranked by real use:
  **concatenations**, then `reject with` / `icmp type`.
- **Open items from Step 1:** (a) fix the dnat-in-inet bug + add a dnat golden
  through `nft -c`; (b) wire the `unshare` fallback into `validate.py` and
  parametrize the nft-check over *all* hosts (not just router1/router2).

## Status
- **Done:** Phases 0–6 — skeleton → definitions → named sets → rules/chains →
  host→`.nft` + includes + site overlay → `nft -c` validation → primitives A–E
  (statements, counters, flowtables, vmaps, tcp-flags). **80 passed, 3 skipped**
  (the 3 are `nft -c` tests that skip in this sandbox; they run on a real box).
- **Standalone generator works.** No Ansible/CI integration exists yet.

## The plan

### Step 1 — Walkthrough + critical structure review  ✓ done → [docs/step1-review.md](docs/step1-review.md)
Module by module (`definitions → ir → rules → generate → validate → cli`): what
it does, how it fits, what's solid, what to change. **Three concrete deliverables**
(not just discussion):

1. **Capability/coverage map** — a flat table: *generates structured* /
   *works via `raw:`* / *can't express yet*. This is the "what can/can't we
   generate" overview, and it scopes feature work to actual gaps (not speculation).
2. **Critical test audit** — per test, is it a real correctness check or a
   self-referential golden pin? (Most are pins — fine for regression, but they do
   **not** prove the nft is valid; `nft -c` is the real gate and it skips here.)
3. **Real `nft -c` validation path** — get nft actually checking on a box/VM and
   validate every golden through it. Highest-value confidence jump.

*Why first:* you want to understand it; a critical review is cheapest **before**
we extend it under a role + CI + new features; it's the "get into better shape"
prerequisite. Mostly discussion + the three artifacts, maybe tiny fixes.

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

## Sequencing (resolved)
nftgen and sessrumnir are **decoupled** — the integration contract is just the
`build(<dir>) → {host: .nft}` API + the `.nft` file format. So:

- **Cleanup + a stable `build()` seam (Steps 1–2): finish before integrating.**
  The role and behavioral tests build on that API/format; don't let it churn under
  them. This is the genuine prerequisite — *not* "all features."
- **Feature extras (Step 5): do NOT gate integration on them.** A new rule key
  changes *what's in* a `.nft`, not *how the role deploys one* — they're
  decoupled. Add à la carte; you'll learn which you need by porting a real ruleset.
- **Testing splits:** unit/golden is continuous; **behavioral/Molecule comes
  *with* the role**, not before — you can't Molecule-test a role that doesn't
  exist. So "proper testing" in the behavioral sense is part of integration.
- **Prove a thin end-to-end slice early** (build one host → minimal role → apply
  on one VM → rollback) once the seam is stable, to de-risk the pipeline before
  deepening features.

## Later (not in this plan yet)
Adopt sessrumnir conventions (`AGENTS.md`, pre-commit hooks, lint/CI), the GitOps
controller mechanics (CI triggers, reconcile cron), and the nftgen JSON schema for
editor support. See DEPLOYMENT.md and TODO.md.
