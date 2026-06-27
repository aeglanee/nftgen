# Progress

Durable orientation: where nftgen is, what's decided, what's next. The
conversation holds nuance; this holds the map. Update on milestones, not every
turn. Last updated: 2026-06-26.

## Status
- **Phases 0–6 done** — standalone generator works (defs → named sets →
  rules/chains → host→`.nft` + includes/site → `nft -c` → primitives A–E).
- **Step 1 (review) done** — see [step1-review.md](step1-review.md): coverage
  map, test audit, a real `nft -c` path.
- **Two bugs found via real `nft -c` and fixed:** `quota gbytes→mbytes`;
  `dnat`/`snat` family-qualified for `inet` tables.
- **`validate.py`** runs `nft -c` under `unshare -rn` when direct netlink is
  blocked → goldens validate wherever `nft` is on PATH (85 pass / 0 skipped with
  nft available; 81 + 4 skipped without).

## Decided
- **nftgen ↔ sessrumnir are decoupled.** nftgen replaces the existing nftables
  role's *generation* (the hand-written common/site/host fragment globbing); the
  role keeps the ship/validate/apply half.
- **nftgen owns composition; emits ONE complete `.nft` per host** — not Ansible
  vars, not on-target fragment assembly. (DECISIONS §3.1.)
- **Integration = two-play playbook:** play 1 (localhost) `nftgen build <root>`
  generates; play 2 ships/validates/applies per host. nftgen is invoked as a
  **CLI (shell out)**, not an in-process filter/lookup plugin. (DECISIONS §3.4.)
- **Deploy artifact = Shape A:** the build output *is* `/etc/nftables.conf` —
  shebang + `flush ruleset` + tables, shipped verbatim. `build()` regenerates all
  hosts; `--host` builds one. (DECISIONS §5.3, DEPLOYMENT §10.1.)
- **Targeting:** naming contract `inventory_hostname == policies/hosts/<name>.yaml
  == generated/<name>.nft` (exact). Build all once (`run_once`+`delegate_to:
  localhost`); `--limit` narrows *apply* only. (DEPLOYMENT §10.2.)
- **Apply = apply-to-live → confirm → persist**, with a `systemd-run` dead-man
  revert, `serial: 1`, reconnect-confirm. (DEPLOYMENT §10.3.)

## Design phase: complete
Integration design settled (#1–#4). The render reference is
[capabilities.md](capabilities.md). Next is **implementation** — Step 2 below.

## Parked (revisit when wiring CI — does NOT affect generation)
- **CI / change-detection.** Two-diff model agreed: **verify** (regenerate at
  HEAD, assert `== committed`) + **apply set** (`git diff <last-applied>..HEAD --
  generated/` → changed `.nft` = hosts). **Leaning model B** (CI regenerates →
  commits to the *PR branch* → reviewed → apply the changed set), so a YAML-only
  edit lets CI handle generation while the `.nft` is still reviewed pre-merge.
  Deferred: pure orchestration, no effect on generated output. (DEPLOYMENT §3–5.)

## Implementation backlog (after the design)
Step 2 `build()` (incl. `flush ruleset` + `--host`) · Step 3 the apply role
(rollback sequence) · Step 4 molecule/behavioral in sessrumnir. See [../PLAN.md](../PLAN.md).

## Sequencing (user priority)
Nail nftgen functionality + verify correct nftables **first** (Step 2), **then**
integrate the role (Step 3), **then** molecule/behavioral tests in sessrumnir
(Step 4). Full plan: [../PLAN.md](../PLAN.md).
