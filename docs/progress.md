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

## Open agenda (discuss in this order)
1. **Import mechanics** — how play 1 builds *one* host; the `build()` API +
   directory convention (PLAN Step 2).
2. **Apply mechanics** — how play 2 limits to one host (`--limit`), ships the
   committed `.nft`, on-target `nft -c`, **timed rollback** (DEPLOYMENT §6).
3. **CI / change-detection** — regenerate all, diff committed `.nft`, apply the
   changed hosts; `committed == render` gate (DEPLOYMENT §3–5).
4. **Capability reference** — a full table: render / can't-render yet / TODO.
5. **`flush ruleset`** — should nftgen emit it so the file is directly
   `nft -f`-applyable and reapply-safe? (recommended, not ratified.)

## Sequencing (user priority)
Nail nftgen functionality + verify correct nftables **first** (Step 2), **then**
integrate the role (Step 3), **then** molecule/behavioral tests in sessrumnir
(Step 4). Full plan: [../PLAN.md](../PLAN.md).
