# Progress

Durable orientation: where nftgen is, what's decided, what's next. The
conversation holds nuance; this holds the map. Update on milestones, not every
turn. Last updated: 2026-07-09.

## Status

- **Phases 0–6 done** — standalone generator works (defs → named sets →
  rules/chains → host→`.nft` + includes/site → `nft -c` → primitives A–E).
- **Step 1 (review) done** — see [step1-review.md](step1-review.md): coverage
  map, test audit, a real `nft -c` path.
- **Two bugs found via real `nft -c` and fixed:** `quota gbytes→mbytes`;
  `dnat`/`snat` family-qualified for `inet` tables.
- **`validate.py`** runs `nft -c` under `unshare -rn` when direct netlink is
  blocked → goldens validate wherever `nft` is on PATH (88 pass / 0 skipped with
  nft available; 84 + 4 skipped without).
- **Strict rule-key validation shipped** (#1 safety) — unknown rule keys are a
  `BuildError`, so a typo can't silently weaken a rule. See [TODO.md](../TODO.md).
- **`build(<root>)` + `flush` + `--host`** (Step 2 core) — fleet deploy artifacts.
- **Feature round shipped:** concatenations, inline dnat data map, `mark`
  (read+write), `icmp type`; examples migrated stale `raw:` → structured
  (`flags`/`set-mss`). Suite **117** (real `nft -c` gated).
- **JSON emitter: experimented, then shelved on branch `json-emitter`.** POC
  emits + validates via `nft -j -c`, but it's a *parallel* re-implementation (the
  text IR holds strings, not structured data) and `raw:` has no JSON form.
  Defer until the apply pipeline wants `nft -j` / drift detection. See
  [maps.md](maps.md)/the branch.
- **Reference docs written:** [capabilities.md](capabilities.md) (render ref),
  [best-practices.md](best-practices.md) (cookbook), [sets-and-performance.md](sets-and-performance.md),
  [maps.md](maps.md), and the [automation/](automation/) directory (A–D + not-automated).
- **`def/` → `definitions/`** (all-full names) + **recursive load** (organise
  definitions into subdirs). Layout pinned in DESIGN §Project layout.
- **vmap built out** — keys `iif`/`oif`/`proto`/`dport`/`sport`/`mark`/`state`/
  `saddr`/`daddr` + **concatenated** keys (`key: [iif, oif]`), with group/service
  resolution and single-family addresses. See [maps.md](maps.md).
- **Integration Step 3a done (in sessrumnir)** — the `nftables` role
  rewritten to ship one nftgen-built `.nft` per host (`feat!`), a two-play
  example playbook, and a realistic `gw1a`/`gw1b`/`gw2` fleet + baseline
  scrub/zone includes — all
  `nft -c` clean. nftgen consumed as a pinned dependency.
- **v0.2.0 released (2026-07-05): the strict authoring surface.** A critical
  review probed what `nft -c` *cannot* catch (empty rulesets, dead `iifname { }`
  rules, literal-typo'd interfaces, type-mismatched set refs — all pass!) and
  closed every hole: unknown keys/names error at every level, empty groups
  error at use, type-aware chain policy defaults, loud `--check`, clean CLI
  errors, cycle paths named. **153 tests**; TODO.md §Safety has the list.
- **R0 done (2026-07-05):** v0.2.0 pushed + tagged; sessrumnir branch rebased
  onto main 0.7.0, pin bumped and verified installing from the tag; molecule
  docker-nftables + ansible-lint + yamllint green. The R0–R7 roadmap
  (behavioral tests → CI → rollback apply → enterprise convergence) is in
  [../PLAN.md](../PLAN.md) §Roadmap — the authoritative TODO.
- **R1 specced + fixture built (2026-07-05):** behavioral test matrix in
  [testing-plan.md](testing-plan.md) (B01–B26 primitive semantics, P01–P20
  PoC reachability truth table, netns harness design); showcase fixture
  [../example-poc/](../example-poc/) — a two-site best-practice router pair
  (zone vmaps incl. `[iif, oif]` pair dispatch, dport service dispatch, dnat
  data map, concat paired-flows set, live blocklist, site overlays with
  divergent sites, static-snat vs masquerade) — README-narrated, `nft -c`
  clean, drift-pinned. Bare `dnat:`/`snat:` targets now resolve
  single-address network groups (per-site NAT address behind a shared name).
- **Netns harness live (2026-07-05):** `tests/behavioral/` — agent as root
  inside `unshare -r -n`, per-zone anonymous namespaces (holder pids +
  `setns`), veth topology, applies the *real deploy artifact*, TCP probes
  that distinguish connected/refused/timeout (self-validated). B01–B03 pass
  in ~5s, rootless; suite **164**. Layer 4 exists — next is filling the
  matrix (B04+) and the PoC truth table (P01–P20).
- **v0.3.0 released (2026-07-05):** large set/map literals wrap
  one-per-line (diff-stable artifacts); example-poc names its fleet groups.
  Suite **166**. sessrumnir pin bumped to v0.3.0 on its branch.
- **Dev tooling adopted (2026-07-09), mirroring sessrumnir main:** own
  `.venv` via `make install-dev` (R2's venv half, done early), ruff
  (incl. flake8-bandit `S`), yamllint (flow mappings forbidden —
  enforces the block-style rule), markdownlint at 80 cols, gitleaks,
  all SHA-pinned in pre-commit; `make verify` = lint + tests, green
  gate for every commit. Tree conformed (one real bug: DESIGN.md's
  priority table row split by unescaped pipes). Working agreement split:
  behavior/workflow layer in `.claude/CLAUDE.md`, repo layer in
  `CLAUDE.md`. The stray `origin/dev` branch was dispositioned: its two
  policy-layer draft docs imported (below), the rest superseded or
  discarded.
- **Policy-layer drafts imported, pending review:**
  [policy-design.md](policy-design.md) (opt-in typed zones/policies
  compiling to the mirror layer) + [implementation-phases.md](implementation-phases.md)
  (N1–N8). Self-described drafts — deliberately *not* linked from the
  docs map until discussed. Caveat for that review: N1's premise (no
  structured paired lookups) predates the shipped `concat:`/`tuples:`/`set:`
  surface — re-verify; the [concat-authoring.md](concat-authoring.md)
  decision itself is closed (Option 1, built).
- **⟶ Next:** §1 matrix breadth (B04+), then the P-matrix over
  example-poc, then R2 CI (venv half already done). PLAN §Roadmap.

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

- [x] **Step 2 `build(<root>)`** — fleet generation + `flush ruleset` deploy
      artifact + `--host` + `nftgen build` CLI. Deploy artifacts pass real
      `nft -c`.
- [x] **Concatenation** (#1 feature, done) — structured `concat:`/`tuples:`
      set + `set:` rule; nft-c verified. See
      [concat-authoring.md](concat-authoring.md).
- [x] **Step 3a — role rewrite** (sessrumnir): ships nftgen output, two-play
      example, `gw` fleet, baseline includes. Done.
- [ ] **Step 3b apply role** (rollback sequence) · **Step 4 molecule** (deploy a
      host end-to-end) in sessrumnir. See [../PLAN.md](../PLAN.md).

## Sequencing (user priority)

Nail nftgen functionality + verify correct nftables **first** (Step 2), **then**
integrate the role (Step 3), **then** molecule/behavioral tests in sessrumnir
(Step 4). Full plan: [../PLAN.md](../PLAN.md).
