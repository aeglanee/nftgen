# Working guidance for nftgen

Read this first. Behavior — communication, agent delegation, design and
implementation workflow, git and docs discipline — is defined in
[.claude/CLAUDE.md](.claude/CLAUDE.md); this file adds the nftgen specifics.
The *why* behind design choices is in [DECISIONS.md](DECISIONS.md); the spec
is [DESIGN.md](DESIGN.md).

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

## How we work here (repo specifics)

- **Phase-by-phase, small commits.** One feature/increment per commit, each
  green. Adding a primitive should be a *local* change (a new rule key, a table
  object, or a rule type) — if it isn't, reconsider.
- **Test every increment.** Golden tests (`config → exact .nft`) + `nft -c`
  validation (auto-skips where nft is unusable) + behavioral netns tests where
  traffic semantics are in question. No increment without tests.
- **YAML examples are block-style** (no `{ }` flow mappings) — author
  preference.
- **Setup:** `make install-dev` — own `.venv`, nftgen editable +
  ruff/yamllint/pre-commit, git hook wired.
- **Checks:** `make verify` (lint + tests) must be green before every
  commit. Individually: `make lint`, `make test`, `make format`;
  `pytest tests/test_foo.py -v` for one file (venv on PATH via make, or
  activate it). `make lint-trunk` is an optional breadth sweep
  (shellcheck/shfmt/taplo/trufflehog/checkov via the trunk CLI) — not
  part of the gate.
- **Keep the status docs current.** [`CHANGELOG.md`](CHANGELOG.md) records
  each release (and the unreleased `main`); [`TODO.md`](TODO.md) is the one
  backlog. Update them when a change lands, not on every turn.
- **Best practices are a deliverable.** nftables best practices discovered
  during work are captured in [docs/best-practices.md](docs/best-practices.md),
  [docs/sets-and-performance.md](docs/sets-and-performance.md), or
  [docs/maps.md](docs/maps.md) with verified nft examples — writing these out
  is an explicit project goal, even where it's beyond nftgen's code scope.
- **License:** MIT (definitions model reimplements Aerleon concepts clean-room;
  acknowledged in README, no Aerleon code used).

## Docs map (how the docs are structured)

Root-level Markdown = the durable, reviewed record. `docs/` = focused
findings/proposals. Each has one job — don't duplicate across them:

- **[DESIGN.md](DESIGN.md)** — the reference: layout, every YAML key and what
  it renders to, what nftgen derives, what fails the build, known limits.
- **[DECISIONS.md](DECISIONS.md)** — *why* it's built this way; rationale +
  rejected alternatives + environmental notes. Read before changing a
  design choice.
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — the Ansible/GitOps target end-state
  (not built).
- **[CHANGELOG.md](CHANGELOG.md)** — what shipped, per release.
  **[TODO.md](TODO.md)** — the one backlog (open items only).
- **[docs/](docs/)** — findings & proposals, one topic per file:
  - [docs/authoring.md](docs/authoring.md) — **the hub**: firewall structure,
    the add-a-rule workflow, and the pick-the-right-tool decision table
    (sets/vmap/concat/map/jump/meter/pipapo); links the deep-dives.
  - [docs/raw.md](docs/raw.md) — the `raw:` cookbook: verified recipes for
    features without a key yet.
  - [docs/best-practices.md](docs/best-practices.md) — the cookbook: base-chain
    hygiene + matching patterns (independent/cartesian vs
    paired/concatenation), YAML→nft.
  - [docs/sets-and-performance.md](docs/sets-and-performance.md) — nftables sets
    background: hash vs interval(tree), the complexity math, how to define
    for perf.
  - [docs/maps.md](docs/maps.md) — nftables maps: verdict maps (dispatch) vs
    data maps (dnat targets), inline vs named, each as verified nft code
    blocks.
  - [docs/testing-plan.md](docs/testing-plan.md) — the behavioral (netns) test
    matrix: primitive semantics B01–B26 + the [example-fleet/](example-fleet/)
    reachability truth table P01–P22; harness design + execution order.
  - [docs/review-2026-10.md](docs/review-2026-10.md) — **the 2026-10
    review working list**: findings (C/D/E), agreed decisions, where we
    are, and the user's working preferences. Resume work here.
  - [docs/concatenations.md](docs/concatenations.md) — the concatenation-set
    design proposal (why).
  - [docs/concat-authoring.md](docs/concat-authoring.md) — concatenation
    tuple-authoring options (decided + built: Option 1, `concat:`/`tuples:`).
  - [docs/reference-fleet.md](docs/reference-fleet.md) — design record for
    [example-fleet/](example-fleet/), the realistic 3-site reference
    (opinionated skeleton, sets/vmap composition, dual-stack hygiene).

When you produce a substantial review/finding, add a `docs/<topic>.md` and link
it here so the structure stays discoverable.

## nft -c on this dev box (no VM needed)

`nft` is in `/nix/store/*-nftables-*/bin/nft`; plain `nft -c` fails here
(`NoNewPrivs` blocks netlink), but `unshare -rn <nft> -c -f <file>` validates
correctly (`validate.py` does this automatically).

## Later (from sessrumnir)

Adopt sessrumnir's `AGENTS.md` conventions and CI wiring when we wire nftgen
toward the collection. (Pre-commit hooks + the lint suite are already
adopted, mirroring sessrumnir main.)
