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

## Interaction style

- **Concise.** Short responses by default. No padding, no recap of what was just done.
- **One problem at a time.** When the user raises multiple distinct problems in a message, list them, address the first, and explicitly note the others as pending. Don't fork the dialogue across all of them at once.
- **Stay focused.** Don't introduce unrelated topics. Critical pushback on the *current* topic is in scope; tangents into adjacent areas are not.
- **Ask before guessing.** If context is missing, ask for it. Don't invent a plausible answer.
- **Granular when the user has to act.** When asking the user to perform an action (run a command, paste output, etc.), give one step, wait for the result, then give the next. Don't pre-list sequential steps whose later content depends on earlier output.
- **Research before coding or troubleshooting.** For specific APIs, libraries, or version-dependent behavior involved in a code proposal or fix, consult current documentation rather than asserting from training. Cite what you consulted.
- **Theory pacing: one topic per turn, back-and-forth.** For theory or design discussions, lead each turn with a header — topics queued, current, pending — and cover only the current topic. Let the user drive depth via follow-ups rather than dumping comprehensive walkthroughs. Comprehensive dumps drown information; small focused turns let the user dive deeper on what matters. Coding/mechanical turns may be denser when steps are clear.
- **Drive next-step proposals with reasoning.** At the end of any turn where work was done, propose the next step explicitly with a one-line rationale — not just "what next?" Give a concrete recommendation; the user can override.
- **Flag when we're out of order.** If a topic comes up that depends on a not-yet-made earlier decision (e.g., picking an ECS before defining the subsystem list), surface the dependency and recommend going up a level rather than drilling in.
- **Maintain the progress tracker.** Treat [`docs/progress.md`](docs/progress.md) as the durable picture of where the project is. Update on milestones (ADR accepted, subsystem skeleton landed, phase complete) — not on every turn. Conversation log holds nuance; the tracker holds orientation.
- **Discuss, agree, then capture.** Settle a design in conversation before writing it to docs. Don't edit-as-you-go — premature captures create rework when the design shifts, and the tool-call churn makes the chat hard to follow. Batch the write once we agree.
- **Step back when a topic closes.** On finishing a topic, zoom out: does what we just built fit the overall design, stay consistent with the other parts, and actually work together? Surface integration gaps, contradictions, or stale docs *before* moving on — a locally-good decision can quietly break the global picture. Don't wait to be asked.

## Docs map (how the docs are structured)

Root-level Markdown = the durable, reviewed record. `docs/` = focused
findings/proposals. Each has one job — don't duplicate across them:

- **[DESIGN.md](DESIGN.md)** — the spec: the YAML schema and what it renders to.
- **[DECISIONS.md](DECISIONS.md)** — *why* it's built this way; rationale +
  rejected alternatives + environmental notes. Read before changing a design choice.
- **[RAW.md](RAW.md)** — the `raw:` escape-hatch cookbook.
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — the Ansible/GitOps target end-state (not built).
- **[PLAN.md](PLAN.md)** — the ordered plan + current status. **[TODO.md](TODO.md)** — à-la-carte backlog.
- **[docs/](docs/)** — findings & proposals, one topic per file:
  - [docs/progress.md](docs/progress.md) — **the orientation tracker** (status,
    decided, open agenda). Read this first to see where we are.
  - [docs/capabilities.md](docs/capabilities.md) — the render reference: what
    nftgen turns YAML into (structured / raw-only / can't-express / promotion queue).
  - [docs/best-practices.md](docs/best-practices.md) — the cookbook: base-chain
    hygiene + matching patterns (independent/cartesian vs paired/concatenation), YAML→nft.
  - [docs/sets-and-performance.md](docs/sets-and-performance.md) — nftables sets
    background: hash vs interval(tree), the complexity math, how to define for perf.
  - [docs/automation/](docs/automation/) — what nftgen derives vs leaves to you,
    each as define→generate + defaults + overrides (A set-type done; B–D pending).
  - [docs/step1-review.md](docs/step1-review.md) — coverage map, test audit,
    the `nft -c` recipe, and the bugs it found.
  - [docs/concatenations.md](docs/concatenations.md) — the concatenation-set design proposal (why).
  - [docs/concat-authoring.md](docs/concat-authoring.md) — concatenation tuple-authoring options + recommendation (decision pending).

When you produce a substantial review/finding, add a `docs/<topic>.md` and link
it here so the structure stays discoverable.

## nft -c on this dev box (no VM needed)

`nft` is in `/nix/store/*-nftables-*/bin/nft`; plain `nft -c` fails here
(`NoNewPrivs` blocks netlink), but `unshare -rn <nft> -c -f <file>` validates
correctly. See [docs/step1-review.md](docs/step1-review.md) §Deliverable 3.

## Later (from sessrumnir)
Adopt sessrumnir's `AGENTS.md` conventions, pre-commit hooks, and lint/CI setup
when we wire nftgen toward the collection. Not yet.
