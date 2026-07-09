# Plan & status

The agreed order of work from here. Rationale and decisions live in
[DECISIONS.md](DECISIONS.md); the deployment end-state in [DEPLOYMENT.md](DEPLOYMENT.md).

---

**Step 1 outcome (2026-06-26, historical) — see [docs/step1-review.md](docs/step1-review.md):**

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

- **Done:** Phases 0–6 (skeleton → defs → sets → rules/chains → host→`.nft` →
  `nft -c` → primitives A–E), Step 2 `build()`, Step 3a (sessrumnir role rewrite,
  two-play flow), and the **v0.2.0 strict authoring surface** (2026-07-05: unknown
  keys/names/empty groups fail the build; type-aware chain policy; loud `--check`;
  clean CLI errors — see TODO.md §Safety), and **v0.3.0** (wrapped large
  literals, named PoC fleet groups, netns harness B01–B03). **166 tests.**
- **Not done:** behavioral matrix breadth (harness live, B01–B03 green;
  B04+ and P01–P20 open), nftgen CI, Step 3b apply-rollback,
  Step 4 molecule end-to-end, enterprise (bright-future) firewall integration.

## Roadmap — 2026-07-05 (authoritative TODO; follow in order)

Goal: prove the generated firewalls *behave* (not just parse), make the deploy
safe, then land the role on sessrumnir main and wire nftgen-built rulesets into
the `feat/bright-future` enterprise router platform (its docs name the firewall
as the one architectural gap — "aerleon-style rule generator planned" = us).

### R0 — Release & sync (unblocks everything)  ✓ done 2026-07-05

- [x] Push nftgen master + tag **v0.2.0** (breaking: strict surface).
- [x] sessrumnir `feat/nftgen-integration`: bump `requirements.txt` pin
      `@v0.1.0` → `@v0.2.0`; **rebase onto origin/main (0.7.0)**; re-run the
      docker-nftables molecule scenario green. (Also: ansible-lint + yamllint
      green after conforming the nftgen YAML style; artifacts byte-identical;
      the v0.2.0 pin verified installing from the pushed tag. Branch at
      14f4dc1, force-pushed. Note: `vagrant-libvirt-enterprise` already
      exists on sessrumnir main — R6 targets it there, bright-future adds
      the container/HA roles on top.)

### R1 — Small tests first: netns behavioral harness (in this repo)

The real-trust layer `nft -c` can't give. No VM needed: user+net namespaces
(`unshare -rn` already proven here) + veth pairs.
**Progress 2026-07-05:** the *what* is specced — full behavioral matrix in
[docs/testing-plan.md](docs/testing-plan.md) (B01–B26 primitives + P01–P20
PoC truth table), and the showcase fixture exists:
[example-poc/](example-poc/) (two-site best-practice pair, README-narrated,
built + `nft -c` clean + drift-pinned by `tests/test_poc.py`; bare nat
targets now resolve site-overlay groups). Next: the harness itself.

- [x] pytest fixture: 3-namespace topology (client ↔ router ↔ server), apply a
      fixture ruleset in the router ns, probe with `nc`/ping. (Done 2026-07-05:
      `tests/behavioral/`, rootless.)
- [ ] Assert the *semantics* of each primitive: ct established/related return
      path; default-drop; accepted dport reachable, others refused (B01–B03
      **done**); dnat port-forward rewrites; vmap dispatch (per-interface
      chains hit); icmp policy; concat-set pair matching (B04+ **open**).
- [x] Marked/skipped cleanly where namespaces are unavailable (mirrors
      `requires_nft`).
- [ ] Then run the same harness over `example/` host policies (gateway dnat,
      router1/2 zones) — golden *behavior*, not just golden text.

### R2 — nftgen CI + last safety guard

- [x] Own venv (drop the aerleon `.venv` borrow) — done 2026-07-09 via
      `make install-dev`, plus the full lint suite (ruff/yamllint/
      markdownlint/gitleaks, pre-commit, `make verify`).
- [ ] GitHub Actions: pytest + `nft -c` (ubuntu runner) +
      `nftgen build example --check` + golden-drift (`git diff
      --exit-code` after regenerate) + the R1 netns suite + `make lint`.
- [ ] TODO item: reject nft-keyword set/map names (`fwd`, `last`, …) at build.

### R3 — sessrumnir Step 3b: apply-with-rollback (deploy safety)

- [ ] Role gains the apply sequence (DEPLOYMENT §10.3): `systemd-run` dead-man
      revert (restore last-good + re-enable) → apply to live → Ansible
      reconnect-confirm → persist to `/etc/nftables.conf` → cancel revert;
      `serial: 1`.
- [ ] Molecule test that *proves the revert*: deploy a ruleset, skip the
      confirm, assert the timer restored the previous ruleset.

### R4 — sessrumnir Step 4: molecule verifies behavior, not files

- [ ] docker-nftables `verify.yml` today asserts file contents only — add:
      `nft list ruleset` matches the shipped config (kernel state, not just
      the file), counters increment on probe traffic, disallowed port refused
      (probe from a second container or the host netns).
- [ ] CI drift gate: regenerate `examples/nftgen` + molecule project, `git
      diff --exit-code` (committed artifacts always reproducible).

### R5 — router service-contract policies (the bright-future gap)

Author as reusable nftgen includes + defs (test here first — R1 harness):

- [ ] `services.yaml`: bgp 179/tcp, dns 53/udp+tcp, dhcp 67-68/udp, ntp
      123/udp, vrrp = proto 112 (rule, not port), conntrackd sync, ssh mgmt.
- [ ] `policies/includes/router/`: in-mgmt, vrrp-peers (proto 112 +
      224.0.0.18), bgp-peers (saddr-scoped), dhcp-serve (+relay), dns-serve,
      conntrackd-sync (peer-link scoped), chrony.
- [ ] Example HA-router pair host mirroring the enterprise `router1`/`router2`
      shape; `nft -c` + netns behavioral pass.

### R6 — land on main, then converge with bright-future

- [ ] PR `feat/nftgen-integration` → sessrumnir main (breaking role rewrite;
      release-please bumps minor).
- [ ] Spike branch **off bright-future**: merge main (or cherry-pick the role),
      drop its fragment-role tweaks, add an `nftgen/` project to the
      `vagrant-libvirt-enterprise` inventory (per-router policies from R5),
      deploy via the R3 rollback flow.
- [ ] Run the enterprise scenario's verify + failover drills (VRRP failover,
      BGP session, DHCP lease, DNS resolve, conntrackd sync) **with firewalls
      active on both routers** — fix what breaks; that list is the real
      service contract. Done = enterprise verify green, firewalled.

### R7 — backlog after convergence (unordered)

JSON emitter revival (`nft -j` apply / drift detection), named/reusable maps,
`set-dscp`, CI change-detection apply-set (DEPLOYMENT model B), JSON schema
for editor validation.

## The plan (original phases — kept for history)

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
