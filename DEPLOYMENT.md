# Deployment & integration vision

How nftgen is meant to be operated and how it fits a larger router-configuration
Ansible collection (`sessrumnir`). This is the **target end-state**, not built
yet — it records the model we agreed on so we build toward it deliberately.

Status: nftgen is a working standalone generator (Phases 0–6). None of the
Ansible/CI integration below exists yet. See [PLAN.md](PLAN.md) for the order.

---

## 1. The shape: GitOps for firewalls
Git is the **desired state**; a reconciler **converges** the machines to it;
drift gets corrected. (The ArgoCD/Flux model, applied to nftables.)

- **Source of truth:** the nftgen YAML tree (definitions + sites + includes +
  per-host policies) in git.
- **Rendered artifact:** the generated `.nft` per host, **also committed** to git
  (reviewable, diffable, accurate state record).
- **Reconciler:** CI (the controller) applies git state to machines — both
  on-change and on a schedule.

## 2. nftgen and Ansible are decoupled
nftgen **generates files**; Ansible **deploys files**. The Ansible nftables role
is thin and does not embed nftgen's logic; it ships the committed `.nft`, runs a
syntax check on the target, and reloads safely. nftgen can be developed and
tested entirely on its own; the collection consumes its output.

*Why decoupled (not a vars-in filter plugin):* nftgen owns composition
(definitions/sites/includes — see DECISIONS.md §3.1), which is richer than
Ansible var-layering and avoids Ansible's list-merge pain. So nftgen is a tool
that emits a reviewed `.nft`; the role's job is the safe apply.

## 3. The `.nft` is a render, never a source
The committed `.nft` is **generated output**, committed for review and accurate
state tracking — it is **never hand-edited**. YAML is the only source of truth.

- **CI verifies, does not overwrite:** on every change CI asserts
  `committed.nft == nftgen(yaml)` and **fails** on mismatch. It does *not*
  regenerate-and-commit (that would break review integrity — you'd review one
  `.nft` and deploy another, plus bot-commit churn).
- **Pre-commit hook regenerates** the `.nft` locally so a stale render can't be
  committed → CI's verify then passes unless there's a real problem.
- **Pin the nftgen version** (local == CI). `verify-equal` only holds if both
  sides run the same generator version (a *different version* can legitimately
  produce different output). Pinning makes the gate about *your change*, not
  version drift.

*Why verify-not-overwrite:* what you reviewed in the PR is exactly what deploys;
the human owns the applied bytes, not a bot.

## 4. Change detection: regenerate all, diff the `.nft`
To decide *who to apply*: **regenerate every host's `.nft`, diff against the
committed ones; the hosts whose `.nft` changed are the apply set.**

*Why this and not "trace which files affect which host":* with shared
definitions/includes/site overlays, one edit can ripple to many hosts —
tracing that statically is intractable. But the generated `.nft` **is** the
result of that whole dependency resolution, so diffing it captures the full
transitive effect for free (change a shared net → only hosts whose final ruleset
actually changed get applied; identical renders are skipped). This relies on
**deterministic output** (DECISIONS.md §2.5).

## 5. Triggers: edge + level
- **Edge-triggered** (on change to definitions/includes/host policy): regenerate, apply
  the hosts whose `.nft` changed. The fast path.
- **Level-triggered** (scheduled reconcile, e.g. cron): re-converge to git state.
  **This is the *enforcement* of "git wins,"** not just a backstop — it's what
  reverts an out-of-band manual change. Without it, drift persists.

**Reconcile behavior:** start with **blind reapply** of the committed `.nft`
(`nft -f` with `flush ruleset` is a single atomic transaction, so reapplying an
identical ruleset is a safe no-op). Later upgrade to **drift-detect + alert** —
for a firewall, *seeing* that a box was changed out-of-band is a security signal
worth surfacing, not silently erasing.

## 6. Apply safety (where you lock yourself out)
- **`nft -c -f` on the target first** — catches kernel/netlink issues CI can't
  (CI only checks syntax; the box checks the real ruleset).
- **Apply with a timed rollback** — apply → hold → auto-revert if not confirmed,
  so a bad ruleset can't sever your SSH.
- **One host at a time (or small batches)** — bounds blast radius; a bad ruleset
  takes down one router, the rollback restores it, the run halts.
- **The CI controller holds SSH to every router** — it's the most
  security-sensitive box; lock it down (scoped keys, audit). A pull model (each
  box fetches+applies its own) avoids central keys but is more machinery;
  push-from-CI is the pragmatic start.

## 7. Manual apply is first-class
CI is the eventual automation, but **everything must be runnable by hand**, with
the *same* commands CI uses:
- regenerate: `nftgen build <root>` → `git diff` shows YAML **and** `.nft` changes.
- apply: `ansible-playbook nftables.yml --limit <host>` → ships the committed
  `.nft`, `nft -c` on target, timed rollback.

**The contract:** a local apply works, but the reconciler will **roll back**
anything not in git, and that's on the operator. Guardrails (not prevention):
give operators the same tooling, and document loudly that *out-of-band changes
are temporary; git is truth.* You can't stop someone SSHing in to run `nft` by
hand — the periodic reconcile self-heals it.

## 8. The collection (`sessrumnir`) context
A "router-in-a-box" collection is **one role per daemon**, each the same shape:
`declarative config → generate → validate → ship + reload safely`
(networkd, keepalived, kea-dhcp, frr, **nftables**). Most are vars-driven filter
plugins (their config is flat). **nftables is the odd one out** — it deploys
nftgen's rendered output instead of compiling from vars, *because* nftgen is a
real compiler with its own composition. A collection where most roles are
vars-driven and one deploys a generator's output is perfectly coherent.

The existing sessrumnir `nftables` role just concatenates hand-written `.nft`
fragments (common/site/host file globs). nftgen replaces that fragment-shipping
with a real declarative generator — a clear upgrade — while reusing the role's
ship/validate/reload half almost verbatim.

## 9. End-to-end (the picture)
```
edit YAML  ─┬─ pre-commit: nftgen build → regenerate generated/<host>.nft
            └─ git diff shows BOTH the YAML change and the rule (.nft) change
                                   │  commit + push
                                   ▼
CI ─ nftgen build → assert committed == render → nft -c (syntax) → pytest goldens
                                   │  (on merge / on schedule)
                                   ▼
apply changed hosts, one by one ─ ship committed .nft → nft -c on target
                                 → apply with timed rollback → confirm
scheduled reconcile ─ re-converge every host to git state (revert drift)
```
Manual path is the same `nftgen build` + `ansible-playbook --limit`, run by hand.

## 10. Integration mechanics (agreed 2026-06-26)
nftgen replaces the existing nftables role's *generation* (the hand-written
common/site/host fragment globbing). nftgen emits **one complete config per
host**; composition is nftgen's, resolved at build time. Invoked as a **CLI
(shell out)**, not an in-process plugin (DECISIONS §3.4).

### 10.1 Deploy artifact (Shape A)
The build output **is** the target's `/etc/nftables.conf`, shipped verbatim:
shebang + `flush ruleset` + the host's tables (DECISIONS §5.3). So the committed
`.nft` == the on-box config byte-for-byte, it's directly `nft -f`-applyable, and
`flush ruleset` makes every apply an atomic replace (the §5 reconcile). *Rejected:*
a wrapper `nftables.conf` that `flush`+`include`s a flush-free file (Shape B).

### 10.2 Two-play playbook + targeting
Naming contract (exact): `inventory_hostname` == `policies/hosts/<name>.yaml` ==
`generated/<name>.nft`.
- **Play 1 — build:** `hosts: all`, `run_once: true`, `delegate_to: localhost`,
  runs `nftgen build <root>` → all hosts' files. `hosts: all` (not `localhost`)
  so `--limit` can't skip it. `--limit` narrows *apply*, never *build*.
  (`nftgen build --host <name>` exists for a single-host manual build.)
- **Play 2 — apply:** `hosts: all` (filtered by `--limit`), `serial: 1`, ships
  `generated/{{ inventory_hostname }}.nft`.

`ansible-playbook nftables.yml --limit router1` → builds all once, applies router1.

### 10.3 Apply + rollback (per host, `serial: 1`)
Apply to the *live* ruleset first; persist `/etc/nftables.conf` only after
confirm — so a lockout reverts AND a reboot stays safe (realises §6).
1. **Ship** → staging `/etc/nftables.conf.new`.
2. **Validate** `nft -c -f /etc/nftables.conf.new` → failure aborts; live + boot config untouched.
3. **Snapshot** the running ruleset → `/etc/nftables.rollback.nft` (last-known-good).
4. **Arm dead-man revert:** `systemd-run --on-active=Ns` → `nft -f /etc/nftables.rollback.nft`, cancellable.
5. **Apply to live:** `nft -f /etc/nftables.conf.new` (atomic via flush). Boot config not yet changed.
6. **Confirm** via reconnect (`wait_for_connection`): reachable → cancel timer +
   promote `.new` → `/etc/nftables.conf`; locked out → timer reverts live, boot
   config stays good, play halts.

*Verify at implementation:* exact `systemd-run` flags, Debian `nftables.service`
`ExecReload`, and `wait_for_connection` timing vs N (confirm must finish before
the timer fires).
