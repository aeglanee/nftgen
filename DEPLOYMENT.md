# Deployment

How a rendered ruleset reaches a router: what is built today, and the GitOps
end-state we are building toward. nftgen only renders; shipping and applying
belong to Ansible.

## Built today

### Ansible vars mode (sessrumnir)

sessrumnir authors each host's firewall as inventory variables, and the
[ansible-firewall](https://github.com/sessrumnir/ansible-firewall)
collection deploys it:

1. **Render on the controller.** The `nftgen_render` action plugin imports
   nftgen and calls `render_tables()` with the host's
   `nftgen_definitions__*`, `nftgen_fragments__*` and `nftgen_tables`.
   Nothing is written to disk; any authoring error fails the play.
2. **Apply on the host.** The `nftables` role validates with `nft -c`,
   applies behind a dead-man rollback timer, confirms a fresh SSH
   connection, then writes `/etc/nftables.conf`. Run it with `serial: 1`.
3. **Change detection.** The role applies only when the render differs from
   the installed `/etc/nftables.conf`; `--check --diff` shows the exact rule
   change. This relies on deterministic output
   ([DECISIONS.md](DECISIONS.md) §2.5).

How to author and the rollback steps are in the role's
[README](https://github.com/sessrumnir/ansible-firewall/blob/main/roles/nftables/README.md).

### File tree (standalone)

`nftgen build <root>` renders every host into `generated/<host>.nft`: the host's
reset (`flush ruleset`, or one `destroy table` per own table with `reset:
own-tables` — [DESIGN.md](DESIGN.md#project-layout)) + its tables, shipped
verbatim as `/etc/nftables.conf`. Apply it by hand with `nft -c -f` then `nft
-f`, or with any tool that copies a file. [example-fleet/](example-fleet/)
commits its renders, and CI fails when a committed render differs from a fresh
one.

## Rules for both

- **The render is never a source.** Committed or not, it is never edited by
  hand; the YAML (or the inventory) is the single source of truth.
- **CI verifies, never rewrites.** A committed render is checked against a
  fresh one; CI doesn't regenerate and commit, so what was reviewed is what
  deploys.
- **Pin the nftgen version.** A different nftgen may render different bytes;
  a pin keeps a diff about your change, not the tool's.
- **Apply one host at a time**, behind a rollback, with console access in
  reserve.

## Not built yet (the end-state)

Git is the desired state, a reconciler converges the routers to it, and drift
is corrected (the Argo CD / Flux model for firewalls).

- **Apply from CI on merge:** render every host, apply those whose ruleset
  changed, one by one. A rendered ruleset is the full result of every shared
  definition and fragment, so comparing renders finds exactly the affected
  hosts without tracing dependencies.
- **Scheduled reconcile and drift detection.** The role compares the render
  with `/etc/nftables.conf`, not with the live ruleset, so a rule added by
  hand with `nft` survives a re-run until the next real change or reboot.
  Comparing against `nft list ruleset` (normalised) would catch it; alert on
  drift rather than silently erasing it — an out-of-band change on a
  firewall is a security signal.
- **The CI controller** would hold SSH to every router: scoped keys, audit.
  A pull model (each router fetches its own ruleset) avoids central keys at
  the cost of more machinery.

Manual runs stay first-class: CI would run the same commands
(`ansible-playbook … --limit <host>`) an operator runs by hand.
