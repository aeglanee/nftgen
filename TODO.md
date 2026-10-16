# TODO

The one backlog: open items only. Shipped work is in
[CHANGELOG.md](CHANGELOG.md); settled design is in [DECISIONS.md](DECISIONS.md).
The current working list (review follow-ups, release order) is
[docs/review-2026-10.md](docs/review-2026-10.md).

## Next

- [ ] **Release** the unreleased `main` (see CHANGELOG) — 0.8.0, or 1.0.0
      together with a simpler install (PyPI and/or Ansible Galaxy).
- [ ] **Blame notes** (spike on `feat/blame-notes` in nftgen, ansible-firewall,
      sessrumnir): release the `annotate` hook (document it in DESIGN.md
      "As a library" when it merges), repin, open the PRs. Design record:
      ansible-firewall `docs/blame-notes.md`.

## Structured keys (today via `raw:`)

- [ ] `port/proto` literals in rule port keys: `dport: [dns, 8080/tcp]`
      (vmaps already take them).
- [ ] Named / reusable maps: a table-level `maps:` (verdict maps, dnat
      targets) referenced from a `vmap:` rule or a dnat map.
- [ ] `set-dscp`, rendered per family (`ip dscp set` / `ip6 dscp set`).
- [ ] `redirect` action; `ct mark` (match + set); more meta matches
      (`pkttype`, `skuid`, …).
- [ ] Anti-spoofing (`fib saddr . mark . iif oif missing drop`) as a key,
      strict or loose; the recipe is in
      [docs/best-practices.md](docs/best-practices.md) §5, proven by
      behavioral test B28.

## Checks

- [ ] `--host` as an allowlist (`[A-Za-z0-9][A-Za-z0-9._-]*`) instead of the
      path-separator check.
- [ ] Overlapping keys in a vmap or named set (a prefix inside another, a
      port inside a range; in a vmap also `10.0.0.1` vs `10.0.0.1/32` with
      different verdicts) fail only at nft load — detect them at build if it
      ever matters. Table in
      [docs/sets-and-performance.md](docs/sets-and-performance.md) §5.
- [ ] Definition values checked where they're defined (`22/tpc`,
      `99999/tcp`), not only where they're used.

## Deployment (ansible-firewall)

- [ ] **Drift detection** (discuss first). The role compares the render with
      `/etc/nftables.conf`, never the live ruleset: after a hand-run
      `nft flush ruleset` or `nft add rule … accept`, a re-run reports `ok`
      and the router stays open until a reboot or the next rule change.
      Sketch from 2026-10-16: `nftables_drift: off | warn | fix` (warn first);
      load the render in a throwaway namespace on the host and compare
      `nft -s -j list table …` against live — `-s` drops counter values;
      compare only our own tables (other tools' tables are not ours);
      ignore elements of sets declared without elements (runtime blocklists,
      meters). `fix` re-applies through the rollback (runtime elements are
      lost, as on any apply).
- [ ] **Coexistence** (related): the file starts with `flush ruleset`, so
      every apply also wipes Docker / netavark / libvirt / fail2ban tables.
      Flushing only our own tables would let them coexist.

## Upstream nft

- [ ] nft 1.1.7 parse bug: a rule with `limit rate … reject with tcp reset`
      followed by a line starting `tcp flags` fails with "syntax error,
      unexpected junk"; each line passes alone. nftgen's output is correct and
      `nft -c` catches it. Retest on a newer nft, report upstream, and note it
      in [docs/best-practices.md](docs/best-practices.md). Repro:

      ```nft
      table inet t {
        chain c {
          type filter hook forward priority 0;
          limit rate 4/minute reject with tcp reset
          tcp flags syn drop
        }
      }
      ```

## Editor and lint support

- [ ] Export the rule value schema (`nftgen/schema.py`) as a JSON Schema: editor
      validation + completion for the file tree and for Ansible vars
      (`nftgen_tables`, `nftgen_fragments__*`; templated values pass).
- [ ] A pre-commit check over raw YAML using the same schema (could ride in
      sessrumnir's duplicate-var scan).

## Testing and dev setup

- [ ] A Nix dev shell (python + nftables + iproute2): today `make verify`
      silently skips the `nft -c` and netns tests when `nft` isn't on `PATH`.
- [ ] A two-router behavioral harness (true cross-site end to end).

## Ideas (low priority)

- [ ] Layered sites: `site:` as a list (global → region → site), and an inline
      per-host `local:` override.
- [ ] Bare sets that infer `type:` from their elements.
