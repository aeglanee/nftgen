# nftgen

[![ci](https://github.com/aeglanee/nftgen/actions/workflows/ci.yml/badge.svg)](https://github.com/aeglanee/nftgen/actions/workflows/ci.yml)

A small, **nftables-only** firewall-as-code generator. YAML definitions +
host policies → a native `.nft` ruleset you keep in git and apply with `nft -f`.

> Status: **working standalone generator** (Phases 0–6: definitions, named sets,
> rules/chains, host→`.nft` with includes + per-site overlay, `nft -c` validation,
> primitives — statements, counters, flowtables, vmaps, concatenations,
> tcp-flags; strict
> authoring surface — unknown keys/names and empty groups fail the build).
> Latest release **v0.4.0**; 240 tests. Ansible integration: the sessrumnir
> `nftables` role consumes
> `nftgen build` (Step 3a done; 3b/4 remain — see [PLAN.md](PLAN.md)).
>
> **Docs:** [docs/authoring.md](docs/authoring.md) (**start here** — structure,
> workflow, decision table) · [DESIGN.md](DESIGN.md) (spec) ·
> [DECISIONS.md](DECISIONS.md) (why) ·
> [DEPLOYMENT.md](DEPLOYMENT.md) (GitOps/Ansible vision) · [PLAN.md](PLAN.md)
> (plan & status) · [RAW.md](RAW.md) (`raw:` cookbook) · [TODO.md](TODO.md)
> (backlog) · [CLAUDE.md](CLAUDE.md) (working guardrails).

## Idea

- **Definitions** (`networks` / `services` / `interfaces`) — composable, merged.
- **Host policies** mirror nftables: `tables → sets → chains → rules`. You author
  your own chains; the tool adds named definitions, named-set emission,
  composition, includes, per-site `local` definitions, and validation.
- **You author the structure** — no optimizer. Best practices are easy defaults
  you choose (conntrack-early, named sets, vmaps), not magic.
- A `raw:` escape hatch (per rule and per table) means anything nft can express
  is reachable today.

## Layout

```text
definitions/                 definitions (common to every host)
sites/<site>.yaml    per-site definitions (selected by a host's `site:`)
policies/
  includes/          shared rule fragments (- include:)
  hosts/<host>.yaml  one host -> one generated .nft
```

See [example/](example/) for a worked multi-host example.

## Usage

```bash
# one host (composition primitive, no flush)
nftgen policies/hosts/router1.yaml --defs definitions --out generated/router1.nft

# whole fleet from a directory (convention layout) — the deploy artifacts
nftgen build <root>                 # → generated/<host>.nft for every policies/hosts/*.yaml
nftgen build <root> --host router1  # just one host
nftgen build <root> --host router1 --stdout  # render one host to stdout, write nothing
```

`--stdout` prints the host's ruleset instead of writing `generated/` — for
previewing a change (`… --stdout | git diff --no-index generated/router1.nft -`),
piping, or a deployer that renders on the fly without mutating the committed
tree. It requires `--host` (stdout is a single stream = a single host).

`build` output is a complete, applyable ruleset (`#!/usr/sbin/nft -f` +
`flush ruleset` + tables) that ships verbatim as `/etc/nftables.conf`.

## Develop

```bash
python -m pytest
```

## License

MIT (see [LICENSE](LICENSE)). The YAML definitions model reimplements concepts
from [Aerleon](https://github.com/aerleon/aerleon) (Apache-2.0) clean-room — no
Aerleon code is used; the acknowledgment is courtesy, not a license obligation.
