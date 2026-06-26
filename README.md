# nftgen

A small, **nftables-only** firewall-as-code generator. YAML definitions +
host policies → a native `.nft` ruleset you keep in git and apply with `nft -f`.

> Status: **working standalone generator** (Phases 0–6: definitions, named sets,
> rules/chains, host→`.nft` with includes + per-site overlay, `nft -c` validation,
> primitives — statements, counters, flowtables, vmaps, tcp-flags). 80 tests.
> Ansible/CI integration is planned, not built — see [PLAN.md](PLAN.md).
>
> **Docs:** [DESIGN.md](DESIGN.md) (spec) · [DECISIONS.md](DECISIONS.md) (why) ·
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

```
def/                 definitions (common to every host)
sites/<site>.yaml    per-site definitions (selected by a host's `site:`)
policies/
  includes/          shared rule fragments (- include:)
  hosts/<host>.yaml  one host -> one generated .nft
```

See [example/](example/) for a worked multi-host example.

## Usage

```bash
# one host (works today)
nftgen policies/hosts/router1.yaml --defs def --out generated/router1.nft

# whole fleet from a directory (planned — see PLAN.md step 2)
nftgen build <root>          # → generated/<host>.nft for every policies/hosts/*.yaml
```

## Develop

```bash
python -m pytest
```

## License

Apache-2.0. Definitions model adapted from Aerleon concepts — see [NOTICE](NOTICE).
