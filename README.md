# nftgen

A small, **nftables-only** firewall-as-code generator. YAML definitions +
host policies → a native `.nft` ruleset you keep in git and apply with `nft -f`.

> Status: **early.** Phase 0 (skeleton). See [DESIGN.md](DESIGN.md) for the
> spec/philosophy and [RAW.md](RAW.md) for the `raw:` escape-hatch cookbook.

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

## Usage (planned)

```bash
nftgen policies/hosts/router1.yaml --defs def --out generated/router1.nft
```

## Develop

```bash
python -m pytest
```

## License

Apache-2.0. Definitions model adapted from Aerleon concepts — see [NOTICE](NOTICE).
