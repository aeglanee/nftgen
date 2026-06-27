# D. Match-expression syntax (key → nft tokens)

You write the match *intent* as keys; nftgen emits the correct nft expression —
keyword spelling, family prefix, proto-qualification, `meta` wrapping. Examples
`nft -c`-verified.

## Define → generate

```yaml
rules:
  - ct: [established, related]   # -> ct state ...
    action: accept
  - iif: wan                     # -> iifname (name, not index)
    action: drop
  - proto: icmp                  # -> meta l4proto (standalone)
    action: accept
  - saddr: mgmt                  # -> ip saddr (family prefix)
    proto: tcp                   # -> tcp dport (proto-qualified)
    dport: web                   #    web service -> @web set
    action: accept
```
→
```nft
ct state established,related accept
iifname @wan drop
meta l4proto icmp accept
ip saddr @mgmt tcp dport @web accept
```

## The key → token map

| YAML | nft | note |
| --- | --- | --- |
| `iif` / `oif` | `iifname` / `oifname` | matches by interface **name** |
| `saddr` / `daddr` | `ip`/`ip6 saddr`/`daddr` | family prefix from the address |
| `proto: X` (alone) | `meta l4proto X` | family-agnostic L4 match |
| `proto: X` + `sport`/`dport` | `X sport`/`dport …` | proto-qualified port |
| `dport: <service>` | the service's ports for that proto | e.g. `web` → `@web` / `{ 80, 443 }` |
| `ct: [s, …]` | `ct state s,…` | |

## Why it's safe to automate

- **Fixed, deterministic mapping** — each key has exactly one nft spelling; it's a
  lookup, not a judgement. nft defines the syntax.
- **nft-policed** — a wrong token is an `nft -c` error; it can't silently mislead.
- **Removes syntax memorization** — `iifname` vs `iif`, ports needing a proto,
  `meta l4proto` — you don't have to remember any of it.

## The two deliberate choices

| Key | nftgen emits | Alternative | Why this default |
| --- | --- | --- | --- |
| `iif`/`oif` | `iifname`/`oifname` (name) | `iif`/`oif` (index) | names survive interface renumbering; index is marginally faster |
| `proto` (alone) | `meta l4proto` | `ip protocol` / `ip6 nexthdr` | family-agnostic — one rule works for v4+v6 in `inet` |

Both are consistent, correct-for-`inet` defaults. Want the alternative form
(index match, family-specific protocol)? Use `raw:`.

## Guardrail

Ports require a proto — there's no protocol-less port match in nft:
```yaml
- dport: web
  action: accept        # no proto:
```
```
BuildError: port match needs a proto: {'dport': 'web', 'action': 'accept'}
```

## Override

`raw:` for anything beyond the common vocabulary (index-based `iif`, `ip protocol`,
exotic meta matches). Every standard match has a structured key.
