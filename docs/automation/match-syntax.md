# D. Match-expression syntax (key → nft tokens)

You write the match *intent* as keys; nftgen emits the correct nft expression —
keyword spelling, family prefix, proto-qualification, `meta` wrapping. Examples
`nft -c`-verified.

## Define → generate

```yaml
rules:
  - ct: [established, related]   # -> ct state ...
    action: accept
  - iifname: wan                 # -> iifname (interface name match)
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
| `iifname` / `oifname` | `iifname` / `oifname` | interface **name** match (robust) |
| `iif` / `oif` | `iif` / `oif` | interface **index** match (faster; see below) |
| `saddr` / `daddr` | `ip`/`ip6 saddr`/`daddr` | family prefix from the address |
| `proto: X` (alone) | `meta l4proto X` | family-agnostic L4 match |
| `proto: X` + `sport`/`dport` | `X sport`/`dport …` | proto-qualified port |
| `dport: <service>` | the service's ports for that proto | e.g. `web` → `@web` / `{ 80, 443 }` |
| `ct: [s, …]` | `ct state s,…` | |

## Why it's safe to automate

- **Fixed, deterministic mapping** — each key has exactly one nft spelling;
  it's a lookup, not a judgement. nft defines the syntax.
- **nft-policed** — a wrong token is an `nft -c` error; it can't silently mislead.
- **Removes syntax memorization** — the family prefix, ports needing a proto,
  `meta l4proto` wrapping — you don't have to remember any of it.

## Interface match: name vs index

Both forms are structured keys — you choose by which tradeoff you want:

| Key | nft | when |
| --- | --- | --- |
| `iifname` / `oifname` | name compare, per packet | the **default** — survives interface renumbering / boot ordering |
| `iif` / `oif` | index compare (name resolved at load) | faster, but the ruleset **fails to load** if the interface is absent — for statically-named, always-present interfaces |

Full tradeoff in [best-practices.md](../best-practices.md) §8a. (`proto` alone
emits `meta l4proto` rather than `ip protocol`/`ip6 nexthdr` so one rule works
for v4+v6 in an `inet` table — the family-specific form is a `raw:` matter.)

## Guardrail

Ports require a proto — there's no protocol-less port match in nft:

```yaml
- dport: web
  action: accept        # no proto:
```

```text
BuildError: port match needs a proto: {'dport': 'web', 'action': 'accept'}
```

## Override

`raw:` for anything beyond the common vocabulary (`ip protocol`, exotic meta
matches, `pkttype`, …). Every standard match — including both interface forms —
has a structured key.
