# B. Family split (v4 / v6 awareness)

A rule with address matches renders **once per IP family common to those
matches** — nftgen reads the family off the address, so a restriction never
silently widens or vanishes. All examples below are `nft -c`-verified.

## Define → generate (the default)

```yaml
networks:
  dns_servers: [192.0.2.53, 2001:db8::53]   # dual-stack (v4 + v6)
  lan4: [10.0.0.0/8]                         # v4 only
  lan6: [2001:db8:1::/48]                    # v6 only
```
```yaml
rules:
  - saddr: dns_servers      # dual-stack
    proto: udp
    dport: 53
    action: accept
  - saddr: lan4             # single family
    action: accept
  - saddr: lan6             # single family
    action: accept
```
→
```nft
ip  saddr 192.0.2.53   udp dport 53 accept     # dual-stack group ->
ip6 saddr 2001:db8::53 udp dport 53 accept     #   two lines, one per family
ip  saddr 10.0.0.0/8 accept                    # v4-only group -> one ip  line
ip6 saddr 2001:db8:1::/48 accept               # v6-only group -> one ip6 line
```

The family comes from the address itself (`_addr` returns a per-family token); a
rule renders for the **intersection** of the families of all its address matches.
A `@named` set carries the family of its `type` (`ipv4_addr` → v4 only).

## Why these defaults are safe

- **Deterministic** — family is intrinsic to the address; no judgement call.
- **Removes a footgun** — the alternative (not splitting) is Aerleon's "E2": a
  mixed-family rule silently drops one family's restriction or emits invalid nft.
  Per-family rendering means you get correct lines **or a loud error** — never a
  silent widening.
- **nft-policed** — `ip saddr` only matches v4; a mismatch is an `nft -c` error.

## Guardrails (where it refuses, loudly)

A rule whose address matches share **no** family can never render:
```yaml
- saddr: lan6            # v6 only
  daddr: lan4            # v4 only
  action: accept
```
```
BuildError: rule mixes incompatible address families: {...}
```

A definition-backed set must be single-family:
```yaml
networks:
  dual: [192.0.2.1, 2001:db8::1]
```
```
BuildError: set 'dual' mixes IPv4 and IPv6; a named set is single-family —
split into e.g. dual_v4 / dual_v6
```

## Scoping to one family (the override)

Auto-split assumes the **same** policy for both families. But v4 and v6 policy
*often differ* — v6 must allow ICMPv6 neighbor discovery, usually has no NAT,
has link-local, etc. When you want different rules per family, **author
single-family groups** and reference the one you mean:

```yaml
networks:
  lan_v4: [10.0.0.0/8]
  lan_v6: [2001:db8:1::/48]
rules:
  - saddr: lan_v4         # v4 policy
    proto: tcp
    dport: ssh
    action: accept
  - saddr: lan_v6         # v6 policy (could differ)
    proto: tcp
    dport: ssh
    action: accept
  - proto: icmpv6         # v6-only: neighbor discovery, etc.
    action: accept
```

So: nftgen automates "same policy across the families an address spans"; **you**
author per-family when they diverge. (`raw:` covers anything beyond that.) See
DECISIONS §2.4 for why single-family-with-loud-errors beats silent widening.
