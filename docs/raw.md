# `raw:` recipes

For nft features without a structured key yet. A rule's `raw:` is copied
verbatim; nftgen doesn't check it (no names resolved, no family split), so
`nft -c` is the only check. Each recipe here passed `nft -c` on nft 1.1.7
unless noted.

## Table-level declarations

A table's `raw:` list declares objects nftgen doesn't model: ct helpers,
named quotas, named maps, sets with tuning, netdev device chains.

```yaml
tables:
  - family: inet
    name: filter
    raw:
      - 'ct helper ftp-standard { type "ftp" protocol tcp; }'
      - "quota user_cap { over 10240 mbytes }"
      - "map port_dispatch { type inet_service : verdict; }"
    chains: []
```

Quota units stop at `mbytes`. A multi-line string works too; nft doesn't
mind that only its first line is indented.

## DSCP / QoS marking

```yaml
- raw: "udp dport 5060 ip dscp set ef"   # SIP as Expedited Forwarding
```

`ip dscp` is IPv4 only; IPv6 needs its own `ip6 dscp set ef` rule. (nft
parses both; a rootless namespace can refuse to load `dscp set`, so they
were not load-tested.)

## Add to a set from a rule

```yaml
- raw: "tcp dport ssh ct state new update @ssh_meters { ip saddr }"
```

The set is a `sets:` entry with `flags: [dynamic]`. With a rate limit, use the
`meter:` key instead.

## redirect

```yaml
- raw: "tcp dport 80 redirect to :8080"   # in a type nat, hook prerouting chain
```

## NFLOG batching

`log: {group: 2}` is structured; the batching options are not:

```yaml
- raw: "tcp dport 25 log group 2 queue-threshold 16"
```

## Trace a packet (debugging)

```yaml
- raw: "ip saddr 192.168.10.55 meta nftrace set 1"   # then: nft monitor trace
```

## Meta matches beyond mark

```yaml
- raw: "meta pkttype broadcast drop"
- raw: "meta skuid 1000 accept"   # output chain
```

## Now structured — use the key, not `raw:`

| Was a recipe | Key |
| --- | --- |
| concatenated lookups | set `concat:` + `tuples:`, rule `set:` |
| rule comments | `comment:` |
| reject with a type | `action: reject with tcp reset` |
| tcp flags | `flags: {match: [...], mask: [...]}` |
| fwmark match / set | `mark:` / `set-mark:` |
| MSS clamp | `set-mss: pmtu` (or a number) |
| per-source rate limit | `meter:` |
| log / limit / quota | `log:` / `limit:` / `quota:` |
| flowtables | table `flowtables:` + rule `flow-offload:` |
| named counters | table `counters:` + rule `counter: <name>` |

Every key: [DESIGN.md](../DESIGN.md). Candidates for a key: [TODO.md](../TODO.md).
