# Raw recipes (escape-hatch cookbook)

Things nftgen doesn't model with structured keys *yet* — written today with the
`raw:` escape hatch (a literal nft fragment), promoted to structured keys when
they earn it (see the log at the bottom). `raw:` is **not validated by
nftgen** — `nft -c -f` catches mistakes. Verify exact syntax against your nft
version.

A table can also carry a top-level `raw:` list for object *declarations* that
have no structured form yet (ct helpers, named quotas, synproxy):

```yaml
tables:
  - family: inet
    name: filter
    raw:
      - 'ct helper ftp-standard { type "ftp" protocol tcp; }'
      - 'quota user_cap { over 10 gbytes }'
    sets: [...]
    chains: [...]
```

---

## DSCP / QoS marking

```yaml
rules:
  # mark SIP as Expedited Forwarding
  - raw: "udp dport 5060 ip dscp set ef"
```

*Promotion queue:* a family-aware `set-dscp:` key (see
[docs/capabilities.md](docs/capabilities.md) §9).

## Dynamic set ops (populate a set from a rule)

```yaml
rules:
  # track sources into a live set (pairs with a bare `sets:` entry)
  - raw: "tcp dport ssh ct state new update @ssh_meters { ip saddr }"
```

## redirect / tproxy

```yaml
rules:
  - raw: "tcp dport 80 redirect to :8080"
```

## Rule comments

```yaml
rules:
  - raw: 'tcp dport ssh accept comment "mgmt access, ticket #123"'
```

## NFLOG batching knobs

`log: {group: N}` is structured; the batching/snap options are not:

```yaml
rules:
  # deliver to nflog group 2 (e.g. ulogd2), batched 16 packets at a time
  - raw: "tcp dport 25 log group 2 queue-threshold 16"
```

## Trace a packet's path (debugging)

```yaml
rules:
  # temporary: arm tracing for one test source, watch `nft monitor trace`
  - raw: "ip saddr 192.168.10.55 meta nftrace set 1"
```

## Meta matches beyond mark

```yaml
rules:
  - raw: "meta pkttype broadcast drop"
  - raw: "meta skuid 1000 accept"
```

---

## Promoted (now structured — don't use raw for these)

| Was a raw recipe here | Structured form today |
| --- | --- |
| concatenated lookups | set `concat:`+`proto:`+`tuples:`, rule `set: <name>` |
| tcp flags | `flags: {match: [...], mask: [...]}` |
| fwmark match / set | `mark:` / `set-mark:` |
| MSS clamp | `set-mss: pmtu` (or a number) |
| log / limit / quota | `log:` / `limit:` / `quota:` |
| flowtables | table `flowtables:` + rule `flow-offload: <ft>` |
| named counters | table `counters: [name]` + rule `counter: <name>` |

Full render reference: [docs/capabilities.md](docs/capabilities.md); schema:
[DESIGN.md](DESIGN.md).
