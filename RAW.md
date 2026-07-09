# Raw recipes (escape-hatch cookbook)

Things nftgen doesn't model with structured keys *yet* — written today with the
`raw:` escape hatch (a literal nft fragment), to be given structured forms later.
`raw:` is **not validated by nftgen** — `nft -c -f` catches mistakes. Verify
exact syntax against your nft version.

A table can also carry a top-level `raw:` list for object *declarations*
(flowtables, named counters, ct helpers) that have no structured form yet:

```yaml
tables:
  - family: inet
    name: filter
    raw:
      - 'flowtable ft { hook ingress priority filter; devices = { "wan0", "lan0" } }'
      - 'counter http_hits { }'
    sets: [...]
    chains: [...]
```

---

## Concatenations  (match several fields as one key)

Match `(source, dest-port)` *pairs* in a single lookup against a concat-typed
set — far better than a rule per pair.

```yaml
# the set is a concatenation type (declared via table raw: for now)
#   set allow_pairs { type ipv4_addr . inet_service ;
#                     elements = { 192.168.1.5 . 22, 192.168.1.6 . 443 } }
rules:
  - raw: "ip saddr . tcp dport @allow_pairs counter accept"
```

*Future structured idea:* a `match-pairs:` key referencing a concat set.

## TCP flags

```yaml
rules:
  - raw: "tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop"   # null scan
  - raw: "tcp flags & (fin|syn) == (fin|syn) counter drop"             # syn+fin
  - raw: "tcp flags syn counter accept"                                # new-conn syn
```

*Future:* a `flags:` / `flags-mask:` key (like the aerleon fork's `tcp-flags`).

## Mangle — mark / dscp / mss

```yaml
rules:
  # fwmark for policy routing (multi-WAN, etc.)
  - raw: "ip daddr 10.0.0.0/8 meta mark set 0x1"
  # DSCP / QoS marking (mark SIP as Expedited Forwarding)
  - raw: "udp dport 5060 ip dscp set ef"
  # MSS clamp to path MTU for forwarded TCP
  - raw: "tcp flags syn tcp option maxseg size set rt mtu"
```

*Future:* `mark: 0x1`, `dscp: ef`, `mss: pmtu` keys.

## log / limit / quota

```yaml
rules:
  # log matching packets with a prefix
  - raw: 'tcp dport ssh log prefix "ssh-attempt " level info accept'
  # rate-limit new SSH (passes while under rate; over-rate falls through)
  - raw: "tcp dport ssh ct state new limit rate 10/minute accept"
  # drop a host once it has pushed > 1 GiB
  - raw: "ip saddr 192.0.2.50 quota over 1 gbytes drop"
```

*Future:* `log:` (bool/opts), `limit:` (rate), `quota:` keys.

## Flowtables  (offload established flows off the slow path)

Declare the flowtable on the table (table `raw:`), then add flows in `forward`.

```yaml
tables:
  - family: inet
    name: filter
    raw:
      - 'flowtable ft { hook ingress priority filter; devices = { "wan0", "lan0" } }'
    chains:
      - name: forward
        hook: forward
        priority: filter
        policy: drop
        rules:
          - ct: [established, related]
            action: accept
          - raw: "ip protocol { tcp, udp } flow add @ft"   # offload established
```

*Future:* a `flowtable:` block on the table + a `flow-offload: ft` rule key.

## Named counters  (per-rule stats you can read by name)

```yaml
tables:
  - family: inet
    name: filter
    raw:
      - 'counter http_hits { }'
    chains:
      - name: input
        hook: input
        priority: filter
        policy: drop
        rules:
          - raw: "tcp dport 80 counter name http_hits accept"
```

Read with `nft list counter inet filter http_hits`.
*Future:* `counter: http_hits` (a name instead of `true`).
