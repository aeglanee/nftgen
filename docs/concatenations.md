# Finding: structured rules can't emit concatenated set lookups

> **Superseded — the feature shipped (2026-07).** This was the design
> proposal for the then-deferred **concatenations** feature. It was
> implemented with a *different* authoring surface than proposed below:
> set-level `concat:`+`proto:`+`tuples:` plus a `set:` rule key — see
> [concat-authoring.md](concat-authoring.md) (the decision) and
> [DESIGN.md](../DESIGN.md)/[capabilities.md](capabilities.md) (the result).
> Kept as history for the *why*. The root cause below was **verified
> accurate** against `rules.py` (`render()` appends matches as independent
> space-joined parts; `_addr`/`_port` resolve independently; no `.`-join path).
> Two corrections to the proposal:
>
> - **Priority:** framed below as "high for the tiered design," but that tiered
>   `goto`-dispatch example is illustrative — it is **not in this repo** (our
>   examples use vmaps). For us this is à-la-carte; rank it via the Step 1
>   coverage map against real rules, not as a blocker.
> - **`_VMAP_KEYS` reuse:** only *partial* — vmap's map is just `iif/oif/proto`;
>   concat also needs family-aware `saddr/daddr` and proto-tagged `dport/sport`,
>   so it's a broader shared table, not a literal reuse.

## Summary

The generator produces the **chain-structure** half of the tiered design
correctly (state short-circuit → interface-pair dispatch ladder → isolated leaf
chains, with `goto` dispatch). The **leaf set-matching** half is incomplete: the
structured rule path can only emit *independent* matches, not a single
concatenated key lookup (`ip daddr . tcp dport @set`). The concatenated form is
reachable only via `raw:` plus a hand-declared bare set.

## What works today

Tiered output renders as intended. For a host policy with a `forward` base chain
and zone-pair dispatch:

```nft
chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "eth1" oifname "eth0" goto lan_to_wan
    iifname "eth1" oifname "eth4" goto lan_to_svc
    iifname "eth0" oifname "eth2" goto wan_to_dmz
    iifname "eth3" goto mgmt_out
}
```

- state-first short-circuit ✓
- zone names resolve to devices via interface defs (`lan` → `eth1`) ✓
- dispatch emits `goto` (not `jump`), so leaf fall-through hits `policy drop`
  instead of walking later dispatch lines ✓
- single-interface dispatch (`iif` with no `oif`) works ✓
- leaves are isolated — a `lan→wan` packet only sees `lan_to_wan` ✓

## The gap

A leaf written structurally:

```yaml
- name: lan_to_svc
  rules:
    - daddr: svc_hosts
      proto: tcp
      dport: postgres
      action: accept
```

emits **two independent matches**:

```nft
ip daddr @svc_hosts tcp dport 5432 accept
```

This is "dest in @svc_hosts AND port == 5432" — the **cartesian** product. It
cannot express the paired form where host A is allowed only on 443 and host B
only on 5432:

```nft
ip daddr . tcp dport @svc_pairs accept     # one key, host+port paired
```

### Root cause

In `rules.py`, `RuleRenderer.render()` appends address matches and proto/port
matches as separate space-joined parts:

```python
if "daddr" in rule:
    parts.append(f"{fam} daddr {addr['daddr'][fam]}")
...
parts.extend(self._proto_ports(rule))   # -> "tcp dport <x>" as its own part
```

There is no code path that joins fields with `.` into a single set reference.
`_addr()` / `_port()` each resolve to their own `@set` or literal independently.

### Current workaround (confirmed working)

A bare concatenated set + a `raw:` rule does emit the right thing:

```yaml
sets:
  - name: svc_pairs
    type: "ipv4_addr . inet_service"
    elements:
      - "10.0.10.5 . 443"
      - "10.0.10.6 . 5432"
chains:
  - name: leaf
    rules:
      - raw: "ip daddr . tcp dport @svc_pairs accept"
```

→

```nft
set svc_pairs {
    type ipv4_addr . inet_service
    elements = { 10.0.10.5 . 443, 10.0.10.6 . 5432 }
}
chain leaf {
    ip daddr . tcp dport @svc_pairs accept
}
```

But `raw:` bypasses validation, family-awareness, and definition resolution —
the reasons to use the structured path at all. It also forces the author to
hand-maintain the element list instead of composing it from definitions.

## Suggested fix

Teach the structured path a concatenation syntax that emits `field . field …
@set` and auto-builds the concatenated set from definitions.

### Proposed schema

```yaml
- match: [daddr, {dport: tcp}]     # ordered list of fields to concatenate
  set: svc_pairs                    # the named set to look up against
  action: accept
```

emitting:

```nft
ip daddr . tcp dport @svc_pairs accept
```

Field tokens map to the existing match vocabulary:
`saddr`/`daddr` → `ip{,6} saddr/daddr`, `{dport: tcp}` → `tcp dport`,
`{sport: udp}` → `udp sport`, `iif`/`oif` → `iifname`/`oifname`. Reuse the
existing key→expr mapping (cf. `_VMAP_KEYS`) so vmap and concat share one table.

### Set construction

When `set:` names a concatenated set, build its `type` and `elements` from the
ordered `match` field types:

- `daddr` / `saddr` → `ipv4_addr` or `ipv6_addr` (family-aware, same split logic
  as `_classify_family`)
- `{dport: tcp}` → `inet_service`

so the type string (`ipv4_addr . inet_service`) is derived, not hand-written.
Elements come from a definitions group of paired tuples, deduped/ordered the way
`build_sets` already does for single-field sets.

### Family handling

A concat set is single-family (same constraint as today's address sets). If the
address field resolves to both v4 and v6, emit per-family sets + per-family
rules (`svc_pairs_v4` / `svc_pairs_v6`), mirroring the existing
`render()` family-iteration loop and the `_classify_family` v4/v6 split error.

### Validation to add

- `match` field order must equal the set's key field order (else the lookup is
  silently wrong).
- reject mixing a concat `set:` with sibling independent match keys on the same
  rule (ambiguous).
- element arity must match the number of `match` fields.

## Touch points

- `rules.py`: `RuleRenderer.render()` — handle `match`/`set`; new `_concat()`
  helper; share key→expr map with `_vmap()`.
- `ir.py`: `build_sets()` / a new `_concat_set_from_definition()` — derive
  type + elements for concatenated definition groups.
- `definitions.py`: optionally a paired-tuple group form, or compose from
  existing networks × services with an explicit pairing.

## Priority

High for completeness of the tiered design: dispatch is already optimal; this is
the one piece between "structured rules" and "optimal leaf lookups." Until then,
per-pair leaves must use `raw:` + bare sets and lose validation/composition.
