# Concatenation: how to author the tuples (options)

> **Status: BUILT — Option 1.** The schema below is implemented (see
> `tests/test_concat.py`). The options/comparison are kept as the decision record.
> *Refinement during build:* the proto moved out of the field list to a set-level
> `proto:` key (cleaner than the inline `{dport: tcp}`):
>
> ```yaml
> sets:
>   - name: db_flows
>     concat: [saddr, daddr, dport]   # fields: saddr/daddr/sport/dport/iif/oif/mark
>     proto: tcp                       # required when a port field is present
>     tuples:
>       - [app_host, db_host, postgres]   # literals or single-value definition names
>       - [10.0.1.11, 192.0.2.21, 8443]
> rules:
>   - set: db_flows
>     action: accept
> ```
>
> nftgen derives the type, resolves names via definitions, auto-adds `interval` for
> ranges, family-splits errors on mixed v4/v6, and enforces **one element per field**
> (multi-value → error → use a regular rule). Single-proto for now; `proto: [tcp,udp]`
> and per-row `proto` field are follow-ons. The *why* (cartesian vs paired) is in
> [concatenations.md](concatenations.md) and [best-practices.md](best-practices.md) §2/§6.

Concatenation expresses **specific paired flows** — "client A may reach server X
*only* on 443, client B server Y *only* on 5432" — as a single set lookup over a
combined key, instead of independent matches (which would allow the cartesian
cross-product A→Y, B→X) or N separate rules.

The feature has **two halves**: the **set** (holds the tuples and their field
types) and the **rule** (references the set). The rule side is the same for every
option; the decision is **how you author the tuples**.

---

## The rule side (same for all options)

The set already knows its field order, so the rule just names it — no repetition:

```yaml
rules:
  - set: db_flows        # field order comes from the set declaration
    action: accept
```
→
```nft
ip saddr . ip daddr . tcp dport @db_flows accept
```

---

## Option 1 — Inline tuples on the set  ·  **recommended**

```yaml
sets:
  - name: db_flows
    concat: [saddr, daddr, {dport: tcp}]    # ordered fields -> derives the type
    tuples:
      - [10.0.1.10, 192.0.2.10, 5432]       # each row = one explicit flow
      - [10.0.1.11, 192.0.2.11, 5432]
```
→
```nft
set db_flows {
    type ipv4_addr . ipv4_addr . inet_service
    elements = { 10.0.1.10 . 192.0.2.10 . 5432, 10.0.1.11 . 192.0.2.11 . 5432 }
}
```

- **Each tuple is one concrete flow** — maximally explicit; the policy *is* the
  list. Tuple values may be literals *or* single-value definition names
  (`[ssh_host, db_host, 5432]`) for light composition.
- Directly upgrades today's raw workaround: you stop hand-writing
  `"10.0.1.10 . 192.0.2.10 . 5432"` strings and gain validation + family-awareness.

**Pros:** simplest, smallest build, perfectly matches "tuples = author-defined
intent."
**Cons:** verbose for *many* flows; no group expansion.

---

## Option 2 — Compose from groups with a pairing strategy

```yaml
sets:
  - name: db_flows
    concat: [saddr, daddr, {dport: tcp}]
    from: [clients, servers, db_ports]   # three existing definition groups
    pair: zip                            # positional 1:1  (or `product` = cartesian)
```

With `clients=[A,B]`, `servers=[X,Y]`, `db_ports=[5432]`:
- `pair: zip` → `A.X.5432, B.Y.5432` (positional)
- `pair: product` → `A.X.5432, A.Y.5432, B.X.5432, B.Y.5432` (cartesian)

**Pros:** DRY, reuses definitions, compact for many flows.
**Cons:** `zip` silently misbehaves if the groups drift to different lengths;
`product` re-introduces the cartesian you were avoiding (explicit here, but easy
to misuse); more "magic" to reason about.

---

## Option 3 — A first-class `flows:` definition category

```yaml
# def/flows.yaml  (a new category alongside networks / services / interfaces)
flows:
  db_access:
    fields: [saddr, daddr, {dport: tcp}]
    tuples:
      - [10.0.1.10, 192.0.2.10, 5432]
```
```yaml
# any host references it
sets: [db_access]
rules:
  - set: db_access
    action: accept
```

**Pros:** reusable across hosts (defined once, like networks); fits the `def/`
mental model.
**Cons:** a new top-level category + a richer (fields+tuples) schema — the
biggest change.

---

## Comparison

| | Explicitness | Composition | Build size | Footgun risk |
| --- | --- | --- | --- | --- |
| **1 — inline tuples** | ★★★ | light (single-value names) | **smallest** | low |
| 2 — from-groups + `pair` | ★★ | strong | medium | `zip` drift / `product` cartesian |
| 3 — `flows:` category | ★★★ | strong (fleet-wide) | largest | low |

## Recommendation

**Option 1 now; Option 3 later if reuse demands it.**

- **Option 1** is the smallest correct cut, the most explicit (the point — tuples
  are intent), and immediately replaces the raw workaround with a validated,
  family-aware, composable-by-name form.
- **Option 2** trades real footguns (`zip` drift, `product` cartesian) for
  compactness we don't yet need — **skip**.
- **Option 3** is genuinely nice for *fleet-wide reuse*, but it's a bigger schema
  change. Option 1's `tuples:` schema **lifts cleanly into** a `flows:` category
  later with no rework — so start simple, promote if repetition across hosts
  actually appears.

## What nftgen derives / checks regardless of the option

These are automated (the mechanics — see [automation/](automation/)); only the
tuples themselves are author-defined:

- **Set `type`** from the field list (`saddr`→`ipv4_addr`, `{dport: tcp}`→`inet_service`).
- **Family split** — if the address fields resolve to both v4 and v6, emit
  `db_flows_v4` / `db_flows_v6` + per-family rules (single-family rule, as today).
- **Arity check** — each tuple's length must equal the field count.
- **Match syntax** — `ip saddr . ip daddr . tcp dport @set`, field order taken
  from the set's `concat:` (so the rule never restates it).
