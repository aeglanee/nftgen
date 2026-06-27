# The not-automated side — what stays yours

A–D automate things that are **mechanical and always-correct** (translation,
derivation, dedup). This side is **intent and policy** — and intent can't be
safely guessed. Guessing it *is* the footgun, so nftgen refuses to invent it.

## What stays author-defined (and why automating it would be a footgun)

| Stays yours | Why it can't be safely automated |
| --- | --- |
| **Which flows are allowed** (incl. **concatenation tuples**) | only you know the policy; a guess is a security hole (too permissive) or an outage (too strict) |
| **Chain structure** — base + regular chains | auto-generating chains is the lossy abstraction nftgen rejects; you'd debug a model that isn't nft's (DECISIONS §1.1) |
| **Default policy direction** | `drop` is the safe *fallback* when omitted, but you choose — nftgen can't know a chain should pass (`nat` → `accept`) vs gate (`drop`) |
| **set-vs-inline** | a per-table perf/readability tradeoff only you can weigh (DECISIONS §2.3) |
| **conntrack / counters / `ct state`** | injecting them = surprises in generated rules = a firewall you can't predict = can't trust (DECISIONS §1.5) |
| **rule order** | first-match-wins is load-bearing; order is yours (see [dedup-ordering.md](dedup-ordering.md)) |

## Proof: nftgen injects nothing

One authored rule → exactly one rule. No auto conntrack, no auto loopback-accept,
no auto counters:
```yaml
chains:
  - name: input
    hook: input
    priority: filter
    policy: drop
    rules:
      - proto: tcp
        dport: 22
        action: accept
```
→
```nft
chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 22 accept
}
```
An empty chain stays empty (no invented structure):
```nft
chain forward {
    type filter hook forward priority 0; policy drop;
}
```

## The line, restated

**Mechanical + always-correct → automate (A–D). Intent + policy → author.**

This is also why best practices (conntrack-early, default-deny, sets over rule
lists) are *easy defaults you choose*, not things forced on you — see
[../best-practices.md](../best-practices.md).

## Where concatenation sits

The concatenation tuples are the canonical "not automated": **you** define which
source pairs with which destination:port (intent), and nftgen automates the set
*type*, *family split*, and *match syntax* around them (A, B, D). So promoting
concatenation to a structured key is "let you express the intent cleanly with
validation + composition," **never** "guess the pairings." See
[concatenations.md](../concatenations.md).
