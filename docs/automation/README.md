# Automation — what nftgen derives for you, and what it won't

nftgen automates the **mechanical, always-correct** parts of writing nftables, and
**refuses** the parts that require intent it can't safely guess. This directory
documents each automation as **define-it-like-this → generates-like-this**, with the
defaults and how to override them.

## The principle

Something is **safe to automate** when its output is:
1. **uniquely determined** by what you wrote (no judgement call), and
2. **always correct** — if it were ever wrong, `nft -c` rejects it loudly (it can't
   silently mislead, unlike a wrong-but-valid rule), and
3. **overridable** — there's an explicit escape hatch for the rare case where your
   intent diverges.

The pattern everywhere: **derive the always-correct default, leave an explicit
escape for real intent.** Guessing *intent* (which flows, which structure, which
optimization) is the "no optimizer / no magic" line — that stays yours.

## Safe to automate

| # | Automation | Doc |
| --- | --- | --- |
| A | **Set type + `interval` flag** — derived from the members | [set-type.md](set-type.md) |
| B | **Family split (v4/v6)** — render per family, error on incompatible mixes | [family-split.md](family-split.md) |
| C | Dedup + deterministic ordering | _pending_ |
| D | Match-expression syntax — key → nft tokens | _pending_ |

## Not safe to automate (stays author-defined)

_pending — which flows are allowed (concatenation tuples), set-vs-inline, default
policies, conntrack/counters placement, structure (no auto-chains)._
