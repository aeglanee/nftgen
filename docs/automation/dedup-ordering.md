# C. Dedup + deterministic ordering

nftgen removes exact duplicates during definition expansion and emits
**deterministically** — same input → byte-identical output. Crucially, it only
normalizes order where order is *semantically irrelevant*, and never where it
matters. Examples `nft -c`-verified.

## Define → generate (dedup)

```yaml
networks:
  web1:    [192.0.2.10]
  group_a: [web1, 192.0.2.10, 192.0.2.11]   # web1 -> .10, then literal .10 again, then .11
```

```yaml
sets: [group_a]
```

→

```nft
set group_a {
    type ipv4_addr
    flags interval
    elements = { 192.0.2.10, 192.0.2.11 }    # the duplicate .10 collapsed; order kept
}
```

The composition pulled `192.0.2.10` in twice (via `web1` and the literal); the
duplicate is dropped, first-seen order preserved (`list(dict.fromkeys(...))`).

> Note: nft actually *tolerates* an exact duplicate in a set declaration (verified
> — `{ .10, .10 }` passes `nft -c`). So dedup is for **clean, deterministic
> output**, not to avoid an nft error.

## What's preserved vs sorted

| Thing | Behaviour | Why it's safe to normalise |
| --- | --- | --- |
| **rule order in a chain** | **preserved exactly — never reordered** | first-match-wins; order is load-bearing |
| set elements | deduped, author order kept | a set is unordered; membership ignores order |
| per-family lines | sorted (`ip` before `ip6`) | the two lines are independent; sort just fixes the tie |
| file merge (`definitions/*.yaml`) | sorted by filename | files on disk have no author order |

The rule: dedup/sort touches only **set membership**, **independent per-family
lines**, and **file-merge order** — none of which change what the firewall does.
The one place order is semantically critical — your **rule sequence** — is rendered
verbatim.

## Why it's safe to automate

- **It can't change behaviour.** It normalises only the things whose order is
  semantically irrelevant; rule order is untouched.
- **Dedup is a no-op semantically.** An exact-duplicate element is redundant.
- **Determinism is a correctness property** (DECISIONS §2.5), not cosmetics.

## Why it matters

Deterministic output is the foundation of git-diff change-detection in the deploy
pipeline (DEPLOYMENT §4): a committed `.nft` that differs means a *real* rule
change, never reordering noise. If output weren't deterministic, every regenerate
would churn the diff and "which hosts changed?" would be meaningless.

## Override?

**None — and there's no legitimate reason to want one.** Nobody wants
nondeterministic output, duplicate elements, or auto-reordered rules. You already
control the part that matters (rule order, and set-element order via the
definition); nftgen only normalises what you don't.
