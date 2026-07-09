# nftables sets, intervals & performance

Pure nftables background (not nftgen-specific): how sets are stored, why
`interval` exists, and how you'd define things *if you were optimising for
performance*. At homelab/small-fleet scale this is mostly FYI — pick sets for
readability/reuse, not speed (see the bottom line). For nftgen's policy on this,
see DECISIONS §1.2 ("no optimizer").

---

## 1. Three ways to match N things — three costs

| Approach | Per-packet cost | Can hold CIDRs/ranges? |
| --- | --- | --- |
| **hash set** (plain) | **O(1)** — constant, size-independent | ❌ exact values only |
| **interval set** (`flags interval`) | **O(log N)** — tree search | ✅ yes |
| **N separate rules** | **O(N)** — linear scan | ✅ (a rule can be anything) |

Worst-case comparisons per packet:

| N | hash O(1) | interval O(log₂N) | N rules O(N) |
| ---: | ---: | ---: | ---: |
| 1 | 1 | ~1 | 1 |
| 3 | 1 | ~2 | 3 |
| 50 | 1 | ~6 | 50 |
| 1,000 | 1 | ~10 | 1,000 |

Two caveats that stop this being "always use hash":

- **Big-O is *scaling*, not absolute speed.** O(1) means "doesn't grow with
  N," not "fastest." At small N the constant factor (hashing + memory
  indirection) can make a hash lookup *slower* in wall-clock than scanning 3
  items.
- **hash can't hold prefixes/ranges.** A plain set literally rejects
  `192.168.0.0/24` (`nft` error: *"must add 'flags interval' for prefix
  elements"*). Firewalls match subnets constantly, so for that data interval
  isn't a choice — it's required.

---

## 2. The two backends

- **Plain set** → **hash table**, **O(1)**, **exact values only** (single IPs, single
  ports). What you want for large lists of *exact* things.
- **Interval set** (`flags interval`) → **red-black tree** (newer kernels: "pipapo"),
  **O(log N)**, holds **ranges and CIDR prefixes** (`10.0.0.0/8`, `1024-65535`).
  Mandatory the moment an element isn't an exact value.

(Both beat **N separate rules** (O(N)) at scale — that linear scan is the
thing sets exist to replace.)

---

## 3. How you define a set in nftgen (the two places)

A `@named` set comes from **two** author actions:

1. **`definitions/networks.yaml`** (or services/interfaces) defines the *members*:

   ```yaml
   networks:
     web_servers: [192.0.2.10, 192.0.2.11]
   ```

2. **the table's `sets:`** lists the name → it emits as a `@named` set; omit
   it and the same reference **inlines** as an anonymous `{ … }`:

   ```yaml
   tables:
     - family: inet
       name: filter
       sets: [web_servers]        # <-- makes @web_servers a named set
   ```

→ generated nft (note `flags interval`, added by nftgen, *not* by you):

```nft
set web_servers {
    type ipv4_addr
    flags interval
    elements = { 192.0.2.10, 192.0.2.11 }
}
```

**nftgen always adds `flags interval` to network sets** — because a `networks` group
*may* contain a CIDR, and it doesn't inspect each group to find out. Correct always;
slightly suboptimal for all-exact sets (uses the tree backend where hash would do).
Service sets are the opposite: hash by default, `interval` only when a *port range*
appears.

---

## 4. "Ideal" definitions if you were optimising for performance

| Your data | Best structure | nftgen today |
| --- | --- | --- |
| many **exact** IPs/ports, large N | **hash set** (no interval) → O(1) | networks always get `interval` (tree); services w/o ranges already hash |
| **CIDRs / ranges** | **interval set** (no choice) | ✅ correct |
| **multi-field, specific flows** (saddr+daddr+dport tuples) | **concatenated set** → *one* combined lookup | ✅ `concat:`/`tuples:` set + `set:` rule |
| a handful of things | doesn't matter — inline or a few rules | ✅ author's choice |

On the concatenated set: a `saddr . daddr . dport` lookup is **one**
O(1)/O(log N) hit over the combined key. The alternative for *specific*
flows is either **many rules** (O(N), linear) or **independent set
matches** — which are 3 separate lookups *and* semantically wrong (they
allow the cartesian cross-product). So a concat set is both **more
correct** (paired tuples) **and** a single efficient lookup. That's why
it was promoted to a structured key (`concat:`).

---

## 5. Bottom line for our scale

At homelab/small-fleet N (tens, low hundreds), all three structures are within noise
of each other — so **define sets for readability and reuse, not speed.** The hash-vs-
tree distinction only becomes measurable in the **hundreds-plus** (datacenter/fabric
territory), and that's exactly why nftgen has **no optimizer**: at the scale it
targets, "the fastest structure" has no meaningful answer, so it stays dumb and
always-correct and leaves set-vs-inline to you.
