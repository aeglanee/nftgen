# A. Set type + `interval` flag (derived from members)

When you list a definition under a table's `sets:`, nftgen derives the nft set
**`type`** and **flags** from the members — you never write them. All examples below
are `nft -c`-verified.

## Define → generate (the defaults)

```yaml
# definitions/networks.yaml
networks:
  hosts4: [192.0.2.10, 192.0.2.11]     # exact v4 hosts
  net4:   [10.0.0.0/8]                 # a v4 CIDR
  hosts6: [2001:db8::1, 2001:db8::2]   # exact v6 hosts
# definitions/services.yaml
services:
  ssh:  [22/tcp]                       # single port
  etcd: [2379-2380/tcp]                # a port range
# definitions/interfaces.yaml
interfaces:
  wan: [wan0, wwan0]
```

```yaml
# in the table
sets: [hosts4, net4, hosts6, ssh, etcd, wan]
```

generates:

```nft
set hosts4 { type ipv4_addr
    flags interval
    elements = { 192.0.2.10, 192.0.2.11 } }

set net4   { type ipv4_addr
    flags interval
    elements = { 10.0.0.0/8 } }

set hosts6 { type ipv6_addr
    flags interval
    elements = { 2001:db8::1, 2001:db8::2 } }

set ssh    { type inet_service
    elements = { 22 } }                       # no interval -> hash backend

set etcd   { type inet_service
    flags interval                            # range -> interval
    elements = { 2379-2380 } }

set wan    { type ifname
    elements = { "wan0", "wwan0" } }
```

| You define | Derived type | `interval`? | Why |
| --- | --- | --- | --- |
| v4 addresses | `ipv4_addr` | **yes** | a network group may contain a CIDR |
| v6 addresses | `ipv6_addr` | **yes** | same |
| a port | `inet_service` | no → **hash** | exact value, O(1) |
| a port **range** | `inet_service` | **yes** | ranges need interval |
| device names | `ifname` | no | exact strings |

**Default rationale:** networks always get `interval` (always correct — a CIDR
*requires* it, and nftgen doesn't inspect each group to special-case all-exact ones).
Services get `interval` only when a range is actually present. The type itself
is uniquely fixed by the members, and `nft -c` rejects any mismatch — so this
can't be silently wrong.

## Overriding (the escape hatch: a bare set)

When you need something other than the derived default, declare a **bare set** —
you specify `type` / `flags` / `elements` yourself:

```yaml
sets:
  - name: bighosts
    type: ipv4_addr        # NO interval -> hash backend, O(1)
    elements: [203.0.113.5, 203.0.113.6]
```

→

```nft
set bighosts {
    type ipv4_addr
    elements = { 203.0.113.5, 203.0.113.6 }
}
```

Reach for a bare set when your intent diverges from "just hold these members":

| Want | How |
| --- | --- |
| **hash** backend for a large all-exact set (perf) | bare set, omit `interval` |
| a **live** set filled at runtime (`nft add element`) | bare set, `flags: [timeout]`, no `elements` |
| exotic flags (`constant`, `dynamic`, concat `type: "ipv4_addr . inet_service"`) | bare set, set them explicitly |

Trade-off: a bare set bypasses definition composition (you hand-maintain the
elements) — that's the cost of overriding.

## Guardrail (where derivation refuses)

A definition-backed set is **single-family**. Mixing v4 and v6 is a loud
error, not a silent widening:

```yaml
networks:
  bad: [192.0.2.1, 2001:db8::1]
```

```text
nftgen.ir.BuildError: set 'bad' mixes IPv4 and IPv6; a named set is
single-family — split into e.g. bad_v4 / bad_v6
```

This is deliberate — see DECISIONS §2.4 (designs out Aerleon's silent-widen footgun).
