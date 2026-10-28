# Testing

What the tests prove, how to run them, and the behavioral matrix.

## Layers

| # | Layer | Proves | Where |
| --- | --- | --- | --- |
| 1 | unit + golden | YAML → the exact expected text | `tests/` |
| 2 | `nft -c` | the text is a ruleset nft accepts | `tests/test_validate.py` and others |
| 3 | drift | committed renders reproduce from source | pytest + CI (`example-fleet/generated`) |
| 4 | behavioral | packets are accepted or dropped as authored | `tests/behavioral/` |
| 5 | deploy | the role ships, applies and rolls back safely | ansible-firewall molecule; sessrumnir scenarios |

`nft -c` passes dead rules, empty rulesets and rules that never match, so
layer 4 exists: syntax is not semantics. Behavioral tests assert traffic
outcomes only, never text — layers 1–3 already pin rendering, family checks,
build errors and determinism.

## Running

- `make verify` — lint + tests. **Put `nft` and `ip` on `PATH` first**:
  without them the `nft -c` and behavioral tests skip (70 of 426) and the
  run still looks green. Where they aren't on `PATH` (e.g. NixOS without a
  dev shell), from the Nix store:

  ```bash
  nft=$(ls -d /nix/store/*-nftables-*/bin | head -1)
  ip=$(ls -d /nix/store/*-iproute2-*/bin | head -1)
  PATH=$nft:$ip:$PATH make verify
  ```

- One file: `pytest tests/test_vmaps.py -v`.
- `nft -c` on a file by hand: plain `nft -c` fails in a `NoNewPrivs` sandbox
  (netlink); `unshare -rn nft -c -f <file>` works. `validate.py` falls back to
  it, so `nftgen build --check` works there too.
- CI runs everything on Python 3.11–3.14; the runner enables unprivileged
  user namespaces so the behavioral tests run instead of skipping.

## Behavioral harness

Network namespaces, no VM, rootless (`unshare -rn`):

- A **router** namespace holds the ruleset under test, with one veth per
  zone into peer namespaces (`client`, `server`, `wan`, …). `link` adds a
  veth between any two of them, e.g. a second router (B32).
- The **rendered file is applied verbatim** (`nft -f generated/<host>.nft`) —
  the deploy artifact, not a copy.
- Probes tell three outcomes apart: connected, refused (reject), timeout
  (drop). Counters, sets and logs are read back for state checks.
- Tests skip cleanly where user namespaces, veth, nft or conntrack are
  missing.
- iproute2 7.x needs `ip link add name X type veth …` (explicit `name`).

### Primitives (B01–B32)

One small fixture per concern under `tests/behavioral/fixtures/`.

| ID | Behavior | Probe | Expected |
| --- | --- | --- | --- |
| B01 | base-chain default drop | unsolicited TCP SYN to the router | timeout, not refused |
| B02 | ct established/related return path | client→server through forward | handshake completes |
| B03 | unsolicited inbound on B02's port | server→client SYN, no prior flow | timeout |
| B04 | ct invalid drop | out-of-state ACK | timeout; `ct state invalid` counter rises |
| B05 | input vmap on `iifname` | same port from two zones | zone A accepted, zone B dropped |
| B06 | zone missing from the vmap | probe from an unlisted zone | chain policy (drop) |
| B07 | concat vmap `[iifname, oifname]` | allowed pair, then reversed | allowed passes; reverse times out |
| B08 | group expansion in a vmap | via both members of a 2-device group | same verdict chain |
| B09 | named set membership | member vs non-member IP | member matches; non-member falls through |
| B10 | bogon drop + named counter | spoofed rfc1918 source into wan | timeout; `bogon_drops` rises |
| B11 | concat set tuple | exact tuple, then right source + wrong port | exact passes; near miss drops (no cartesian bleed) |
| B12 | live timeout set | `nft add element`, probe, wait past timeout, probe | blocked, then unblocked |
| B13 | dnat, one target | wan → router:8080 | reaches the inner server with the original source |
| B14 | dnat map | wan → :80 and :2222 | each reaches its own host |
| B15 | dnat map fall-through | wan → unmapped port | forward policy drops |
| B16 | forward leg after dnat | as B13/B14 with a forward allowlist | only dnat'd services pass |
| B17 | masquerade / snat | lan → wan server | server sees the router's address |
| B18 | icmp per family | v4 and v6 ping through one policy | both answered; v6 neighbour discovery works |
| B19 | limit | ping flood above the limit | about the limit answered |
| B20 | quota | stream past the quota | stalls once it runs out |
| B21 | counters | M packets on a counted rule | counter ≥ M |
| B22 | dport vmap per service | ssh vs metrics; tcp to a udp-only service | each lands in its chain; tcp/7004 (only `7004/udp` mapped) times out — the pre-0.7.0 port vmap connected |
| B23 | flowtable | long-lived flow with `flow-offload` | flow continues. Found a bug: `flow-offload` + `action:` in one rule skips the verdict, now a build error |
| B24 | tcp flags scrub | crafted fin+syn and null-scan segments | dropped, `bad_tcp` rises; a normal SYN still answered |
| B25 | log | renders only (kernel log capture isn't portable in a namespace) | n/a |
| B26 | reapply | `nft -f` the same file twice | succeeds; ruleset identical |
| B27 | named service set keeps proto | `app: [7000/tcp, 7001/udp]` named + `proto: tcp` | tcp/7000 connects; tcp/7001 times out — the pre-0.7.0 port-only set connected |
| B28 | anti-spoofing, strict `fib` (best-practices §5) | lan client probes with a wan-subnet source; a `0.0.0.0` → broadcast DHCPDISCOVER frame | spoof dropped + `rpf_drops` rises (own address passes); DHCP arrives, nothing counted |
| B29 | `reset: own-tables` beside a foreign table | a foreign `inet foreign` (counts 7000, drops 7001) loaded first, then the artifact | 7000 connects and the foreign counter rises; 7001 (accepted by ours) times out on the foreign drop |
| B30 | own-tables reapply | apply the artifact again | ruleset identical; `inet foreign` still there |
| B31 | own-tables, own table missing | `nft delete table inet filter`, then apply | applies (`destroy` of a missing table is a no-op); 7000 connects, 7001 still dropped |
| B32 | router pair, one-way flows returned by connection marks (best-practices §8e) | the client's gateway is router A, its target is router B's own address; A drops `ct state invalid`; B runs a `ct-mark` variant | no recipe: v4 + v6 time out, A counts invalid; recipe: both connect; + strict §5 `fib`: both time out, + mark restored in prerouting: both connect; kernel `rp_filter=1`: v4 times out, + restore + `src_valid_mark`: both connect |

### Reference fleet (P01–P22)

[example-fleet/](../example-fleet/) host **hq-r**, one veth per zone (users,
services, dmz, nwm, transit, wan). Every row runs through the skeleton,
includes, site definitions and fleet sets together. Cross-site traffic is
sourced from the transit veth with a branch address; a true two-router test
is on the backlog.

| ID | Flow | Expected |
| --- | --- | --- |
| P01 | users → local services: web, dns, ntp | accept |
| P02 | users → local services: ssh | drop (only nwm manages services) |
| P03 | users → local services: postgres | accept (site-local app) |
| P04 | users → local dmz: web | accept |
| P05 | users → local dmz: ssh | drop |
| P06 | users → internet: web, dns, ntp | accept, masqueraded |
| P07 | users → internet: smtp | drop + `fwd-users-inet-drop` log |
| P08 | dmz → users | drop (only established return traffic) |
| P09 | nwm → local services: ssh, snmp | accept |
| P10 | `hq_monitor` → services: 9100 | accept (metrics pull) |
| P11 | nwm → local services: web | drop (management ports only) |
| P12 | wan → router, any port | drop |
| P13 | wan, spoofed rfc1918 source → forward | drop + `bogon_drops` |
| P14 | wan, crafted syn+fin → forward | drop + `bad_tcp` |
| P15 | wan → :80, :443 | dnat to the dmz web host, served |
| P16 | wan → :23 (unmapped) | drop |
| P17 | transit `all_users` → `hq_central` ldaps | accept |
| P18 | transit `br1_app` → `hq_db` postgres | accept; any other source drops |
| P19 | lan egress source seen by a wan peer | the router's wan address |
| P20 | runtime blocklist add of a users IP | blocked until the timeout |
| P21 | icmp echo v4 to the router; bad tcp flags | rate-limited answers; flags still dropped |
| P22 | a dropped flow's log | NFLOG group gets `fwd-<pair>-drop` |

## Known environment limits

- **`dscp set`** (`ip dscp set ef`) parses, but a kernel can refuse it with
  "Operation not permitted" inside a rootless namespace, so DSCP recipes
  aren't load-tested.
- **`iif`/`oif`** need the interface to exist when the ruleset loads; `nft -c`
  fails on a box without it.
- **`destroy table`** (`reset: own-tables`: router2's `nft -c`, B29–B31) needs
  nft ≥ 1.0.7 and kernel ≥ 6.3; older boxes fail those tests instead of
  skipping.
