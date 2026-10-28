# Changelog

What changed per release, newest first. Details are in the commit messages;
the *why* behind design choices is in [DECISIONS.md](DECISIONS.md).

Versioning: [semantic versioning](https://semver.org) from 1.0.0 on. A new
check that rejects input which rendered a wrong or broken ruleset is a fix,
not a breaking change.

## 1.2.0 — 2026-10-28

- New: connection marks. `ct-mark:` matches the connection's mark
  (`ct mark 0x1`, a number or a range); `set-ct-mark:` sets it (`"0x1"`) or
  saves the packet mark into it (`mark` → `ct mark set meta mark`); and
  `set-mark: ct-mark` restores it onto the packet
  (`meta mark set ct mark`). Recipe: docs/best-practices.md §8e.
- `set-mark` and `set-ct-mark` can't share a rule when one copies the
  other: the order would decide the result. Split them into two rules.

## 1.1.0 — 2026-10-24

- New: `reset: own-tables` on a host policy: the deploy file starts with one
  `destroy table` per rendered table instead of `flush ruleset`, so tables of
  other tools (Docker, Kubernetes, fail2ban) survive an apply. `flush` stays
  the default. Needs nft >= 1.0.7 and kernel >= 6.3.
  `render_tables(reset=…)`; `flush=True` keeps working.
- Single-file mode (`nftgen <policy.yaml>`) stays tables only and warns when
  the policy has `reset:`.

## 1.0.0 — 2026-10-18

The first release on PyPI (`pip install nftgen`).

### Breaking

- Rule values are schema-checked: an `action:` word outside `accept`, `drop`,
  `reject`, `return`, `continue`, `masquerade` or `reject with …` is an error
  (use `raw:` for others).
- Python 3.10 dropped; `requires-python >=3.11`.

### New

- `comment:` on rules, chains, set entries and tables — native nft comments.
- One value or a list on every matching key (`dport: [ssh, 8080]`,
  `saddr: [mgmt, 10.0.0.5]`); `ct: established` takes one state plain.
- `proto:` is optional when the ports come from services: each port keeps
  its own protocol (`meta l4proto . th dport { tcp . 53, udp . 53 }`).
- Concat vmap rows take `action:` (accept, drop, return, continue, jump, goto).
- `family: ip | ip6` for concat sets filled at runtime.
- Protocol numbers (`17`, `112`) are checked as their names everywhere.
- `render_tables(…, annotate=fn)`: an optional per-rule hook whose note is
  appended as a `# <note>` file comment (used by ansible-firewall's blame
  notes); output is unchanged without it.

### Fixed

Mistakes that rendered a wrong or broken ruleset now fail the
build with a clear error:

- `nftgen build <typo>` with no host policies; `--host` with a path or a
  pattern; two files for one host (`fw1.yaml` + `fw1.yml`).
- `type:`/`policy:`/`priority:` on a chain without `hook:`.
- `iif`/`oif` with a named interface set; `flow-offload:` to an undeclared
  flowtable; mark, `set-mss`, log level/group/prefix values.
- Duplicate map keys; a `sport`+`dport` vmap without a `proto` column; a port
  on a protocol without ports; reject/masquerade inside a vmap.
- `icmp`/`icmpv6` with dual-stack addresses render only their own family.
- `log:` with both `level` and `group` (nft refuses the pair).
- Flowtable `devices:` takes one group plain (`devices: wan` was read letter
  by letter); a device shared by two groups is listed once.
- Hand-written sets: `flags:` must be nft set flags (`auto-merge` isn't one);
  `flags:`/`elements:` take one value plain instead of letter by letter.
- Table `counters:`/`raw:` take one value plain (`counters: bad` rendered
  counters `b`, `a`, `d`); a blank `chains:` is empty instead of a crash;
  wrong shapes (`chains:` as a mapping, a non-text name, `concat:` as a
  string) are clean errors.
- `log: {}` logs; OS errors are clean errors; a closed stdout pipe exits
  quietly (141).

### Infra

Renovate (auto-merges minor updates after CI), weekly CI, a lint
job plus tests on Python 3.11–3.14.

## 0.7.0 — 2026-10-11

**Breaking:** named service sets are `(proto . port)` pair sets
(`type inet_proto . inet_service`); `dport`/`sport` vmaps are
`meta l4proto . th dport` pair lookups, and a bare port number there needs
`/tcp`.

- A named service set or a port vmap no longer opens a port on a protocol the
  service doesn't have (udp/80 for a tcp-only service) — proven on the wire.
- Include files are validated: a typo'd section (`rule:`), a file under the
  wrong list, or a non-list fragment is an error instead of contributing
  nothing (an empty `policy: drop` chain = a lockout on deploy).

## 0.6.0 — 2026-07-14

- `render_tables()` core + `PathResolver` / `DictResolver`: nftgen can be
  embedded as a render backend (sessrumnir's Ansible vars mode uses it).
- `Definitions.from_named_mappings()`, with both origins named in duplicate
  errors; malformed definition layers are clean errors.

## 0.5.0 — 2026-07-13

- `nftgen build <root> --host X --stdout`: render one host to stdout, write
  nothing.

## 0.4.0 — 2026-07-11

**Breaking:** interface keys renamed `iif`/`oif` → `iifname`/`oifname`
(matching nft); object names that are reserved nft keywords are an error.

- `iif:`/`oif:` index matching; `meter:` per-key rate limiting.
- `example-fleet/`: a realistic 3-site reference, replacing `example-poc/`.
- Behavioral (network-namespace) tests: the B01–B26 primitive matrix and the
  P01–P22 example-fleet matrix — which found that `flow-offload:` + `action:`
  in one rule drops the handshake; that form is now an error.
- CI on GitHub Actions: lint, tests incl. `nft -c` and netns, drift gate.

## 0.3.0 — 2026-07-05

- Large set/map literals render one element per line (one-line git diffs).
- Bare `dnat:`/`snat:` targets resolve single-address network groups.
- The netns behavioral test harness (rootless).

## 0.2.0 — 2026-07-05

**Breaking:** a strict authoring surface — unknown keys at every level,
undefined names, empty groups, include and definition cycles, and a missing
`tables:` fail the build instead of rendering a weaker or empty ruleset;
`build --check` fails loudly when `nft -c` can't run.

## 0.1.0 — 2026-06-28

The first release: definitions (networks, services, interfaces) with
composition and per-site overlays; tables, base and regular chains, named
sets, includes; rule keys for matches, statements (limit, quota, log,
set-mark, set-mss, counters, flow-offload), tcp flags, icmp types, NAT
including a dnat port map; inline vmaps (incl. concatenated keys) and
concatenation sets; `nftgen build <root>` producing one complete
`flush ruleset` deploy file per host; `nft -c` validation.
