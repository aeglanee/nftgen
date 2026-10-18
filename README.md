# nftgen

[![ci](https://github.com/aeglanee/nftgen/actions/workflows/ci.yml/badge.svg)](https://github.com/aeglanee/nftgen/actions/workflows/ci.yml)

A small, **nftables-only** firewall-as-code generator: YAML definitions +
host policies → one native `.nft` ruleset per host, applied with `nft -f`.

- **It mirrors nftables.** Tables → chains → rules, sets, maps: you write
  your own chains, and the YAML reads like the ruleset it becomes.
- **Definitions** (`networks`, `services`, `interfaces`) compose by name,
  per site; nftgen derives set types, splits rules per address family and
  keeps each port with its protocol.
- **Strict.** Unknown keys, undefined names and values of the wrong shape
  fail the build; nothing is guessed, optimized or injected.
- **Deterministic.** The same input gives the same bytes, so a diff of the
  output is a real rule change.
- **`raw:`** reaches anything nft can do that has no key yet.

Latest release **v0.7.0**; `main` has unreleased changes (see
[CHANGELOG.md][changelog]).

## Example

```yaml
# definitions/networks.yaml
networks:
  mgmt: [192.168.9.0/24, fd00:9::/64]
# definitions/services.yaml
services:
  ssh: [22/tcp]
# policies/hosts/gw1.yaml
tables:
  - family: inet
    name: filter
    chains:
      - name: input
        hook: input
        rules:
          - ct: [established, related]
            action: accept
          - saddr: mgmt
            proto: tcp
            dport: ssh
            action: accept
```

`nftgen build .` → `generated/gw1.nft`:

```nft
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ip saddr 192.168.9.0/24 tcp dport 22 accept
        ip6 saddr fd00:9::/64 tcp dport 22 accept
    }
}
```

## Use

```bash
pip install "nftgen @ git+https://github.com/aeglanee/nftgen@v0.7.0"

nftgen build <root>                       # every host → <root>/generated/
nftgen build <root> --host gw1 --stdout   # one host to stdout, write nothing
nftgen build <root> --check               # also validate each file with nft -c
```

Each output is a complete file (`flush ruleset` + the host's tables) that
ships as `/etc/nftables.conf`. With Ansible, the
[ansible-firewall](https://github.com/sessrumnir/ansible-firewall)
collection renders from inventory variables instead and applies behind a
rollback timer ([DEPLOYMENT.md][deployment]).

## Docs

- [docs/authoring.md][authoring] — **start here**: firewall
  structure, adding a rule, which tool to use.
- [DESIGN.md][design] — the reference: every key and what it renders to.
- [DECISIONS.md][decisions] — why it's built this way.
- [docs/best-practices.md][best-practices],
  [docs/sets-and-performance.md][sets-and-performance],
  [docs/maps.md][maps], [docs/raw.md][raw] — nftables
  cookbooks, every example checked with `nft -c`.
- [example-fleet/][example-fleet] — a realistic 3-site reference;
  [example/][example] — a small one.
- [CHANGELOG.md][changelog] · [TODO.md][todo] ·
  [docs/testing.md][testing].

## Develop

```bash
make install-dev   # .venv with nftgen (editable), linters, pre-commit hook
make verify        # lint + tests — put nft and ip on PATH, see docs/testing.md
```

## License

MIT (see [LICENSE][license]). The definitions model reimplements concepts
from [Aerleon](https://github.com/aerleon/aerleon) (Apache-2.0) clean-room —
no Aerleon code is used; the acknowledgment is courtesy, not a license
obligation.

[authoring]: https://github.com/aeglanee/nftgen/blob/main/docs/authoring.md
[best-practices]: https://github.com/aeglanee/nftgen/blob/main/docs/best-practices.md
[changelog]: https://github.com/aeglanee/nftgen/blob/main/CHANGELOG.md
[decisions]: https://github.com/aeglanee/nftgen/blob/main/DECISIONS.md
[deployment]: https://github.com/aeglanee/nftgen/blob/main/DEPLOYMENT.md
[design]: https://github.com/aeglanee/nftgen/blob/main/DESIGN.md
[example]: https://github.com/aeglanee/nftgen/tree/main/example/
[example-fleet]: https://github.com/aeglanee/nftgen/tree/main/example-fleet/
[license]: https://github.com/aeglanee/nftgen/blob/main/LICENSE
[maps]: https://github.com/aeglanee/nftgen/blob/main/docs/maps.md
[raw]: https://github.com/aeglanee/nftgen/blob/main/docs/raw.md
[sets-and-performance]: https://github.com/aeglanee/nftgen/blob/main/docs/sets-and-performance.md
[testing]: https://github.com/aeglanee/nftgen/blob/main/docs/testing.md
[todo]: https://github.com/aeglanee/nftgen/blob/main/TODO.md
