"""Phase 4 — full host -> .nft, includes, and the per-site overlay (golden)."""

import pathlib
import textwrap

import pytest

from nftgen.generate import generate
from nftgen.ir import BuildError

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "example"
GOLDEN = pathlib.Path(__file__).resolve().parent / "golden"


def _gen(host: str) -> str:
    return generate(
        EXAMPLE / "policies" / "hosts" / host,
        defs_dir=EXAMPLE / "definitions",
        include_base=EXAMPLE / "policies",
        sites_dir=EXAMPLE / "sites",
    )


@pytest.mark.parametrize("host", ["router1.yaml", "router2.yaml", "gateway.yaml"])
def test_matches_golden(host):
    expected = (GOLDEN / host.replace(".yaml", ".nft")).read_text()
    assert _gen(host) == expected


def test_gateway_showcases_all_capabilities():
    out = _gen("gateway.yaml")
    assert "flowtable ft {" in out  # 6C
    assert "flow add @ft" in out
    assert "counter bad_tcp {" in out  # 6B
    assert "iifname vmap {" in out  # 6D
    assert (
        "tcp flags & (fin|syn) == (fin|syn) counter name bad_tcp drop" in out
    )  # 6E + named counter
    assert "limit rate 4/minute" in out  # 6A limit
    assert 'log prefix "ssh-excess "' in out  # 6A log
    assert "maxseg size set rt mtu" in out  # 6A mss
    assert "meta mark set 0x1" in out  # 6A mark
    assert "quota over 10240 mbytes" in out  # 6A quota
    assert "ip saddr 192.168.10.0/24" in out  # per-site overlay
    assert "dnat ip to 192.168.10.50:443" in out  # dnat, family-qualified for inet


def test_site_overlay_differs_per_host():
    assert "192.168.10.0/24" in _gen("router1.yaml")  # site1
    assert "192.168.20.0/24" in _gen("router2.yaml")  # site2


def test_per_table_set_named_vs_inline():
    out = _gen("router1.yaml")
    # `wan` is a named set in the filter table...
    assert "set wan {" in out
    assert "oifname @wan" in out
    # ...but the nat table doesn't declare it, so it inlines there
    assert 'oifname { "wan0", "wwan0" }' in out


def test_includes_and_raw_present():
    out = _gen("router1.yaml")
    assert "ct state established,related accept" in out  # common-input baseline
    assert "tcp flags & (fin|syn) == (fin|syn) counter drop" in out  # scrub raw
    assert "maxseg size set rt mtu" in out  # common-forward raw


# -- strict policy surface (a typo'd section must not become an empty ruleset) - #
def _write_project(tmp_path, policy_text):
    (tmp_path / "definitions").mkdir()
    (tmp_path / "definitions" / "defs.yaml").write_text(
        "networks:\n  lan: [10.0.0.0/24]\n"
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(textwrap.dedent(policy_text))
    return policy


def _gen_tmp(tmp_path, policy_text):
    return generate(
        _write_project(tmp_path, policy_text),
        defs_dir=tmp_path / "definitions",
        include_base=tmp_path,
    )


def test_policy_typo_table_key_errors(tmp_path):
    # `table:` for `tables:` used to yield a valid empty ruleset — with the
    # deploy flush prefix that artifact wipes the firewall.
    with pytest.raises(BuildError, match="unknown policy key"):
        _gen_tmp(
            tmp_path,
            """
            table:
              - {family: inet, name: filter}
        """,
        )


def test_policy_without_tables_errors(tmp_path):
    with pytest.raises(BuildError, match="defines no `tables:`"):
        _gen_tmp(tmp_path, "site: site1\n")


def test_table_typo_chain_key_errors(tmp_path):
    with pytest.raises(BuildError, match="unknown table key"):
        _gen_tmp(
            tmp_path,
            """
            tables:
              - family: inet
                name: filter
                chain:
                  - {name: input, hook: input}
        """,
        )


def test_table_needs_family_and_name(tmp_path):
    with pytest.raises(BuildError, match="needs `family:` and `name:`"):
        _gen_tmp(
            tmp_path,
            """
            tables:
              - name: filter
        """,
        )


def test_include_missing_file_errors(tmp_path):
    with pytest.raises(BuildError, match="include file not found"):
        _gen_tmp(
            tmp_path,
            """
            tables:
              - family: inet
                name: filter
                chains:
                  - name: input
                    hook: input
                    rules:
                      - include: nope.yaml
        """,
        )


def test_include_cycle_errors(tmp_path):
    (tmp_path / "self.yaml").write_text("rules:\n  - include: self.yaml\n")
    with pytest.raises(BuildError, match="include cycle"):
        _gen_tmp(
            tmp_path,
            """
            tables:
              - family: inet
                name: filter
                chains:
                  - name: input
                    hook: input
                    rules:
                      - include: self.yaml
        """,
        )
