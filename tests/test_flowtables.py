"""Phase 6C — flowtables (table object, devices from interface groups) + flow-offload."""

import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Table
from nftgen.rules import RuleRenderer, build_flowtables

DEFS = Definitions.from_mappings(
    {"interfaces": {"wan": ["wan0", "wwan0"], "lan_if": ["lan0"]}}
)


def test_flowtable_resolves_interface_groups():
    ft = build_flowtables(
        [
            {
                "name": "ft",
                "hook": "ingress",
                "priority": "filter",
                "devices": ["wan", "lan_if"],
            }
        ],
        DEFS,
    )[0]
    assert ft.devices == ['"wan0"', '"wwan0"', '"lan0"']
    assert ft.priority == 0
    assert ft.render() == [
        "    flowtable ft {",
        "        hook ingress priority 0",
        '        devices = { "wan0", "wwan0", "lan0" }',
        "    }",
    ]


def test_flowtable_hook_defaults_to_ingress():
    ft = build_flowtables([{"name": "ft", "devices": ["wan"]}], DEFS)[0]
    assert ft.hook == "ingress"


def test_flowtable_unknown_device_errors():
    with pytest.raises(BuildError, match="not a known interface group"):
        build_flowtables([{"name": "ft", "devices": ["eth0", "wan"]}], DEFS)


def test_flowtable_needs_devices():
    with pytest.raises(BuildError, match="resolves to no devices"):
        build_flowtables([{"name": "ft"}], DEFS)


def test_flowtable_unknown_key_errors():
    with pytest.raises(BuildError, match="unknown flowtable key"):
        build_flowtables([{"name": "ft", "devices": ["wan"], "prio": 0}], DEFS)


def test_flow_offload_statement():
    r = RuleRenderer(DEFS, {})
    assert r.render({"proto": "tcp", "flow-offload": "ft"}) == [
        "meta l4proto tcp flow add @ft"
    ]


def test_table_renders_flowtable_block():
    fts = build_flowtables([{"name": "ft", "devices": ["wan"]}], DEFS)
    out = Table(family="inet", name="filter", flowtables=fts).render()
    assert "flowtable ft {" in out
    assert 'devices = { "wan0", "wwan0" }' in out
