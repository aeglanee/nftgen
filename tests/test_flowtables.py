"""Phase 6C — flowtables (table object, devices from interface groups) + flow-offload."""
from nftgen.definitions import Definitions
from nftgen.ir import Table
from nftgen.rules import RuleRenderer, build_flowtables

DEFS = Definitions.from_mappings({"interfaces": {"wan": ["wan0", "wwan0"], "lan_if": ["lan0"]}})


def test_flowtable_resolves_interface_groups():
    ft = build_flowtables(
        [{"name": "ft", "hook": "ingress", "priority": "filter", "devices": ["wan", "lan_if"]}],
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


def test_flowtable_literal_device():
    ft = build_flowtables([{"name": "ft", "devices": ["eth0", "wan"]}], DEFS)[0]
    assert ft.devices == ['"eth0"', '"wan0"', '"wwan0"']
    assert ft.hook == "ingress"  # default


def test_flow_offload_statement():
    r = RuleRenderer(DEFS, {})
    assert r.render({"proto": "tcp", "flow-offload": "ft"}) == ["meta l4proto tcp flow add @ft"]


def test_table_renders_flowtable_block():
    fts = build_flowtables([{"name": "ft", "devices": ["wan"]}], DEFS)
    out = Table(family="inet", name="filter", flowtables=fts).render()
    assert "flowtable ft {" in out
    assert 'devices = { "wan0", "wwan0" }' in out
