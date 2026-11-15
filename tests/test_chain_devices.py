"""Base chains bound to devices: `devices:` on an ingress or egress chain."""

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer, build_chain

DEFS = Definitions.from_mappings(
    {"interfaces": {"wan": ["wan0", "wwan0"], "lan_if": ["lan0"]}}
)
R = RuleRenderer(DEFS, {})

TABLES = [
    {
        "family": "netdev",
        "name": "scrub",
        "chains": [
            {
                "name": "wan_in",
                "hook": "ingress",
                "devices": "wan",
                "policy": "accept",
                "rules": [
                    {"saddr": "10.0.0.0/8", "action": "drop"},
                    {
                        "proto": "tcp",
                        "flags": {"match": [], "mask": ["syn"]},
                        "action": "drop",
                    },
                ],
            }
        ],
    },
    {
        "family": "inet",
        "name": "filter",
        "chains": [
            {
                "name": "early",
                "hook": "ingress",
                "devices": ["wan", "lan_if"],
                "priority": "filter",
                "policy": "accept",
                "rules": [{"saddr": "192.0.2.0/24", "action": "drop"}],
            },
            {
                "name": "input",
                "hook": "input",
                "rules": [{"ct": ["established", "related"], "action": "accept"}],
            },
        ],
    },
]


def _base_line(spec: dict) -> str:
    return build_chain(spec, R).render()[1].strip()


def test_ingress_chain_lists_the_groups_devices():
    assert _base_line(
        {
            "name": "early",
            "hook": "ingress",
            "devices": ["wan", "lan_if"],
            "policy": "accept",
        }
    ) == (
        'type filter hook ingress devices = { "wan0", "wwan0", "lan0" } '
        "priority 0; policy accept;"
    )


def test_one_group_plain():
    assert _base_line({"name": "early", "hook": "ingress", "devices": "wan"}) == (
        'type filter hook ingress devices = { "wan0", "wwan0" } priority 0; policy drop;'
    )


def test_egress_chain_takes_devices_too():
    assert _base_line(
        {"name": "out", "hook": "egress", "devices": "lan_if", "priority": 10}
    ) == ('type filter hook egress devices = { "lan0" } priority 10; policy drop;')


def test_device_shared_by_two_groups_listed_once():
    defs = Definitions.from_mappings(
        {"interfaces": {"wan": ["wan0", "wwan0"], "uplinks": ["wan0"]}}
    )
    chain = build_chain(
        {"name": "early", "hook": "ingress", "devices": ["wan", "uplinks"]},
        RuleRenderer(defs, {}),
    )
    assert chain.devices == ['"wan0"', '"wwan0"']


def test_unknown_group_errors():
    with pytest.raises(BuildError, match="not a known interface group"):
        build_chain({"name": "early", "hook": "ingress", "devices": ["eth0"]}, R)


@pytest.mark.parametrize("bad", [[{"a": "b"}], {"wan": None}, 5])
def test_devices_must_be_group_names(bad):
    with pytest.raises(BuildError, match="takes an interface group"):
        build_chain({"name": "early", "hook": "ingress", "devices": bad}, R)


def test_an_empty_list_errors():
    with pytest.raises(BuildError, match="resolves to no devices"):
        build_chain({"name": "early", "hook": "ingress", "devices": []}, R)


@pytest.mark.parametrize("hook", ["input", "forward", "prerouting"])
def test_devices_need_an_ingress_or_egress_hook(hook):
    with pytest.raises(BuildError, match="ingress or egress"):
        build_chain({"name": "c", "hook": hook, "devices": "wan"}, R)


def test_devices_without_a_hook_errors():
    with pytest.raises(BuildError, match="but no `hook:`"):
        build_chain({"name": "c", "devices": "wan"}, R)


@pytest.mark.parametrize("hook", ["ingress", "egress"])
def test_a_device_hook_needs_devices(hook):
    with pytest.raises(BuildError, match="needs `devices:`"):
        build_chain({"name": "c", "hook": hook}, R)


def test_tables_render():
    text = render_tables(TABLES, DEFS, DictResolver({}))
    assert (
        "table netdev scrub {\n"
        "    chain wan_in {\n"
        '        type filter hook ingress devices = { "wan0", "wwan0" } '
        "priority 0; policy accept;\n"
        "        ip saddr 10.0.0.0/8 drop\n"
    ) in text
    assert (
        '        type filter hook ingress devices = { "wan0", "wwan0", "lan0" } '
        "priority 0; policy accept;\n"
    ) in text
    assert "        type filter hook input priority 0; policy drop;\n" in text


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    # a kernel before 6.16 refuses a chain on a device that does not exist,
    # at `nft -c` too: `lo` is the one device every check namespace has
    defs = Definitions.from_mappings({"interfaces": {"wan": ["lo"], "lan_if": ["lo"]}})
    result = validate.check(render_tables(TABLES, defs, DictResolver({})))
    assert result.ok, result.stderr
