"""Phase 2 — IR + named-set emission."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, NamedSet, Table, build_sets

DEFS = Definitions.from_mappings(
    {
        "networks": {
            "webhosts": ["192.0.2.10", "192.0.2.11"],
            "v6hosts": ["2001:db8::10", "2001:db8::11"],
            "dual": ["192.0.2.10", "2001:db8::10"],
        },
        "services": {
            "http": ["80/tcp"],
            "https": ["443/tcp"],
            "web": ["http", "https"],
            "k3s": ["6443/tcp", "2379-2380/tcp"],
        },
        "interfaces": {"wan": ["wan0", "wwan0"]},
    }
)


def test_network_set_v4():
    s = build_sets(["webhosts"], DEFS)[0]
    assert (s.type, s.flags, s.elements) == (
        "ipv4_addr",
        ["interval"],
        ["192.0.2.10", "192.0.2.11"],
    )


def test_network_set_v6():
    assert build_sets(["v6hosts"], DEFS)[0].type == "ipv6_addr"


def test_mixed_family_named_set_errors():
    with pytest.raises(BuildError):
        build_sets(["dual"], DEFS)


def test_service_set_dedupes_ports_and_no_interval():
    s = build_sets(["web"], DEFS)[0]
    assert s.type == "inet_service"
    assert s.elements == ["80", "443"]
    assert s.flags == []


def test_service_set_range_gets_interval_flag():
    s = build_sets(["k3s"], DEFS)[0]
    assert "interval" in s.flags
    assert "2379-2380" in s.elements


def test_interface_set_quotes_devices():
    s = build_sets(["wan"], DEFS)[0]
    assert s.type == "ifname"
    assert s.elements == ['"wan0"', '"wwan0"']


def test_bare_set_live_blocklist_has_no_elements():
    spec = [{"name": "blocklist", "type": "ipv4_addr", "flags": ["interval", "timeout"]}]
    s = build_sets(spec, DEFS)[0]
    assert s.name == "blocklist"
    assert s.elements == []
    assert s.flags == ["interval", "timeout"]


def test_undefined_set_errors():
    with pytest.raises(BuildError):
        build_sets(["nope"], DEFS)


def test_include_entry_is_skipped_for_now():
    assert build_sets([{"include": "x.yaml"}], DEFS) == []


def test_table_render_golden():
    sets = build_sets(
        ["webhosts", "web", "wan", {"name": "blocklist", "type": "ipv4_addr", "flags": ["interval", "timeout"]}],
        DEFS,
    )
    out = Table(family="inet", name="filter", sets=sets).render()
    expected = """\
table inet filter {
    set webhosts {
        type ipv4_addr
        flags interval
        elements = { 192.0.2.10, 192.0.2.11 }
    }

    set web {
        type inet_service
        elements = { 80, 443 }
    }

    set wan {
        type ifname
        elements = { "wan0", "wwan0" }
    }

    set blocklist {
        type ipv4_addr
        flags interval, timeout
    }
}
"""
    assert out == expected


def test_named_set_render_unit():
    s = NamedSet("x", "ipv4_addr", ["10.0.0.0/8"], ["interval"])
    assert s.render() == [
        "    set x {",
        "        type ipv4_addr",
        "        flags interval",
        "        elements = { 10.0.0.0/8 }",
        "    }",
    ]
