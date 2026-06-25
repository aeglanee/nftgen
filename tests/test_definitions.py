"""Phase 1 — definitions resolver: composition, merge, per-site overlay, errors."""
import pathlib

import pytest

from nftgen.definitions import DefinitionError, Definitions

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "example"


# -- networks --------------------------------------------------------------- #
def test_network_literal_and_ref_composition():
    d = Definitions.from_mappings(
        {
            "networks": {
                "lan": ["192.168.1.0/24"],
                "mgmt": ["192.168.9.0/24"],
                "trusted": ["lan", "mgmt", "10.0.0.0/8"],
            }
        }
    )
    assert d.network("lan") == ["192.168.1.0/24"]
    assert d.network("trusted") == ["192.168.1.0/24", "192.168.9.0/24", "10.0.0.0/8"]


def test_network_dedupe_overlapping_refs():
    d = Definitions.from_mappings(
        {
            "networks": {
                "a": ["10.0.0.0/8"],
                "b": ["a", "10.0.0.0/8"],  # overlap
            }
        }
    )
    assert d.network("b") == ["10.0.0.0/8"]


def test_network_cycle_is_guarded():
    d = Definitions.from_mappings({"networks": {"loop": ["loop", "10.1.0.0/16"]}})
    assert d.network("loop") == ["10.1.0.0/16"]


def test_network_bad_literal_errors():
    d = Definitions.from_mappings({"networks": {"x": ["not-an-ip"]}})
    with pytest.raises(DefinitionError):
        d.network("x")


def test_network_v6_and_mixed():
    d = Definitions.from_mappings(
        {"networks": {"dual": ["192.0.2.0/24", "2001:db8::/32"]}}
    )
    assert d.network("dual") == ["192.0.2.0/24", "2001:db8::/32"]


# -- services --------------------------------------------------------------- #
def test_service_bundle():
    d = Definitions.from_mappings(
        {
            "services": {
                "http": ["80/tcp"],
                "https": ["443/tcp"],
                "web": ["http", "https"],
                "dns": ["53/tcp", "53/udp"],
            }
        }
    )
    assert d.service("web") == [("tcp", "80"), ("tcp", "443")]
    assert d.service("dns") == [("tcp", "53"), ("udp", "53")]
    assert d.service_ports("dns", "udp") == ["53"]
    assert d.service_ports("web", "tcp") == ["80", "443"]


def test_service_range():
    d = Definitions.from_mappings({"services": {"k3s": ["2379-2380/tcp"]}})
    assert d.service("k3s") == [("tcp", "2379-2380")]


def test_service_missing_proto_errors():
    d = Definitions.from_mappings({"services": {"bad": ["80"]}})
    with pytest.raises(DefinitionError):
        d.service("bad")


# -- interfaces ------------------------------------------------------------- #
def test_interface_group_and_composition():
    d = Definitions.from_mappings(
        {
            "interfaces": {
                "wan": ["wan0", "wwan0"],
                "uplinks": ["wan", "lte0"],
            }
        }
    )
    assert d.interface("wan") == ["wan0", "wwan0"]
    assert d.interface("uplinks") == ["wan0", "wwan0", "lte0"]


# -- errors / merge --------------------------------------------------------- #
def test_undefined_name_errors():
    d = Definitions.from_mappings({"networks": {}})
    with pytest.raises(DefinitionError):
        d.network("nope")


def test_duplicate_definition_errors():
    with pytest.raises(DefinitionError):
        Definitions.from_mappings(
            {"networks": {"lan": ["10.0.0.0/8"]}},
            {"networks": {"lan": ["192.168.0.0/16"]}},  # redefines lan
        )


def test_value_must_be_list():
    with pytest.raises(DefinitionError):
        Definitions.from_mappings({"networks": {"lan": "10.0.0.0/8"}})


# -- per-site overlay (the local-definitions mechanism) --------------------- #
def test_site_overlay_resolves_local_alias():
    common = {"networks": {"users_site1": ["192.168.10.0/24"], "users_site2": ["192.168.20.0/24"]}}
    site1 = {"networks": {"local_users": ["users_site1"]}}
    site2 = {"networks": {"local_users": ["users_site2"]}}
    assert Definitions.from_mappings(common, site1).network("local_users") == ["192.168.10.0/24"]
    assert Definitions.from_mappings(common, site2).network("local_users") == ["192.168.20.0/24"]


def test_site_overlay_collision_with_common_errors():
    common = {"networks": {"lan": ["192.168.1.0/24"]}}
    site = {"networks": {"lan": ["192.168.2.0/24"]}}  # must stay disjoint
    with pytest.raises(DefinitionError):
        Definitions.from_mappings(common, site)


# -- loading from the example directory ------------------------------------- #
def test_load_example_dir_and_site_overlay():
    defs = Definitions.load(EXAMPLE / "def", site_files=[EXAMPLE / "sites" / "site1.yaml"])
    assert defs.network("webhosts") == ["192.0.2.10", "192.0.2.11"]
    assert defs.service("web") == [("tcp", "80"), ("tcp", "443")]
    assert defs.interface("wan") == ["wan0", "wwan0"]
    assert defs.network("local_users") == ["192.168.10.0/24"]  # site1 overlay
