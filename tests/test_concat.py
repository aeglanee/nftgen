"""Concatenation sets: paired-flow tuples (`concat:` + `proto:` + `tuples:`)."""
import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Table, build_sets
from nftgen.rules import RuleRenderer, build_chain

DEFS = Definitions.from_mappings(
    {
        "networks": {
            "app": ["10.0.1.10"], "db": ["192.0.2.20"], "iot": ["10.20.0.0/24"],
            "web": ["192.0.2.10"], "grp": ["10.0.0.1", "10.0.0.2"], "v6": ["2001:db8::1"],
        },
        "services": {"postgres": ["5432/tcp"], "https": ["443/tcp"], "dns": ["53/tcp", "53/udp"]},
        "interfaces": {"wan": ["wan0"]},
    }
)


def _r(sets_spec):
    sets = build_sets(sets_spec, DEFS)
    return RuleRenderer(DEFS, {s.name: s for s in sets}), sets


# -- set construction ------------------------------------------------------- #
def test_type_and_elements_resolve_names():
    sets = build_sets(
        [{"name": "f", "concat": ["saddr", "daddr", "dport"], "proto": "tcp",
          "tuples": [["app", "db", "postgres"], ["10.0.1.11", "192.0.2.21", "8443"]]}],
        DEFS,
    )
    s = sets[0]
    assert s.type == "ipv4_addr . ipv4_addr . inet_service"
    assert s.elements == ["10.0.1.10 . 192.0.2.20 . 5432", "10.0.1.11 . 192.0.2.21 . 8443"]
    assert s.flags == []  # all exact -> hash


def test_cidr_field_triggers_interval():
    s = build_sets(
        [{"name": "f", "concat": ["saddr", "daddr", "dport"], "proto": "tcp",
          "tuples": [["iot", "web", "https"]]}], DEFS,
    )[0]
    assert s.flags == ["interval"]


def test_v6_family():
    s = build_sets([{"name": "f", "concat": ["saddr", "daddr"], "tuples": [["v6", "v6"]]}], DEFS)[0]
    assert s.type == "ipv6_addr . ipv6_addr"


# -- match rendering -------------------------------------------------------- #
def test_match_render():
    r, _ = _r([{"name": "f", "concat": ["saddr", "daddr", "dport"], "proto": "tcp",
                "tuples": [["app", "db", "postgres"]]}])
    assert r.render({"set": "f", "action": "accept"}) == \
        ["ip saddr . ip daddr . tcp dport @f accept"]


def test_match_v6_and_iface_and_counter():
    r, _ = _r([{"name": "f", "concat": ["iif", "saddr", "dport"], "proto": "tcp",
                "tuples": [["wan", "app", "https"]]}])
    assert r.render({"set": "f", "counter": True, "action": "accept"}) == \
        ["iifname . ip saddr . tcp dport @f counter accept"]


def test_mark_field():
    sets = build_sets([{"name": "f", "concat": ["mark", "saddr"], "tuples": [["0x1", "app"]]}], DEFS)
    assert sets[0].type == "mark . ipv4_addr"
    assert sets[0].elements == ["0x1 . 10.0.1.10"]
    r = RuleRenderer(DEFS, {s.name: s for s in sets})
    assert r.render({"set": "f", "action": "accept"}) == ["meta mark . ip saddr @f accept"]


# -- guardrails ------------------------------------------------------------- #
def test_multivalue_field_errors():
    with pytest.raises(BuildError):
        build_sets([{"name": "f", "concat": ["saddr", "daddr"], "tuples": [["grp", "db"]]}], DEFS)


def test_arity_errors():
    with pytest.raises(BuildError):
        build_sets([{"name": "f", "concat": ["saddr", "daddr", "dport"], "proto": "tcp",
                     "tuples": [["app", "db"]]}], DEFS)


def test_port_field_needs_proto():
    with pytest.raises(BuildError):
        build_sets([{"name": "f", "concat": ["saddr", "dport"], "tuples": [["app", "postgres"]]}], DEFS)


def test_service_proto_mismatch_errors():
    with pytest.raises(BuildError):  # postgres is tcp; asking udp -> 0 ports
        build_sets([{"name": "f", "concat": ["saddr", "dport"], "proto": "udp",
                     "tuples": [["app", "postgres"]]}], DEFS)


def test_unknown_field_errors():
    with pytest.raises(BuildError):
        build_sets([{"name": "f", "concat": ["saddr", "bogus"], "tuples": [["app", "x"]]}], DEFS)


def test_mixed_family_errors():
    with pytest.raises(BuildError):
        build_sets([{"name": "f", "concat": ["saddr", "daddr"], "tuples": [["app", "v6"]]}], DEFS)


def test_rule_cannot_mix_set_with_match_keys():
    r, _ = _r([{"name": "f", "concat": ["saddr", "dport"], "proto": "tcp", "tuples": [["app", "postgres"]]}])
    with pytest.raises(BuildError):
        r.render({"set": "f", "saddr": "app", "action": "accept"})


def test_unknown_set_reference_errors():
    with pytest.raises(BuildError):
        RuleRenderer(DEFS, {}).render({"set": "nope", "action": "accept"})


# -- real nft -c ------------------------------------------------------------ #
@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_generated_concat_passes_nft_check():
    sets = build_sets(
        [{"name": "f", "concat": ["saddr", "daddr", "dport"], "proto": "tcp",
          "tuples": [["app", "db", "postgres"], ["iot", "web", "https"]]}], DEFS,
    )
    r = RuleRenderer(DEFS, {s.name: s for s in sets})
    chain = build_chain(
        {"name": "forward", "hook": "forward", "priority": "filter", "policy": "drop",
         "rules": [{"set": "f", "action": "accept"}]}, r,
    )
    text = "#!/usr/sbin/nft -f\n\n" + Table(family="inet", name="filter", sets=sets, chains=[chain]).render()
    result = validate.check(text)
    assert result.ok, result.stderr
