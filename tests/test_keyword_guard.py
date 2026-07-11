"""Reserved-keyword name guard: an nft keyword as a set/chain/counter/flowtable
name is a BuildError, not a cryptic downstream nft parse error."""

import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, build_sets, check_nft_name
from nftgen.rules import RuleRenderer, build_chain, build_flowtables

DEFS = Definitions.from_mappings(
    {
        "networks": {"mark": ["10.0.0.0/8"], "trusted": ["192.168.0.0/16"]},
        "interfaces": {"ct": ["eth0"], "wan": ["wan0"]},
    }
)


@pytest.mark.parametrize(
    "kw", ["fwd", "meta", "ct", "counter", "map", "mark", "log", "comment"]
)
def test_check_rejects_keywords(kw):
    with pytest.raises(BuildError, match="reserved nftables keyword"):
        check_nft_name(kw, "set")


@pytest.mark.parametrize(
    "ok", ["input", "forward", "nat", "last", "state", "wan_scrub", "fwd_users"]
)
def test_check_allows_contextual_and_normal_names(ok):
    check_nft_name(ok, "set")  # no raise


def test_named_set_keyword_rejected():
    # a definition group named after a keyword, materialised as a named set
    with pytest.raises(BuildError, match="set name 'mark' is a reserved"):
        build_sets(["mark"], DEFS)
    # …but a fine name is accepted
    assert build_sets(["trusted"], DEFS)[0].name == "trusted"


def test_bare_and_concat_set_keyword_rejected():
    with pytest.raises(BuildError, match="reserved nftables keyword"):
        build_sets([{"name": "counter", "type": "ipv4_addr"}], DEFS)
    with pytest.raises(BuildError, match="reserved nftables keyword"):
        build_sets([{"name": "flow", "concat": ["saddr", "daddr"], "tuples": []}], DEFS)


def test_chain_name_keyword_rejected():
    r = RuleRenderer(DEFS, {})
    with pytest.raises(BuildError, match="chain name 'jump' is a reserved"):
        build_chain({"name": "jump", "rules": []}, r)
    # a normal chain name is fine
    assert build_chain({"name": "wan_scrub", "rules": []}, r).name == "wan_scrub"


def test_flowtable_name_keyword_rejected():
    with pytest.raises(BuildError, match="flowtable name 'flow' is a reserved"):
        build_flowtables([{"name": "flow", "devices": ["wan"]}], DEFS)
