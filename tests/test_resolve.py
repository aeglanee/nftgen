"""Include resolution via the resolver abstraction — the DictResolver (vars mode)
path in particular, since the PathResolver path is covered by test_generate."""

import pytest

from nftgen.generate import DictResolver, _resolve_list
from nftgen.ir import BuildError


def test_dict_resolver_expands_by_name():
    frags = {"icmp": [{"proto": "icmp", "action": "accept"}]}
    out = _resolve_list([{"include": "icmp"}], "rules", DictResolver(frags))
    assert out == [{"proto": "icmp", "action": "accept"}]


def test_dict_resolver_nested_fragment():
    frags = {"outer": [{"include": "inner"}], "inner": [{"x": 1}]}
    out = _resolve_list([{"include": "outer"}], "rules", DictResolver(frags))
    assert out == [{"x": 1}]


def test_dict_resolver_key_is_ignored_shared_namespace():
    # a fragment is one list, used from either sets: or rules: context.
    frags = {"f": [{"x": 1}]}
    assert _resolve_list([{"include": "f"}], "sets", DictResolver(frags)) == [{"x": 1}]
    assert _resolve_list([{"include": "f"}], "rules", DictResolver(frags)) == [{"x": 1}]


def test_dict_resolver_unknown_fragment_lists_known():
    with pytest.raises(
        BuildError, match=r"unknown fragment 'nope' \(known: \['icmp'\]\)"
    ):
        _resolve_list([{"include": "nope"}], "rules", DictResolver({"icmp": []}))


def test_dict_resolver_cycle_by_name():
    frags = {"a": [{"include": "b"}], "b": [{"include": "a"}]}
    with pytest.raises(BuildError, match="include cycle: a -> b -> a"):
        _resolve_list([{"include": "a"}], "rules", DictResolver(frags))


def test_include_must_be_the_only_key():
    with pytest.raises(BuildError, match="`include:` must be the entry's only key"):
        _resolve_list([{"include": "x", "extra": 1}], "rules", DictResolver({"x": []}))
