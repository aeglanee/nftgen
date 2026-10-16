"""Table-level key shapes: keys that take one value or a list read a bare
string as one value (never letter by letter); list-of-mapping keys say so
instead of iterating a mapping's keys."""

import pytest

from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets

DEFS = Definitions.from_mappings({"networks": {"a": ["10.0.0.1"], "b": ["10.0.0.2"]}})


def render(**table):
    return render_tables(
        [{"family": "inet", "name": "f", **table}], DEFS, DictResolver({})
    )


def test_counters_take_one_name_plain():
    # `counters: bad` rendered three counters: b, a, d
    out = render(counters="bad")
    assert "counter bad {" in out
    assert "counter b {" not in out


def test_table_raw_takes_one_line_plain():
    # a bare string rendered one character per line
    out = render(raw="quota q { over 1 mbytes }")
    assert "    quota q { over 1 mbytes }" in out


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("counters", {"x": 1}, "`counters:` takes a value or a list"),
        ("raw", 5, "`raw:` takes a value or a list"),
        ("raw", [{"x": 1}], "`raw:` takes nft text"),
    ],
)
def test_table_list_keys_reject_other_shapes(key, value, match):
    with pytest.raises(BuildError, match=match):
        render(**{key: value})


def test_concat_fields_must_be_a_list():
    # a bare string was read letter by letter ("unknown field 's'")
    with pytest.raises(BuildError, match="`concat:` takes a list of fields"):
        build_sets([{"name": "c", "concat": "saddr", "tuples": []}], DEFS)


@pytest.mark.parametrize("key", ["sets", "chains", "flowtables"])
def test_list_of_mapping_keys_must_be_lists(key):
    # a single mapping was iterated by its keys: "unknown flowtable key(s)
    # ['a', 'e', 'm', 'n']"
    with pytest.raises(BuildError, match=f"`{key}:` must be a list"):
        render(**{key: {"name": "x"}})


def test_concat_tuples_must_be_a_list():
    with pytest.raises(BuildError, match="`tuples:` takes a list of rows"):
        build_sets([{"name": "c", "concat": ["saddr", "daddr"], "tuples": "ab"}], DEFS)


def test_blank_keys_are_empty():
    # YAML `chains:` with nothing after it is None; `chains: None` crashed
    out = render(sets=None, chains=None, flowtables=None, counters=None, raw=None)
    assert "table inet f {" in out
