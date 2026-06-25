"""Phase 6B — named counters (table object + `counter: <name>`)."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Table, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings({"services": {"http": ["80/tcp"]}})
NAMED = {s.name: s for s in build_sets(["http"], DEFS)}


def test_anonymous_counter_still_works():
    r = RuleRenderer(DEFS, NAMED)
    assert r.render({"proto": "tcp", "dport": "http", "counter": True, "action": "accept"}) == \
        ["tcp dport @http counter accept"]


def test_named_counter_renders_when_declared():
    r = RuleRenderer(DEFS, NAMED, counters={"http_hits"})
    assert r.render({"proto": "tcp", "dport": "http", "counter": "http_hits", "action": "accept"}) == \
        ["tcp dport @http counter name http_hits accept"]


def test_named_counter_undeclared_errors():
    r = RuleRenderer(DEFS, NAMED)  # nothing declared
    with pytest.raises(BuildError):
        r.render({"proto": "tcp", "counter": "nope", "action": "accept"})


def test_table_renders_counter_objects():
    t = Table(family="inet", name="filter", counters=["http_hits", "ssh_drops"])
    out = t.render()
    assert "    counter http_hits {\n    }" in out
    assert "    counter ssh_drops {\n    }" in out
