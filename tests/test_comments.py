"""`comment:` — nft's native comments on rules, chains, sets, and tables."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "networks": {"mgmt": ["192.168.9.0/24", "fd00:9::/64"], "app": ["10.0.1.10"]},
        "services": {"ssh": ["22/tcp"]},
        "interfaces": {"lan": ["lan0"]},
    }
)
R = RuleRenderer(DEFS, {})

TABLES = [
    {
        "family": "inet",
        "name": "filter",
        "comment": "main filter",
        "sets": [
            {
                "name": "blocklist",
                "type": "ipv4_addr",
                "flags": ["timeout"],
                "comment": "filled at runtime",
            },
            {
                "name": "flows",
                "concat": ["saddr", "dport"],
                "proto": "tcp",
                "tuples": [["app", "ssh"]],
                "comment": "paired flows",
            },
        ],
        "chains": [
            {
                "name": "input",
                "hook": "input",
                "comment": "to the router",
                "rules": [
                    {
                        "saddr": "mgmt",
                        "proto": "tcp",
                        "dport": "ssh",
                        "action": "accept",
                        "comment": "admins → router ssh",
                    },
                    {"set": "flows", "action": "accept", "comment": "app ssh"},
                    {
                        "vmap": {"key": "iifname", "map": {"lan": "accept"}},
                        "comment": "zone dispatch",
                    },
                ],
            }
        ],
    }
]


def test_rule_comment_goes_last_on_every_expanded_line():
    # one YAML rule, v4 + v6 lines — each carries the comment
    assert R.render(
        {
            "saddr": "mgmt",
            "proto": "tcp",
            "dport": "ssh",
            "action": "accept",
            "comment": "admins → router ssh",
        }
    ) == [
        'ip saddr 192.168.9.0/24 tcp dport 22 accept comment "admins → router ssh"',
        'ip6 saddr fd00:9::/64 tcp dport 22 accept comment "admins → router ssh"',
    ]


def test_vmap_and_concat_rules_take_a_comment():
    named = {s.name: s for s in build_sets(TABLES[0]["sets"], DEFS)}
    r = RuleRenderer(DEFS, named)
    assert r.render(
        {"vmap": {"key": "iifname", "map": {"lan": "accept"}}, "comment": "zones"}
    ) == ['iifname vmap { "lan0" : accept } comment "zones"']
    assert r.render({"set": "flows", "action": "accept", "comment": "x"}) == [
        'ip saddr . tcp dport @flows accept comment "x"'
    ]


def test_table_chain_and_set_comments_render():
    out = render_tables(TABLES, DEFS, DictResolver({}))
    assert 'table inet filter {\n    comment "main filter"\n' in out
    assert (
        "    set blocklist {\n        type ipv4_addr\n        flags timeout\n"
        '        comment "filled at runtime"\n    }'
    ) in out
    assert 'comment "paired flows"' in out
    assert (
        "        type filter hook input priority 0; policy drop;\n"
        '        comment "to the router"\n'
    ) in out


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ('say "hi"', "can't contain a double quote"),
        ("two\nlines", "can't contain a double quote or a line break"),
        ("", "must be a non-empty string"),
        (42, "must be a non-empty string"),
        # 126 ASCII + one 3-byte arrow = 129 bytes: nft counts bytes
        ("a" * 126 + "→", "is 129 bytes; nft allows at most 128"),
    ],
)
def test_comment_values_checked_at_build(value, match):
    with pytest.raises(BuildError, match=match):
        R.render({"action": "accept", "comment": value})


def test_comment_at_the_byte_limit_is_fine():
    assert R.render({"action": "accept", "comment": "a" * 125 + "→"}) == [
        f'accept comment "{"a" * 125}→"'
    ]


def test_raw_rule_rejects_comment_key():
    with pytest.raises(BuildError, match="write `comment"):
        R.render({"raw": "accept", "comment": "x"})


def test_comment_alone_is_not_a_rule():
    with pytest.raises(BuildError, match="neither an action nor a statement"):
        R.render({"comment": "orphan"})


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_commented_ruleset_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_comments_survive_into_the_kernel(tmp_path):
    # the point of native comments: `nft list ruleset` on the box shows them
    # (a `#` file comment is gone once loaded)
    path = tmp_path / "r.nft"
    path.write_text(render_tables(TABLES, DEFS, DictResolver({})))
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    for text in (
        "main filter",
        "to the router",
        "admins → router ssh",
        "zone dispatch",
    ):
        assert f'comment "{text}"' in proc.stdout
