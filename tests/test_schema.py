"""Rule value schema (C7 + C8): every value's shape is checked before
rendering; one value or a list works the same for every matching key."""

import pytest

from nftgen import cli, validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, Table, build_sets
from nftgen.rules import RuleRenderer, build_chain

DEFS = Definitions.from_mappings(
    {
        "networks": {"mgmt": ["192.168.9.0/24", "fd00:9::/64"]},
        "services": {"ssh": ["22/tcp"], "dns": ["53/tcp", "53/udp"]},
        "interfaces": {"lan": ["lan0"], "wan": ["wan0"]},
    }
)
NAMED = {
    s.name: s for s in build_sets([{"name": "blocklist", "type": "ipv4_addr"}], DEFS)
}
R = RuleRenderer(DEFS, NAMED)


def bad(rule, match):
    with pytest.raises(BuildError, match=match):
        R.render(rule)


# -- one value or a list ------------------------------------------------------ #
def test_ct_takes_one_state_plain():
    # C7: `ct: established` rendered `ct state e,s,t,a,b,l,i,s,h,e,d`
    assert R.render({"ct": "established", "action": "accept"}) == [
        "ct state established accept"
    ]
    assert R.render({"ct": ["established", "related"], "action": "accept"}) == [
        "ct state established,related accept"
    ]


def test_ct_unknown_state_errors():
    bad({"ct": ["established", "bogus"], "action": "accept"}, "got the text 'bogus'")


def test_port_list_mixes_literals_and_services():
    # C7: a list crashed with TypeError (unhashable)
    assert R.render({"proto": "udp", "dport": ["dns", 5353], "action": "accept"}) == [
        "udp dport { 53, 5353 } accept"
    ]


def test_address_list_splits_per_family_and_dedupes():
    out = R.render({"saddr": ["10.0.0.5", "mgmt", "10.0.0.5"], "action": "accept"})
    assert out == [
        "ip saddr { 10.0.0.5, 192.168.9.0/24 } accept",
        "ip6 saddr fd00:9::/64 accept",
    ]


def test_interface_list_unions_groups():
    assert R.render({"iifname": ["lan", "wan"], "action": "accept"}) == [
        'iifname { "lan0", "wan0" } accept'
    ]


def test_named_set_inside_a_list_errors():
    bad(
        {"saddr": ["blocklist", "10.0.0.1"], "action": "drop"}, "can't go inside a list"
    )


def test_unknown_name_inside_a_list_errors():
    bad(
        {"iifname": ["lan", "lna"], "action": "accept"}, "unknown interface group 'lna'"
    )


def test_empty_list_errors():
    bad({"dport": [], "proto": "tcp", "action": "accept"}, "non-empty list")


# -- action -------------------------------------------------------------------- #
def test_reject_with_is_a_first_class_action():
    assert R.render(
        {"proto": "tcp", "dport": 23, "action": "reject with tcp reset"}
    ) == ["tcp dport 23 reject with tcp reset"]


def test_unknown_verdict_word_errors():
    # used to pass through as-is (a typo surfaced only at nft -c)
    bad({"action": "acept"}, "anything else: a `raw:` rule")


def test_action_mapping_needs_exactly_one_key():
    # C8: two keys crashed with ValueError
    bad({"action": {"jump": "a", "goto": "b"}}, "exactly one of jump, goto")
    bad({"action": {}}, "exactly one of jump, goto")


def test_jump_target_must_be_a_name():
    bad({"action": {"jump": ["a"]}}, "action.jump")


# -- log ------------------------------------------------------------------------ #
def test_log_false_means_no_log():
    # C8: crashed with AttributeError
    assert R.render({"log": False, "action": "drop"}) == ["drop"]


def test_log_empty_mapping_is_a_plain_log():
    # review N1: `log: {}` was dropped (an empty mapping is falsy) — a drop
    # rule meant to log went silent
    assert R.render({"proto": "tcp", "dport": 23, "log": {}, "action": "drop"}) == [
        "tcp dport 23 log drop"
    ]


def test_log_unknown_subkey_errors():
    # C8: `prefx` was silently ignored — a log line without its prefix
    bad({"log": {"prefx": "x "}, "action": "drop"}, r"unknown key\(s\) \['prefx'\]")


def test_log_values_checked():
    bad({"log": {"level": "loud"}, "action": "drop"}, "log.level")
    bad({"log": {"group": 70000}, "action": "drop"}, "log.group")
    # C15: a quote in the prefix broke the rendered quoting
    bad({"log": {"prefix": 'say "hi"'}, "action": "drop"}, "log.prefix")


def test_log_level_and_group_exclude_each_other():
    # nft refuses `log level info group 2` at load ("mutually exclusive")
    bad({"log": {"level": "info", "group": 2}, "action": "drop"}, "can't be combined")
    assert R.render({"log": {"group": 2}, "action": "drop"}) == ["log group 2 drop"]
    assert R.render({"log": {"level": "info"}, "action": "drop"}) == [
        "log level info drop"
    ]


# -- other keys ------------------------------------------------------------------ #
def test_icmp_type_with_ports_errors():
    # C8: dport was silently dropped — the rule matched more than written
    bad(
        {"proto": "icmp", "icmp-type": "echo-request", "dport": 22, "action": "accept"},
        "icmp has no ports",
    )


def test_proto_accepts_names_and_numbers():
    assert R.render({"proto": "vrrp", "action": "accept"}) == [
        "meta l4proto vrrp accept"
    ]
    assert R.render({"proto": 112, "action": "accept"}) == ["meta l4proto 112 accept"]
    bad({"proto": "t cp", "action": "accept"}, "rule key 'proto'")
    bad({"proto": 300, "action": "accept"}, "rule key 'proto'")
    bad({"proto": ["tcp", "udp"], "action": "accept"}, "rule key 'proto'")


def test_flags_unknown_subkey_errors():
    bad(
        {"proto": "tcp", "flags": {"match": ["syn"], "msk": ["syn"]}, "action": "drop"},
        r"unknown key\(s\) \['msk'\]",
    )


def test_set_mss_values():
    assert R.render({"proto": "tcp", "set-mss": "pmtu"}) == [
        "meta l4proto tcp tcp flags syn tcp option maxseg size set rt mtu"
    ]
    assert R.render({"proto": "tcp", "set-mss": "1452"}) == [
        "meta l4proto tcp tcp flags syn tcp option maxseg size set 1452"
    ]
    bad({"proto": "tcp", "set-mss": "huge"}, "rule key 'set-mss'")
    # review N8: "0" passed while 0 failed; both and 65536+ are out of range
    for v in (0, "0", "00", 65536, "99999"):
        bad({"proto": "tcp", "set-mss": v}, r"1-65535")


# -- shapes around rules (C8) ---------------------------------------------------- #
def test_a_rule_must_be_a_mapping():
    bad("accept", "a rule must be a mapping")


@pytest.mark.parametrize(
    ("tables", "match"),
    [
        ("filter", "`tables:` must be a list"),
        (["filter"], "a table must be a mapping"),
        (
            [{"family": "inet", "name": "f", "chains": ["input"]}],
            "a chain must be a mapping",
        ),
        (
            [
                {
                    "family": "inet",
                    "name": "f",
                    "chains": [{"name": "c", "rules": "accept"}],
                }
            ],
            "`rules:` must be a list",
        ),
    ],
)
def test_malformed_table_shapes_error(tables, match):
    with pytest.raises(BuildError, match=match):
        render_tables(tables, DEFS, DictResolver({}))


# -- CLI safety net (C8) --------------------------------------------------------- #
def test_cli_turns_an_unexpected_error_into_one_line(monkeypatch, capsys):
    def boom(*_args, **_kwargs):
        raise KeyError("surprise")

    monkeypatch.setattr(cli, "generate", boom)
    monkeypatch.delenv("NFTGEN_DEBUG", raising=False)
    assert cli.main(["policy.yaml"]) == 70
    err = capsys.readouterr().err
    assert "nftgen: internal error: KeyError" in err
    assert "this is a bug in nftgen" in err
    assert "Traceback" not in err


def test_cli_debug_shows_the_traceback(monkeypatch):
    def boom(*_args, **_kwargs):
        raise KeyError("surprise")

    monkeypatch.setattr(cli, "generate", boom)
    monkeypatch.setenv("NFTGEN_DEBUG", "1")
    with pytest.raises(KeyError):
        cli.main(["policy.yaml"])


# -- the new forms are valid nft ------------------------------------------------- #
@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_lists_and_reject_with_pass_nft_check():
    chain = build_chain(
        {
            "name": "input",
            "hook": "input",
            "rules": [
                {"ct": "established", "action": "accept"},
                {
                    "iifname": ["lan", "wan"],
                    "saddr": ["10.0.0.5", "mgmt"],
                    "proto": "udp",
                    "dport": ["dns", 5353],
                    "action": "accept",
                },
                {"proto": "tcp", "dport": 23, "action": "reject with tcp reset"},
                {"proto": "vrrp", "action": "accept"},
                {"log": False, "action": "drop"},
            ],
        },
        R,
    )
    text = Table(
        family="inet", name="filter", sets=list(NAMED.values()), chains=[chain]
    ).render()
    result = validate.check(text)
    assert result.ok, result.stderr


# -- C15: unvalidated passthroughs ----------------------------------------------- #
def test_flow_offload_must_name_a_declared_flowtable():
    # nft said only "Could not process rule: No such file or directory"
    tables = [
        {
            "family": "inet",
            "name": "f",
            "flowtables": [{"name": "ft", "devices": ["lan"]}],
            "chains": [
                {
                    "name": "forward",
                    "hook": "forward",
                    "rules": [{"ct": "established", "flow-offload": "fft"}],
                }
            ],
        }
    ]
    with pytest.raises(
        BuildError, match=r"flowtable 'fft' is not declared .*declared: ft"
    ):
        render_tables(tables, DEFS, DictResolver({}))
    tables[0]["chains"][0]["rules"][0]["flow-offload"] = "ft"
    assert "flow add @ft" in render_tables(tables, DEFS, DictResolver({}))


def test_mark_values_are_numbers():
    assert R.render({"mark": "0x1", "action": "accept"}) == ["meta mark 0x1 accept"]
    assert R.render({"mark": 7, "action": "accept"}) == ["meta mark 7 accept"]
    assert R.render({"mark": "0x10-0x1f", "action": "accept"}) == [
        "meta mark 0x10-0x1f accept"
    ]
    bad({"mark": "gold", "action": "accept"}, "rule key 'mark'")
    bad({"set-mark": "0x1-0x2"}, "rule key 'set-mark'")  # a range can't be set
    bad({"set-mark": "mark"}, "rule key 'set-mark'")  # only ct-mark is a source
    bad({"ct-mark": "gold", "action": "accept"}, "rule key 'ct-mark'")
    bad({"set-ct-mark": "0x1-0x2"}, "rule key 'set-ct-mark'")
    bad({"set-ct-mark": "ct-mark"}, "rule key 'set-ct-mark'")  # only mark is a source


def test_mark_copy_and_set_in_one_rule_is_rejected():
    # set-mark always renders first, so a copy beside a set would read the old
    # value: `meta mark set ct mark ct mark set 0x1` copies 0, not 0x1
    bad({"set-ct-mark": "0x1", "set-mark": "ct-mark"}, "split them into two rules")
    bad({"set-ct-mark": "mark", "set-mark": "ct-mark"}, "split them into two rules")
    bad({"set-ct-mark": "mark", "set-mark": "0x2"}, "split them into two rules")
    assert R.render({"set-ct-mark": "0x1", "set-mark": "0x2"}) == [
        "meta mark set 0x2 ct mark set 0x1"
    ]


def test_concat_mark_values_are_numbers():
    with pytest.raises(BuildError, match=r"field mark='gold' is not a mark"):
        build_sets([{"name": "m", "concat": ["mark"], "tuples": [["gold"]]}], DEFS)


# -- review N6: OS errors are not "internal errors" ------------------------------ #
def test_cli_os_error_is_a_clean_error(tmp_path, capsys):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    policy = tmp_path / "p.yaml"
    policy.write_text("tables:\n  - family: inet\n    name: f\n")
    (tmp_path / "definitions").mkdir()
    # --out pointing at a directory: IsADirectoryError
    rc = cli.main(
        [str(policy), "--defs", str(tmp_path / "definitions"), "--out", str(out_dir)]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert err.startswith("nftgen: error: ")
    assert "internal error" not in err


def test_cli_broken_pipe_exits_quietly(monkeypatch, capsys):
    def closed_pipe(*_args, **_kwargs):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(cli, "generate", closed_pipe)
    assert cli.main(["policy.yaml"]) == 141
    assert capsys.readouterr().err == ""


# -- review R6: only ASCII digits are numbers ------------------------------------- #
@pytest.mark.parametrize("text", ["\u00b2", "\u0661\u0667", "\uff11\uff14\uff15\uff12"])
def test_non_ascii_digits_are_not_numbers(text):
    # str.isdigit() says yes to "²", Arabic-Indic and full-width digits:
    # int("²") crashed, the others were rendered into the .nft as written
    bad({"proto": "tcp", "set-mss": text}, "rule key 'set-mss'")
    bad({"proto": text, "action": "accept"}, "rule key 'proto'")
