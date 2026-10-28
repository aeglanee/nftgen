"""The value schema for rule keys: what each key accepts, checked once before
rendering.

Rule *keys* were always strict; their *values* were read in many places, each
assuming a shape — a wrong one crashed or rendered garbage that nft -c then
rejected far from the YAML (`ct: established` → `ct state e,s,t,…`). Every
value is now checked here first, with an error naming the key, what it got
and what it takes.

One value or a list, the same everywhere: a key that matches something
(addresses, ports, interfaces, ct states, icmp types) takes one value plain or
several as a list.
"""

from __future__ import annotations

import re

from nftgen.ir import MARK_SET_VALUE, MARK_VALUE, BuildError, check_comment

CT_STATES = ("new", "established", "related", "invalid", "untracked")
LOG_LEVELS = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warn",
    "notice",
    "info",
    "debug",
    "audit",
)
VERDICTS = ("accept", "drop", "reject", "return", "continue", "masquerade")
ACTION_MAPPING_KEYS = ("jump", "goto", "dnat", "snat")
MSS_ALIASES = ("pmtu", "rt-mtu", "rt_mtu")
_PROTO_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")  # tcp, icmpv6, vrrp, …
_REJECT_WITH = re.compile(r"^reject with \S.*$")


def _got(value) -> str:
    """How a value reads in an error: its kind and the value itself."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return f"the text {value!r}"
    if isinstance(value, int):
        return f"the number {value}"
    if isinstance(value, list):
        return f"a list {value!r}"
    if isinstance(value, dict):
        return f"a mapping {value!r}"
    return f"{type(value).__name__} {value!r}"


def _fail(key: str, expected: str, value):
    raise BuildError(f"rule key {key!r}: expected {expected}, got {_got(value)}")


def _is_scalar(value) -> bool:
    return isinstance(value, str | int) and not isinstance(value, bool)


# -- checkers: (key, value) -> normalized value, or raise --------------------- #
def _one_or_list(what: str, element):
    """One value plain, or a non-empty list of them (normalized: kept as given)."""

    def check(key, value):
        if isinstance(value, list):
            if not value:
                _fail(key, f"{what}, or a non-empty list of them", value)
            for item in value:
                element(key, item, what)
            return value
        element(key, value, what)
        return value

    return check


def _scalar(key, value, what):
    if not _is_scalar(value):
        _fail(key, what, value)


def _name(key, value, what="a name"):
    if not isinstance(value, str) or not value:
        _fail(key, what, value)
    return value


def _ct_state(key, value, what):
    if value not in CT_STATES:
        _fail(key, what, value)


def _ct(key, value):
    # one state plain → a one-item list: the renderer joins a list
    check = _one_or_list(f"a ct state ({', '.join(CT_STATES)})", _ct_state)
    value = check(key, value)
    return value if isinstance(value, list) else [value]


def _proto(key, value):
    if isinstance(value, bool):
        _fail(key, "a protocol name or a number 0-255", value)
    if isinstance(value, int):
        if not 0 <= value <= 255:
            _fail(key, "a protocol name or a number 0-255", value)
        return value
    if isinstance(value, str) and (
        _PROTO_NAME.match(value)
        or (value.isascii() and value.isdigit() and int(value) <= 255)
    ):
        return value
    return _fail(
        key, "a protocol name (tcp, udp, icmp, vrrp, …) or a number 0-255", value
    )


def check_proto(value, where: str):
    """The `proto` check for a value outside a rule (a vmap row's proto
    column), with the error placed at `where`."""
    try:
        return _proto("proto", value)
    except BuildError as e:
        detail = str(e).removeprefix("rule key 'proto': ")
        raise BuildError(f"{where}: {detail}") from None


def _flags(key, value):
    checks = value if isinstance(value, list) else [value]
    if not checks:
        _fail(key, "a {match, mask} mapping, or a list of them", value)
    for check in checks:
        if not isinstance(check, dict):
            _fail(key, "a {match, mask} mapping, or a list of them", value)
        unknown = set(check) - {"match", "mask"}
        if unknown:
            raise BuildError(
                f"rule key {key!r}: unknown key(s) {sorted(unknown)} in {check!r} "
                f"(allowed: match, mask)"
            )
    return value


def _log(key, value):
    if isinstance(value, bool):
        return value  # false = no log statement, like `counter: false`
    if not isinstance(value, dict):
        _fail(key, "true, false, or a mapping of prefix / level / group", value)
    unknown = set(value) - {"prefix", "level", "group"}
    if unknown:
        raise BuildError(
            f"rule key {key!r}: unknown key(s) {sorted(unknown)} "
            f"(allowed: prefix, level, group)"
        )
    prefix = value.get("prefix")
    if prefix is not None and (
        not isinstance(prefix, str) or '"' in prefix or "\n" in prefix
    ):
        _fail("log.prefix", "text without a double quote or a line break", prefix)
    level = value.get("level")
    if level is not None and level not in LOG_LEVELS:
        _fail("log.level", f"one of {', '.join(LOG_LEVELS)}", level)
    group = value.get("group")
    if group is not None and (
        isinstance(group, bool) or not isinstance(group, int) or not 0 <= group <= 65535
    ):
        _fail("log.group", "a number 0-65535", group)
    if level is not None and group is not None:
        # nft refuses both at load: `group` sends to NFLOG (userspace), which
        # has no syslog level
        raise BuildError(
            f"rule key {key!r}: `level` and `group` can't be combined — "
            f"`group` logs to NFLOG (userspace), `level` to the kernel log"
        )
    return value


def _counter(key, value):
    if isinstance(value, bool) or (isinstance(value, str) and value):
        return value
    return _fail(key, "true, false, or a declared counter name", value)


def _set_mss(key, value):
    if value in MSS_ALIASES:
        return value
    # the TCP MSS option is 16 bits; 0 would stall every connection it touches
    number = value if isinstance(value, int) and not isinstance(value, bool) else None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        number = int(value)
    if number is not None and 1 <= number <= 65535:
        return value
    return _fail(
        key, f"a size in bytes (1-65535) or one of {', '.join(MSS_ALIASES)}", value
    )


def _action(key, value):
    if isinstance(value, str):
        if value in VERDICTS or _REJECT_WITH.match(value):
            return value
        _fail(
            key,
            f"one of {', '.join(VERDICTS)}, `reject with …`, or a mapping with one "
            f"of {', '.join(ACTION_MAPPING_KEYS)} (anything else: a `raw:` rule)",
            value,
        )
    if not isinstance(value, dict) or len(value) != 1:
        _fail(
            key,
            f"a verdict word, or a mapping with exactly one of "
            f"{', '.join(ACTION_MAPPING_KEYS)}",
            value,
        )
    ((kind, target),) = value.items()
    if kind not in ACTION_MAPPING_KEYS:
        _fail(key, f"a mapping with one of {', '.join(ACTION_MAPPING_KEYS)}", value)
    if kind in ("jump", "goto"):
        _name(f"action.{kind}", target, "a chain name")
    elif not (_is_scalar(target) or isinstance(target, dict)):
        _fail(f"action.{kind}", "an address, a network group, or a port map", target)
    return value


def _mapping(what):
    def check(key, value):
        if not isinstance(value, dict):
            _fail(key, what, value)
        return value

    return check


def _text(what):
    def check(key, value):
        if not isinstance(value, str) or not value:
            _fail(key, what, value)
        return value

    return check


def _plain(what):
    def check(key, value):
        if not _is_scalar(value):
            _fail(key, what, value)
        return value

    return check


def _pattern(regex, what):
    def check(key, value):
        if isinstance(value, bool) or not regex.match(str(value)):
            _fail(key, what, value)
        return value

    return check


def _mark_or(word, what):
    """A mark to set (one number or 0x…), or the one copy source `word`."""

    def check(key, value):
        if value == word:
            return value
        if isinstance(value, bool) or not MARK_SET_VALUE.match(str(value)):
            _fail(key, what, value)
        return value

    return check


def _comment(key, value):
    return check_comment(value, "rule")


_ADDR = _one_or_list("an address, a network group, or a set", _scalar)
_PORT = _one_or_list("a port, a port range, or a service", _scalar)
_IFACE = _one_or_list("an interface group or a set", _scalar)
_MARK = _pattern(MARK_VALUE, "a mark (a number or 0x…, or a range a-b)")

RULE_SCHEMA = {
    "saddr": _ADDR,
    "daddr": _ADDR,
    "sport": _PORT,
    "dport": _PORT,
    "iifname": _IFACE,
    "oifname": _IFACE,
    "iif": _IFACE,
    "oif": _IFACE,
    "ct": _ct,
    "mark": _MARK,
    "ct-mark": _MARK,
    "proto": _proto,
    "icmp-type": _one_or_list("an icmp type name", _scalar),
    "flags": _flags,
    "meter": _mapping("a mapping of set / key / rate / timeout"),
    "limit": _plain("a rate such as 10/minute"),
    "quota": _plain("a quota such as 25 mbytes"),
    "log": _log,
    "set-mark": _mark_or("ct-mark", "a mark (a number or 0x…) or `ct-mark`"),
    "set-ct-mark": _mark_or("mark", "a mark (a number or 0x…) or `mark`"),
    "set-mss": _set_mss,
    "flow-offload": _text("a flowtable name"),
    "counter": _counter,
    "action": _action,
    "comment": _comment,
    "raw": _text("an nft rule as text"),
    "vmap": _mapping("a mapping with `key:` and `map:`"),
    "set": _text("a concat set name"),
}


def check_rule(rule) -> dict:
    """Check every value of a rule against RULE_SCHEMA; return a normalized
    copy (e.g. `ct: established` → `ct: [established]`). Unknown keys are left
    for the caller's key check, which names them all at once."""
    if not isinstance(rule, dict):
        raise BuildError(f"a rule must be a mapping of keys, got {_got(rule)}")
    out = dict(rule)
    for key, value in rule.items():
        check = RULE_SCHEMA.get(key)
        if check is not None:
            out[key] = check(key, value)
    if "icmp-type" in out and ("sport" in out or "dport" in out):
        raise BuildError(
            f"`icmp-type` can't be combined with `sport`/`dport` — icmp has no "
            f"ports: {rule!r}"
        )
    if (
        "set-mark" in out
        and "set-ct-mark" in out
        and (out["set-mark"] == "ct-mark" or out["set-ct-mark"] == "mark")
    ):
        raise BuildError(
            f"`set-mark` and `set-ct-mark` can't share a rule when one copies the "
            f"other — the order decides the result; split them into two rules: "
            f"{rule!r}"
        )
    return out
