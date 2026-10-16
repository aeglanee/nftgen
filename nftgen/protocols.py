"""Layer-4 protocols: the names nftgen checks, and their IANA numbers.

Shared by definitions (service `port/proto` entries), the IR (concat sets)
and the renderer (rules, vmaps, nat maps), so `17` and `udp` mean the same
everywhere.
"""

from __future__ import annotations

# IANA numbers of the protocols nftgen checks by name; `proto: 17` is checked
# (and, where nft needs a keyword, rendered) as `udp`
PROTO_NUMBERS = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    33: "dccp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    112: "vrrp",
    132: "sctp",
    136: "udplite",
}
# protocols with ports: `<proto> dport …` needs one of these as its keyword
PORT_PROTOS = ("tcp", "udp", "sctp", "dccp", "udplite")


def proto_name(value) -> str | None:
    """A rule's `proto` as a name: a known number becomes its name, anything
    else stays as written. None when there is no proto."""
    if value is None:
        return None
    text = str(value)
    if text.isascii() and text.isdigit():
        return PROTO_NUMBERS.get(int(text), text)
    return text
