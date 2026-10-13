"""`render_tables(annotate=…)` — per-rule `# <note>` file comments (e.g. the
Ansible front-end's git-blame notes). nftgen only places the note."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError

DEFS = Definitions.from_mappings(
    {
        "networks": {"mgmt": ["192.168.9.0/24", "fd00:9::/64"]},
        "services": {"ssh": ["22/tcp"]},
        "interfaces": {"lan": ["lan0"]},
    }
)
SSH = {"saddr": "mgmt", "proto": "tcp", "dport": "ssh", "action": "accept"}
VMAP = {"vmap": {"key": "iifname", "map": {"lan": "accept"}}, "comment": "zones"}
ICMP = {"proto": "icmp", "action": "accept"}
FRAGMENTS = {"icmp": [ICMP]}


def _tables():
    return [
        {
            "family": "inet",
            "name": "filter",
            "chains": [
                {
                    "name": "input",
                    "hook": "input",
                    "rules": [SSH, VMAP, {"include": "icmp"}, {"action": "drop"}],
                }
            ],
        }
    ]


def _notes(rule):
    # identity: the hook gets the caller's own rule objects, incl. from includes
    if rule is SSH:
        return "alice · a1b2c3d · 2026-06-12"
    if rule is VMAP:
        return "bob · e4f5a6b · 2026-07-01"
    if rule is ICMP:
        return "carol · 0c0ffee · 2026-08-15"
    return None  # no note for this rule


def test_notes_go_on_every_line_of_their_rule():
    out = render_tables(_tables(), DEFS, DictResolver(FRAGMENTS), annotate=_notes)
    assert (
        "ip saddr 192.168.9.0/24 tcp dport 22 accept  # alice · a1b2c3d · 2026-06-12\n"
        "        ip6 saddr fd00:9::/64 tcp dport 22 accept  # alice · a1b2c3d · 2026-06-12\n"
    ) in out
    assert 'accept } comment "zones"  # bob · e4f5a6b · 2026-07-01\n' in out
    assert "meta l4proto icmp accept  # carol · 0c0ffee · 2026-08-15\n" in out
    assert "        drop\n" in out  # None -> untouched


def test_without_annotate_output_is_unchanged():
    plain = render_tables(_tables(), DEFS, DictResolver(FRAGMENTS))
    noted = render_tables(_tables(), DEFS, DictResolver(FRAGMENTS), annotate=_notes)
    assert "#" not in plain.split("\n", 2)[2]  # only the header has comments
    # stripping the notes gives back exactly the plain render
    stripped = "\n".join(line.split("  # ", 1)[0] for line in noted.splitlines()) + "\n"
    assert stripped == plain


def test_multiline_note_rejected():
    with pytest.raises(BuildError, match="single-line"):
        render_tables(
            _tables(), DEFS, DictResolver(FRAGMENTS), annotate=lambda r: "a\nb"
        )


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_notes_are_file_only_kernel_ruleset_identical(tmp_path):
    # `#` notes are valid nft and vanish on load: same kernel ruleset either way
    def listed(text):
        path = tmp_path / "r.nft"
        path.write_text(text)
        proc = subprocess.run(
            ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    plain = render_tables(_tables(), DEFS, DictResolver(FRAGMENTS), flush=True)
    noted = render_tables(
        _tables(), DEFS, DictResolver(FRAGMENTS), flush=True, annotate=_notes
    )
    assert noted != plain
    assert listed(noted) == listed(plain)
