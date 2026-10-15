"""Step 2 — build(<root>): fleet generation + flush-ruleset deploy artifact."""

import pathlib

import pytest

from nftgen import validate
from nftgen.cli import main
from nftgen.generate import build
from nftgen.ir import BuildError

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "example"

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def test_build_all_hosts():
    out = build(EXAMPLE)
    assert set(out) == {"gateway", "router1", "router2"}
    for text in out.values():
        assert text.startswith("#!/usr/sbin/nft -f")
        assert "flush ruleset" in text  # deploy artifact (Shape A)


def test_build_single_host():
    out = build(EXAMPLE, host="router1")
    assert set(out) == {"router1"}


def test_build_missing_host_errors():
    with pytest.raises(FileNotFoundError):
        build(EXAMPLE, host="does-not-exist")


def test_build_no_hosts_errors(tmp_path):
    # a typo'd/empty root used to return {} — exit 0 with nothing checked
    (tmp_path / "policies" / "hosts").mkdir(parents=True)
    with pytest.raises(FileNotFoundError, match="no host policies under"):
        build(tmp_path)
    with pytest.raises(FileNotFoundError, match="no host policies under"):
        build(tmp_path / "nope")


def test_cli_build_missing_root_fails_and_writes_nothing(tmp_path, capsys):
    root = tmp_path / "exmaple"
    assert main(["build", str(root)]) == 1
    assert "no host policies under" in capsys.readouterr().err
    assert not root.exists()  # no stray generated/ created


def _host_tree(tmp_path, *names):
    (tmp_path / "definitions").mkdir()
    hosts = tmp_path / "policies" / "hosts"
    hosts.mkdir(parents=True)
    policy = "tables:\n  - family: inet\n    name: f\n"
    for n in names:
        (hosts / n).write_text(policy)
    return tmp_path


def test_build_same_host_twice_errors(tmp_path):
    # C14: fw1.yaml + fw1.yml both became host 'fw1'; one silently won
    root = _host_tree(tmp_path, "fw1.yaml", "fw1.yml", "fw2.yaml")
    with pytest.raises(
        BuildError, match=r"two host policies for 'fw1': fw1.yaml, fw1.yml"
    ):
        build(root)
    with pytest.raises(BuildError, match="two host policies for 'fw1'"):
        build(root, host="fw1")
    assert list(build(root, host="fw2")) == ["fw2"]


def test_build_host_is_an_exact_name(tmp_path):
    # C14: `--host '*'` globbed; with --stdout it printed the first host
    root = _host_tree(tmp_path, "fw1.yaml", "fw2.yml")
    with pytest.raises(FileNotFoundError, match="no host policy '\\*'"):
        build(root, host="*")
    assert list(build(root, host="fw2")) == ["fw2"]


@pytest.mark.parametrize(
    "name", ["../includes/x", "sub/fw1", "..", ".hidden", "a\\b", ""]
)
def test_build_host_must_be_a_plain_name(tmp_path, name):
    # review N2: `--host ../includes/x` read a file outside policies/hosts/
    root = _host_tree(tmp_path, "fw1.yaml")
    with pytest.raises(BuildError, match="--host must be a plain host name"):
        build(root, host=name)


def test_build_ignores_non_yaml_files(tmp_path):
    root = _host_tree(tmp_path, "fw1.yaml", "notes.txt", "fw1.yaml.bak")
    assert list(build(root)) == ["fw1"]


def test_flush_precedes_tables():
    text = build(EXAMPLE, host="router1")["router1"]
    assert text.index("flush ruleset") < text.index("table inet")


def test_build_body_matches_generate_golden():
    # build() == the committed (flush-free) golden, plus the flush line — i.e.
    # build is generate() + the deploy header, nothing else changes.
    text = build(EXAMPLE, host="router1")["router1"]
    golden = (ROOT / "tests" / "golden" / "router1.nft").read_text()
    assert text == golden.replace(
        "\n\ntable inet raw", "\n\nflush ruleset\n\ntable inet raw", 1
    )


def test_cli_build_writes_files(tmp_path):
    assert main(["build", str(EXAMPLE), "--out-dir", str(tmp_path)]) == 0
    for host in ("gateway", "router1", "router2"):
        assert (tmp_path / f"{host}.nft").exists()


def test_cli_build_stdout_requires_host(capsys):
    # stdout is a single stream, so it only makes sense for one host.
    assert main(["build", str(EXAMPLE), "--stdout"]) == 2
    assert "--stdout requires --host" in capsys.readouterr().err


def test_cli_build_stdout_emits_and_writes_nothing(tmp_path, capsys):
    # --stdout emits the host's deploy artifact byte-for-byte and touches no file.
    assert (
        main(
            [
                "build",
                str(EXAMPLE),
                "--host",
                "router1",
                "--stdout",
                "--out-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out == build(EXAMPLE, host="router1")["router1"]
    assert out.startswith("#!/usr/sbin/nft -f")
    assert not list(tmp_path.glob("*.nft"))  # nothing written, even with --out-dir set


def test_cli_build_check_unusable_fails_loudly(tmp_path, monkeypatch, capsys):
    # --check must never silently skip: CI asking for validation has to know
    # when it didn't run.
    monkeypatch.setattr(validate, "can_check", lambda: False)
    assert main(["build", str(EXAMPLE), "--out-dir", str(tmp_path), "--check"]) == 2
    assert "--check requested" in capsys.readouterr().err
    assert not list(tmp_path.glob("*.nft"))  # refused before writing


def test_cli_single_policy_check_unusable_fails_loudly(tmp_path, monkeypatch, capsys):
    # C11: the single-policy form used to probe only "is an nft binary there?"
    # and only after writing the output; it now uses the same probe as build,
    # before rendering anything.
    monkeypatch.setattr(validate, "can_check", lambda: False)
    out = tmp_path / "r1.nft"
    rc = main(
        [
            str(EXAMPLE / "policies" / "hosts" / "router1.yaml"),
            "--defs",
            str(EXAMPLE / "definitions"),
            "--out",
            str(out),
            "--check",
        ]
    )
    assert rc == 2
    assert "`nft -c` is not usable here" in capsys.readouterr().err
    assert not out.exists()  # refused before writing


def test_cli_authoring_error_is_clean(tmp_path, capsys):
    # authoring mistakes exit 1 with a one-line message, not a traceback
    root = tmp_path / "proj"
    (root / "policies" / "hosts").mkdir(parents=True)
    (root / "definitions").mkdir()
    (root / "policies" / "hosts" / "h1.yaml").write_text("tabels: []\n")
    assert main(["build", str(root)]) == 1
    err = capsys.readouterr().err
    assert "nftgen: error:" in err
    assert "unknown policy key" in err


@requires_nft
@pytest.mark.parametrize("host", ["gateway", "router1", "router2"])
def test_build_output_is_valid_nft(host):
    result = validate.check(build(EXAMPLE, host=host)[host])
    assert result.ok, result.stderr
