"""nftgen — a small, nftables-only firewall-as-code generator.

YAML definitions + host policies -> a native nftables ruleset. See DESIGN.md.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth is pyproject.toml; read it from installed metadata
    # so __version__ can never drift from the packaged version.
    __version__ = version("nftgen")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+source"
