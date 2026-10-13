"""Release constraint parity and Linux-platform regression checks."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "constraints" / "release-0.38.1.txt"


def _manifest_entries() -> list[str]:
    """Return package entries while preserving manifest order."""

    return [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_linux_release_constraint_manifest_matches_pyproject() -> None:
    """Keep the Linux text manifest and both uv constraint arrays identical."""

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    uv = data["tool"]["uv"]
    configured = [
        *uv["constraint-dependencies"],
        *uv["build-constraint-dependencies"],
    ]
    manifest = _manifest_entries()

    assert configured == manifest
    assert "Linux release" in MANIFEST.read_text(encoding="utf-8").splitlines()[0]
    assert all("win32" not in entry.lower() for entry in manifest)
    assert all("colorama" not in entry.lower() for entry in manifest)


def test_release_version_and_constraint_filename_agree() -> None:
    """The versioned manifest must follow the application release number."""

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "0.38.1"
    assert MANIFEST.is_file()
    assert not (ROOT / "constraints" / "release-0.38.0.txt").exists()
    assert not (ROOT / "constraints" / "release-0.37.0.txt").exists()
    assert not (ROOT / "constraints" / "release-0.36.3.txt").exists()
    assert not (ROOT / "constraints" / "release-0.36.0.txt").exists()
    assert not (ROOT / "constraints" / "release-0.35.5.txt").exists()
    assert not (ROOT / "constraints" / "release-0.35.4.txt").exists()
    assert not (ROOT / "constraints" / "release-0.35.3.txt").exists()
    assert not (ROOT / "constraints" / "release-0.35.1.txt").exists()
    assert not (ROOT / "constraints" / "release-0.34.0.txt").exists()
    assert not (ROOT / "constraints" / "release-0.33.0.txt").exists()
    assert not (ROOT / "constraints" / "release-0.32.9.txt").exists()
