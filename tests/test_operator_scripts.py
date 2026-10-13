"""Regression checks for the operator convenience launchers shipped in scripts/."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_NAMES = (
    "lrun-checkconfig",
    "lrun-clean",
    "lrun-dryrun",
    "lrun-diff",
    "lrun-explain",
    "lrun-get",
    "lrun-run",
    "lrun-purge",
    "lrun-bundle-diff",
    "lrun-seedrun",
    "lrun-show",
    "lrun-version",
    "lrun-watch",
)

DISALLOWED_SCRIPT_NAMES = (
    "lrun-prepare-bundle",
    "lrun-prepare-diff",
)


def test_operator_launchers_are_shipped_and_executable() -> None:
    """Keep the documented operational helpers in source releases as executables."""

    scripts_dir = PROJECT_ROOT / "scripts"
    for name in SCRIPT_NAMES:
        path = scripts_dir / name
        assert path.is_file(), f"missing operator launcher: {name}"
        assert os.access(path, os.X_OK), f"operator launcher is not executable: {name}"
        assert path.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")

    for name in DISALLOWED_SCRIPT_NAMES:
        assert not (scripts_dir / name).exists(), f"disallowed launcher shipped: {name}"


def test_snmp_diagnostics_are_shipped_with_release_modes() -> None:
    """Keep all diagnostics executable and their operator notes non-executable."""

    expected = {
        "gufo-ipv6-test.py": 0o755,
        "gufo-snmp-diag.py": 0o755,
        "pysnmp-snmp-diag.py": 0o755,
        "gufo-readme.txt": 0o644,
    }
    scripts = PROJECT_ROOT / "scripts"
    for name, mode in expected.items():
        path = scripts / name
        assert path.is_file(), f"missing SNMP diagnostic file: {name}"
        assert stat.S_IMODE(path.stat().st_mode) == mode


def test_snmp_diagnostics_survive_source_archive_with_modes(
    tmp_path: Path,
) -> None:
    """The release source-archive layout preserves all diagnostic file modes."""

    expected = {
        "gufo-ipv6-test.py": 0o755,
        "gufo-snmp-diag.py": 0o755,
        "pysnmp-snmp-diag.py": 0o755,
        "gufo-readme.txt": 0o644,
    }
    archive = tmp_path / "lldp-runner-source.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name in expected:
            handle.add(
                PROJECT_ROOT / "scripts" / name,
                arcname=f"lldp-runner-test/scripts/{name}",
            )

    with tarfile.open(archive) as handle:
        members = {member.name: member for member in handle.getmembers()}
    for name, mode in expected.items():
        member = members[f"lldp-runner-test/scripts/{name}"]
        assert member.isfile()
        assert member.mode & 0o777 == mode


def test_snmp_diagnostic_help_and_source_compile_without_dependencies() -> None:
    """Fresh-source help remains useful before either SNMP library is installed."""

    scripts = PROJECT_ROOT / "scripts"
    for name in (
        "gufo-ipv6-test.py",
        "gufo-snmp-diag.py",
        "pysnmp-snmp-diag.py",
    ):
        path = scripts / name
        subprocess.run(
            [sys.executable, "-m", "py_compile", str(path)],
            check=True,
            text=True,
            capture_output=True,
        )
        result = subprocess.run(
            [sys.executable, str(path), "--help"],
            check=False,
            text=True,
            capture_output=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout.lower()


def test_gufo_readme_uses_canonical_names_and_valid_ipv6_examples() -> None:
    """Operator examples must match shipped filenames and valid IPv6 syntax."""

    text = (PROJECT_ROOT / "scripts" / "gufo-readme.txt").read_text(encoding="utf-8")
    assert "./gufo-ipv6-test.py" in text
    assert "./gufo-snmp-diag.py" in text
    assert "gufo_ipv6_test.py" not in text
    assert "gufo_snmp_diag.py" not in text
    assert ":::" not in text


def test_clean_launcher_uses_clean_without_single_instance_guard() -> None:
    """Cleanup may run concurrently and should target the deployed config."""

    text = (PROJECT_ROOT / "scripts" / "lrun-clean").read_text(encoding="utf-8")
    assert '--config "/opt/lldp-runner/config.toml"' in text
    assert "  clean\n" in text
    assert "SINGLE_INSTANCE=false" in text


def test_purge_launcher_uses_purge_without_single_instance_guard() -> None:
    """Purge may run concurrently and should target the deployed config."""

    text = (PROJECT_ROOT / "scripts" / "lrun-purge").read_text(encoding="utf-8")
    assert '--config "/opt/lldp-runner/config.toml"' in text
    assert "  purge\n" in text
    assert "SINGLE_INSTANCE=false" in text


def test_shared_setup_helper_is_shipped_and_documents_group_inheritance() -> None:
    """Keep the root-run shared-directory helper safe and discoverable."""

    path = PROJECT_ROOT / "scripts" / "shared-setup.sh"
    assert path.is_file()
    assert os.access(path, os.X_OK)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "chmod -R g+rwX" in text
    assert "find \"$root\" -type d -exec chmod g+s" in text
    assert "setfacl" in text
    assert "umask 0002" in text
    assert '# GROUP_NAME="${LLDP_RUNNER_GROUP:-lldp-runner}"' in text
    assert '# PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-/var/lib/lldp-runner}"' in text
    assert '# SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/var/tmp/lldp-runner}"' in text
    assert 'GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"' in text
    assert 'PERSISTENT_ROOT="${LLDP_RUNNER_PERSISTENT_ROOT:-/opt/lldp-runner}"' in text
    assert 'SCRATCH_ROOT="${LLDP_RUNNER_SCRATCH_ROOT:-/dev/shm/lldp-runner}"' in text
    assert 'PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"' in text
    assert '"$PERSISTENT_ROOT/runs" "$PERSISTENT_ROOT/outputs"' in text
    assert '"$PERSISTENT_ROOT/output"' not in text


def test_version_launcher_runs_version_without_configuration() -> None:
    """Version launcher should invoke the credential/config-free version command."""

    text = (PROJECT_ROOT / "scripts" / "lrun-version").read_text(encoding="utf-8")
    app_args = text.split("APP_ARGS=(", 1)[1].split(")", 1)[0]
    assert "  version\n" in app_args
    assert "--config" not in app_args
    assert "SINGLE_INSTANCE=false" in text


def test_diff_launcher_runs_diff_and_preserves_operator_working_directory() -> None:
    """Diff launcher must keep relative --file paths relative to the caller."""

    text = (PROJECT_ROOT / "scripts" / "lrun-diff").read_text(encoding="utf-8")
    app_args = text.split("APP_ARGS=(", 1)[1].split(")", 1)[0]
    assert "--config /opt/lldp-runner/config.toml diff" in app_args
    assert 'exec "$UV_BIN" run --project "$project_directory"' in text
    assert '\ncd -- "$project_directory"\n' not in text
    assert "SINGLE_INSTANCE=false" in text


def test_explain_launcher_runs_explain_target_without_fixed_config() -> None:
    """Explain launcher should use normal config discovery for the read-only command."""

    text = (PROJECT_ROOT / "scripts" / "lrun-explain").read_text(encoding="utf-8")
    app_args = text.split("APP_ARGS=(", 1)[1].split(")", 1)[0]
    assert "  explain-target\n" in app_args
    assert "--config" not in app_args
    assert "SINGLE_INSTANCE=false" in text


def test_systemd_service_helpers_are_shipped_and_safe() -> None:
    """Service helpers should validate identity, schedule jitter, and scratch setup."""

    setup = PROJECT_ROOT / "scripts" / "svc-setup.sh"
    remove = PROJECT_ROOT / "scripts" / "svc-remove.sh"
    for path in (setup, remove):
        assert path.is_file()
        assert os.access(path, os.X_OK)
        assert path.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")

    text = setup.read_text(encoding="utf-8")
    assert 'SERVICE_USER="${LLDP_RUNNER_SERVICE_USER:-lldp-runner}"' in text
    assert 'GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"' in text
    assert 'RANDOM_DELAY_MINUTES="${LLDP_RUNNER_RANDOM_DELAY_MINUTES:-10}"' in text
    assert "RandomizedDelaySec=${RANDOM_DELAY_MINUTES}min" in text
    assert "FixedRandomDelay=true" in text
    assert "systemd-tmpfiles --create" in text
    assert "2775 $SERVICE_USER $GROUP_NAME" in text
    assert "is not a member of group" in text
    assert "run scripts/svc-remove.sh first" in text
    assert "lrun-clean && $PROJECT_ROOT/scripts/lrun-purge --keep $PURGE_KEEP" in text
    assert 'paths may not contain single quotes' in text

    remove_text = remove.read_text(encoding="utf-8")
    assert "Runtime/output data was preserved" in remove_text
    assert "systemctl daemon-reload" in remove_text


def test_shared_private_example_is_shipped_for_central_uv_use() -> None:
    """Keep the shared launcher example aligned with maintainer/operator roles."""

    scripts = PROJECT_ROOT / "scripts"
    path = scripts / "example.private"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert 'export UV_PYTHON_INSTALL_DIR="/opt/shared/python"' in text
    assert 'export UV_LINK_MODE="copy"' in text
    assert "umask 0002" in text
    assert 'LLDP_RUNNER_DEVELOPER_ACCOUNT="lldp-maintainer"' in text
    assert "UV_RUN_ARGS=(--no-sync)" in text
    assert not (scripts / "lldp-runner.env.example").exists()


def test_markdown_publisher_uses_hyphenated_flat_names(tmp_path: Path) -> None:
    """Subdirectory Markdown should publish with readable path prefixes."""

    script = PROJECT_ROOT / "scripts" / "md-to-html.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)

    project = tmp_path / "sample-project"
    (project / "docs" / "guides").mkdir(parents=True)
    (project / "README.md").write_text("# Root\n", encoding="utf-8")
    (project / "docs" / "CLI.md").write_text("# CLI\n", encoding="utf-8")
    (project / "docs" / "guides" / "OPS.md").write_text(
        "# Operations\n", encoding="utf-8"
    )

    fake_pandoc = tmp_path / "pandoc"
    fake_pandoc.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "output=\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    --output=*) output=${arg#--output=} ;;\n"
        "  esac\n"
        "done\n"
        "[ -n \"$output\" ]\n"
        "printf '<!doctype html><title>test</title>\\n' > \"$output\"\n",
        encoding="utf-8",
    )
    fake_pandoc.chmod(0o755)

    output = tmp_path / "html"
    env = os.environ.copy()
    env["PANDOC_BIN"] = str(fake_pandoc)
    subprocess.run(
        [
            str(script),
            "--project-dir",
            str(project),
            "--output-dir",
            str(output),
        ],
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )

    generated = {path.name for path in output.iterdir() if path.is_file()}
    assert "README.html" in generated
    assert "docs-CLI.html" in generated
    assert "docs-guides-OPS.html" in generated
    assert "docs__CLI.html" not in generated
    assert "index.html" in generated


def _write_review_run(root: Path, run_id: str, completed: str) -> None:
    """Create minimal finalized output and runtime trees for bundle tests."""

    import json
    import sqlite3

    output = root / "outputs" / run_id
    runtime = root / "runs" / run_id
    output.mkdir(parents=True)
    runtime.mkdir(parents=True)
    (output / "discovery.json").write_text(
        json.dumps({"schema_version": 8, "hosts": [], "errors": []}),
        encoding="utf-8",
    )
    (output / "run.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "status": "COMPLETED",
                "completed": completed,
            }
        ),
        encoding="utf-8",
    )
    state_path = runtime / "discovery-state.sqlite"
    with sqlite3.connect(state_path) as connection:
        connection.execute("CREATE TABLE fixture(value TEXT NOT NULL)")
        connection.execute("INSERT INTO fixture(value) VALUES('review')")
        connection.commit()
    # Sidecars can remain next to a completed run when another process recently
    # inspected it. The bundle must publish one coherent database, not copy these
    # process-local files.
    (runtime / "discovery-state.sqlite-wal").write_bytes(b"")
    (runtime / "discovery-state.sqlite-shm").write_bytes(b"")


def _write_fake_diff(path: Path) -> None:
    """Write a deterministic lrun-diff stand-in with the real source contract."""

    path.write_text(
        """#!/usr/bin/env bash
set -eu
run_a=
run_b=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --runid)
            if [ -z "$run_a" ]; then run_a=$2; else run_b=$2; fi
            shift 2
            ;;
        --changes-only|--json)
            shift
            ;;
        *)
            exit 2
            ;;
    esac
done
printf '{"sources":{"a":{"run_id":"%s","path":"%s/%s/discovery.json"},"b":{"run_id":"%s","path":"%s/%s/discovery.json"}},"result":{"exit_code":1}}\\n' \\
    "$run_a" "$LLDP_RUNNER_OUTPUTS_DIR" "$run_a" \\
    "$run_b" "$LLDP_RUNNER_OUTPUTS_DIR" "$run_b"
exit 1
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_bundle_diff_selects_latest_runs_and_preserves_layout(tmp_path: Path) -> None:
    """The helper creates one portable archive with an embedded JSON diff."""

    root = tmp_path / "project"
    archive_dir = tmp_path / "bundles"
    archive_dir.mkdir()
    _write_review_run(root, "20260107-01", "2026-08-29T08:00:00-04:00")
    _write_review_run(root, "20260107-02", "2026-08-29T09:00:00-04:00")
    _write_review_run(root, "20260107-03", "2026-08-29T10:00:00-04:00")
    fake_diff = tmp_path / "lrun-diff"
    _write_fake_diff(fake_diff)

    env = os.environ.copy()
    env.update(
        {
            "LLDP_RUNNER_BUNDLE_ROOT": str(root),
            "LLDP_RUNNER_OUTPUTS_DIR": str(root / "outputs"),
            "LLDP_RUNNER_RUNS_DIR": str(root / "runs"),
            "LLDP_RUNNER_BUNDLE_ARCHIVE_DIR": str(archive_dir),
            "LLDP_RUNNER_DIFF_BIN": str(fake_diff),
        }
    )
    result = subprocess.run(
        [str(PROJECT_ROOT / "scripts" / "lrun-bundle-diff")],
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )
    archive = archive_dir / "lldp-runner-bundle-20260107-03-20260107-02.tar"
    assert archive.is_file()
    assert "Run A:          20260107-03" in result.stdout
    assert "Run B:          20260107-02" in result.stdout
    with tarfile.open(archive) as handle:
        names = set(handle.getnames())
    assert "outputs/20260107-03/discovery.json" in names
    assert "outputs/20260107-02/discovery.json" in names
    assert "runs/20260107-03/discovery-state.sqlite" in names
    assert "runs/20260107-02/discovery-state.sqlite" in names
    assert not any(name.endswith("discovery-state.sqlite-wal") for name in names)
    assert not any(name.endswith("discovery-state.sqlite-shm") for name in names)
    assert "./diff-20260107-03-20260107-02.changes.json" in names

    extracted = tmp_path / "extracted"
    with tarfile.open(archive) as handle:
        handle.extractall(extracted, filter="data")
    import sqlite3

    with sqlite3.connect(
        extracted / "runs" / "20260107-03" / "discovery-state.sqlite"
    ) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM fixture").fetchone() == (
            "review",
        )


def test_bundle_diff_requires_matching_output_and_runtime_directories(
    tmp_path: Path,
) -> None:
    """An explicit run pair fails before diff when either tree is missing."""

    root = tmp_path / "project"
    archive_dir = tmp_path / "bundles"
    archive_dir.mkdir()
    _write_review_run(root, "run-a", "2026-08-29T10:00:00-04:00")
    _write_review_run(root, "run-b", "2026-08-29T09:00:00-04:00")
    (root / "runs" / "run-b").rename(root / "runs" / "run-b-missing")
    fake_diff = tmp_path / "lrun-diff"
    _write_fake_diff(fake_diff)
    env = os.environ.copy()
    env.update(
        {
            "LLDP_RUNNER_BUNDLE_ROOT": str(root),
            "LLDP_RUNNER_OUTPUTS_DIR": str(root / "outputs"),
            "LLDP_RUNNER_RUNS_DIR": str(root / "runs"),
            "LLDP_RUNNER_BUNDLE_ARCHIVE_DIR": str(archive_dir),
            "LLDP_RUNNER_DIFF_BIN": str(fake_diff),
        }
    )
    result = subprocess.run(
        [
            str(PROJECT_ROOT / "scripts" / "lrun-bundle-diff"),
            "run-a",
            "run-b",
        ],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )
    assert result.returncode == 1
    assert "required directory is missing: runs/run-b" in result.stderr
    assert not list(archive_dir.iterdir())
