"""Regression checks for the operator convenience launchers shipped in scripts/."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_NAMES = (
    "lrun-checkconfig",
    "lrun-clean",
    "lrun-dryrun",
    "lrun-diff",
    "lrun-explain",
    "lrun-get",
    "lrun-paths",
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


SNMP_DIAGNOSTIC_FILES = {
    "gufo-ipv6-test.py": True,
    "gufo-snmp-diag.py": True,
    "pysnmp-snmp-diag.py": True,
    "gufo-readme.txt": False,
}
EXECUTE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _assert_release_mode(name: str, mode: int, *, executable: bool) -> None:
    """Check the executable bit that Git records for a shipped file.

    A checkout or extraction applies the local umask to the remaining permission
    bits, so an exact mode such as 0755 would fail under the documented shared
    umask 0002.
    """

    if executable:
        assert mode & stat.S_IXUSR, f"{name} must be executable (mode {mode:o})"
    else:
        assert not mode & EXECUTE_BITS, f"{name} must not be executable (mode {mode:o})"


def test_snmp_diagnostics_are_shipped_with_release_modes() -> None:
    """Keep all diagnostics executable and their operator notes non-executable."""

    scripts = PROJECT_ROOT / "scripts"
    for name, executable in SNMP_DIAGNOSTIC_FILES.items():
        path = scripts / name
        assert path.is_file(), f"missing SNMP diagnostic file: {name}"
        _assert_release_mode(name, stat.S_IMODE(path.stat().st_mode), executable=executable)


def test_snmp_diagnostics_survive_source_archive_with_modes(
    tmp_path: Path,
) -> None:
    """The release source-archive layout preserves all diagnostic file modes."""

    scripts = PROJECT_ROOT / "scripts"
    archive = tmp_path / "lldp-runner-source.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name in SNMP_DIAGNOSTIC_FILES:
            handle.add(
                scripts / name,
                arcname=f"lldp-runner-test/scripts/{name}",
            )

    with tarfile.open(archive) as handle:
        members = {member.name: member for member in handle.getmembers()}
    for name, executable in SNMP_DIAGNOSTIC_FILES.items():
        member = members[f"lldp-runner-test/scripts/{name}"]
        assert member.isfile()
        source_mode = stat.S_IMODE((scripts / name).stat().st_mode) & 0o777
        assert member.mode & 0o777 == source_mode
        _assert_release_mode(name, member.mode & 0o777, executable=executable)


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
    """Cleanup may run concurrently; the launcher selects the deployed config."""

    text = (PROJECT_ROOT / "scripts" / "lrun-clean").read_text(encoding="utf-8")
    app_args = text.split("APP_ARGS=(", 1)[1].split(")", 1)[0]
    assert app_args.strip() == "clean"
    assert "SINGLE_INSTANCE=false" in text


def test_purge_launcher_uses_purge_without_single_instance_guard() -> None:
    """Purge may run concurrently; the launcher selects the deployed config."""

    text = (PROJECT_ROOT / "scripts" / "lrun-purge").read_text(encoding="utf-8")
    app_args = text.split("APP_ARGS=(", 1)[1].split(")", 1)[0]
    assert app_args.strip() == "purge"
    assert "SINGLE_INSTANCE=false" in text


def test_launchers_embed_no_installation_path() -> None:
    """A launcher must work for /opt, /etc, and home-directory installations alike."""

    for name in SCRIPT_NAMES:
        text = (PROJECT_ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "/opt/lldp-runner" not in text, name
        if name != "lrun-bundle-diff":
            assert "KEEP_WORKING_DIRECTORY=" in text, name


def test_shared_setup_helper_is_shipped_and_documents_group_inheritance() -> None:
    """Keep the root-run shared-directory helper safe and discoverable."""

    path = PROJECT_ROOT / "scripts" / "shared-setup.sh"
    assert path.is_file()
    assert os.access(path, os.X_OK)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "chmod -R g+rwX,o-rwx" in text
    assert 'find "$root" -type d -exec chmod g+s' in text
    assert "setfacl" in text
    assert "umask 0002" in text
    assert 'LAYOUT="${LLDP_RUNNER_LAYOUT:-shared}"' in text
    assert 'GROUP_NAME="${LLDP_RUNNER_GROUP:-netops}"' in text
    assert 'PROJECT_ROOT="${LLDP_RUNNER_PROJECT_ROOT:-/opt/lldp-runner}"' in text
    assert ': "${PERSISTENT_ROOT:=${PROJECT_ROOT}/var}"' in text
    assert ': "${SCRATCH_ROOT:=/dev/shm/lldp-runner}"' in text
    assert ': "${PERSISTENT_ROOT:=/var/lib/lldp-runner}"' in text
    assert 'PYTHON_DIR="${UV_PYTHON_INSTALL_DIR:-/opt/shared/python}"' in text
    assert '"$PERSISTENT_ROOT/runs" "$PERSISTENT_ROOT/outputs" "$PERSISTENT_ROOT/tmp"' in text
    assert "-m 2770" in text and "2775" not in text
    assert "must not be the project root or one of its parents" in text
    assert "/etc/tmpfiles.d/lldp-runner-scratch.conf" in text
    # An existing interpreter directory keeps its owner; only a missing one is created.
    assert 'if [[ ! -e "$PYTHON_DIR" ]]; then\n    install -d -o root -g root -m 0755' in text


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
    assert app_args.strip() == "diff"
    assert "KEEP_WORKING_DIRECTORY=true" in text
    assert 'exec "$UV_BIN" run --project "$project_directory"' in text
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
    assert ': "${PERSISTENT_ROOT:=${PROJECT_ROOT}/var}"' in text
    assert "run scripts/shared-setup.sh first" in text
    assert "Environment=UV_CACHE_DIR=/var/cache/$CACHE_DIRECTORY_NAME/uv" in text
    assert "CacheDirectory=$CACHE_DIRECTORY_NAME" in text
    assert "2775" not in text
    assert "is not a member of group" in text
    assert "run scripts/svc-remove.sh first" in text
    assert "lrun-clean && $PROJECT_ROOT/scripts/lrun-purge --keep $PURGE_KEEP" in text
    assert "paths may not contain single quotes" in text

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
    assert "export UV_NO_CACHE=1" in text
    assert not (scripts / "lldp-runner.env.example").exists()


def _launcher_project(tmp_path: Path, *, source: bool) -> Path:
    """Copy one launcher set into a scratch project directory."""

    project = tmp_path / "install"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    for name in ("lrun-run", "lrun-show", "lrun-diff"):
        target = scripts / name
        target.write_text(
            (PROJECT_ROOT / "scripts" / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
        target.chmod(0o755)
    if source:
        (project / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    return project


def _write_recorder(path: Path) -> None:
    """Write a uv/lldp-runner stand-in that records how it was started."""

    path.write_text(
        "#!/usr/bin/env bash\n"
        'printf "cwd=%s\\n" "$PWD"\n'
        'printf "config=%s\\n" "${LLDP_RUNNER_CONFIG:-}"\n'
        'printf "arg=%s\\n" "$@"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_launcher(
    launcher: Path, bin_dir: Path, *args: str, cwd: Path, env: dict[str, str] | None = None
) -> list[str]:
    environment = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(cwd)}
    environment.update(env or {})
    result = subprocess.run(
        [str(launcher), *args],
        check=True,
        text=True,
        capture_output=True,
        cwd=cwd,
        env=environment,
    )
    return result.stdout.splitlines()


def test_launcher_selects_project_config_and_resolves_seed_file_beside_it(
    tmp_path: Path,
) -> None:
    project = _launcher_project(tmp_path, source=True)
    (project / "config.toml").write_text("", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_recorder(bin_dir / "uv")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    lines = _run_launcher(project / "scripts" / "lrun-run", bin_dir, "--dry-run", cwd=elsewhere)

    resolved = project.resolve()
    assert f"cwd={resolved}" in lines
    assert f"config={resolved}/config.toml" in lines
    args = [line.removeprefix("arg=") for line in lines if line.startswith("arg=")]
    assert args == [
        "run",
        "--project",
        str(resolved),
        "lldp-runner",
        "run",
        "--seed-file",
        "seed.list",
        "--dry-run",
    ]


def test_launcher_honors_relative_config_override_and_its_directory(tmp_path: Path) -> None:
    project = _launcher_project(tmp_path, source=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_recorder(bin_dir / "uv")
    site = tmp_path / "site"
    site.mkdir()
    (site / "lab.toml").write_text("", encoding="utf-8")

    lines = _run_launcher(
        project / "scripts" / "lrun-show",
        bin_dir,
        "core1",
        cwd=tmp_path,
        env={"LLDP_RUNNER_CONFIG": "site/lab.toml"},
    )

    assert f"cwd={tmp_path}/site" in lines
    assert f"config={tmp_path}/site/lab.toml" in lines


def test_diff_launcher_keeps_operator_directory(tmp_path: Path) -> None:
    project = _launcher_project(tmp_path, source=True)
    (project / "config.toml").write_text("", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_recorder(bin_dir / "uv")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    lines = _run_launcher(project / "scripts" / "lrun-diff", bin_dir, cwd=elsewhere)

    assert f"cwd={elsewhere}" in lines
    assert f"config={project.resolve()}/config.toml" in lines


def test_packaged_launcher_runs_installed_command_without_uv(tmp_path: Path) -> None:
    project = _launcher_project(tmp_path, source=False)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_recorder(bin_dir / "lldp-runner")

    lines = _run_launcher(project / "scripts" / "lrun-show", bin_dir, "core1", cwd=tmp_path)

    args = [line.removeprefix("arg=") for line in lines if line.startswith("arg=")]
    assert args == ["show-neighbors", "core1"]


def test_bundle_diff_reads_installation_paths_from_lrun_paths(tmp_path: Path) -> None:
    """Without overrides, the bundle uses the configured outputs and runs."""

    import json

    data = tmp_path / "opt" / "lldp-runner" / "var"
    archive_dir = tmp_path / "bundles"
    archive_dir.mkdir()
    _write_review_run(data, "run-1", "2026-08-29T08:00:00-04:00")
    _write_review_run(data, "run-2", "2026-08-29T09:00:00-04:00")
    fake_diff = tmp_path / "lrun-diff"
    _write_fake_diff(fake_diff, data / "outputs")
    fake_paths = tmp_path / "lrun-paths"
    report = {"outputs_dir": str(data / "outputs"), "runs_dir": str(data / "runs")}
    fake_paths.write_text(f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(report)}\nEOF\n", encoding="utf-8")
    fake_paths.chmod(0o755)
    env = os.environ.copy()
    for name in ("LLDP_RUNNER_BUNDLE_ROOT", "LLDP_RUNNER_OUTPUTS_DIR", "LLDP_RUNNER_RUNS_DIR"):
        env.pop(name, None)
    env.update(
        {
            "LLDP_RUNNER_PATHS_BIN": str(fake_paths),
            "LLDP_RUNNER_BUNDLE_ARCHIVE_DIR": str(archive_dir),
            "LLDP_RUNNER_DIFF_BIN": str(fake_diff),
        }
    )

    result = subprocess.run(
        [str(PROJECT_ROOT / "scripts" / "lrun-bundle-diff")],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )

    assert "Run A:          run-2" in result.stdout, result.stderr
    assert (archive_dir / "lldp-runner-bundle-run-2-run-1.tar").is_file()


def _write_fake_pandoc(directory: Path) -> Path:
    """Create a pandoc stand-in that writes a minimal page to --output."""

    fake_pandoc = directory / "pandoc"
    fake_pandoc.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "output=\n"
        'for arg in "$@"; do\n'
        '  case "$arg" in\n'
        "    --output=*) output=${arg#--output=} ;;\n"
        "  esac\n"
        "done\n"
        '[ -n "$output" ]\n'
        "printf '<!doctype html><title>test</title>\\n' > \"$output\"\n",
        encoding="utf-8",
    )
    fake_pandoc.chmod(0o755)
    return fake_pandoc


def test_markdown_publisher_uses_hyphenated_flat_names(tmp_path: Path) -> None:
    """Subdirectory Markdown should publish with readable path prefixes."""

    script = PROJECT_ROOT / "scripts" / "md-to-html.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)

    project = tmp_path / "sample-project"
    (project / "docs" / "guides").mkdir(parents=True)
    (project / "README.md").write_text("# Root\n", encoding="utf-8")
    (project / "docs" / "CLI.md").write_text("# CLI\n", encoding="utf-8")
    (project / "docs" / "guides" / "OPS.md").write_text("# Operations\n", encoding="utf-8")

    output = tmp_path / "html"
    env = os.environ.copy()
    env["PANDOC_BIN"] = str(_write_fake_pandoc(tmp_path))
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


def test_markdown_publisher_links_repository_from_pyproject(tmp_path: Path) -> None:
    """The index should link [project.urls] Repository unless overridden."""

    script = PROJECT_ROOT / "scripts" / "md-to-html.sh"
    project = tmp_path / "sample-project"
    project.mkdir()
    (project / "README.md").write_text("# Root\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "sample"\n\n'
        '[project.urls]\nRepository = "https://example.com/sample?a=1&b=2"\n',
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PANDOC_BIN"] = str(_write_fake_pandoc(tmp_path))
    env.pop("REPO_URL", None)

    def publish(output: Path, *extra: str) -> str:
        subprocess.run(
            [str(script), "--project-dir", str(project), "--output-dir", str(output), *extra],
            check=True,
            env=env,
            text=True,
            capture_output=True,
        )
        return (output / "index.html").read_text(encoding="utf-8")

    index = publish(tmp_path / "default")
    assert '<a href="https://example.com/sample?a=1&amp;b=2">' in index

    index = publish(tmp_path / "override", "--repo-url", "https://example.org/fork")
    assert '<a href="https://example.org/fork">' in index
    assert "example.com/sample" not in index

    index = publish(tmp_path / "omitted", "--repo-url", "")
    assert "Source repository" not in index

    with pytest.raises(subprocess.CalledProcessError) as rejected:
        publish(tmp_path / "rejected", "--repo-url", "javascript:alert(1)")
    assert "must be an http:// or https:// URL" in rejected.value.stderr


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


def _write_fake_diff(path: Path, outputs_dir: Path | None = None) -> None:
    """Write a deterministic lrun-diff stand-in with the real source contract.

    The reported source paths are below ``LLDP_RUNNER_OUTPUTS_DIR``, or below
    ``outputs_dir`` when that variable is unset.
    """

    default = "" if outputs_dir is None else str(outputs_dir)

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
    "$run_a" "${LLDP_RUNNER_OUTPUTS_DIR:-__DEFAULT__}" "$run_a" \\
    "$run_b" "${LLDP_RUNNER_OUTPUTS_DIR:-__DEFAULT__}" "$run_b"
exit 1
""".replace("__DEFAULT__", default),
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
        assert connection.execute("SELECT value FROM fixture").fetchone() == ("review",)


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
