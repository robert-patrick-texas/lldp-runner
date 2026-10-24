"""Install-layout rules for ``auto`` persistent and scratch roots.

An LLDP-Runner installation is defined by its primary configuration file. When
``paths.persistent_root`` or ``paths.scratch_root`` is ``auto``, runtime data is
placed with that installation instead of being chosen from a global list of
per-user candidates. This keeps every operator of a shared installation on the
same data, while distribution packages and single-user installations get their
conventional locations from the same rule:

``shared``
    ``<dir>/config.toml`` outside the invoking user's home directory, such as
    ``/opt/lldp-runner``. Data lives in ``<dir>/var`` so the installation root
    itself can stay read-only for operators.
``system``
    ``/etc/lldp-runner/config.toml``. Data lives in ``/var/lib/lldp-runner``.
``user``
    A configuration below the home directory, or no configuration at all. Data
    lives in ``<dir>/var`` (``~/lldp-runner/var`` without a config) and scratch
    uses the per-user ``$XDG_RUNTIME_DIR``.

A shared or user installation created before this layout existed kept
``runs/`` and ``outputs/`` directly in the installation directory. That legacy
layout is still honored while ``<dir>/var`` does not exist.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lldp_runner.defaults import (
    INSTANCE_DATA_DIRNAME,
    SCRATCH_FALLBACK_DIRNAME,
    SHARED_SCRATCH_ROOTS,
    SYSTEM_CONFIG_DIR,
    SYSTEM_PERSISTENT_ROOT,
    SYSTEM_SCRATCH_ROOTS,
    USER_HOME_CONFIG_NAME,
    USER_INSTANCE_DIR,
)


@dataclass(slots=True, frozen=True)
class InstallLayout:
    """Automatic runtime locations for one installation.

    Args:
        name: ``shared``, ``system``, or ``user``.
        persistent_root: Root holding ``runs/`` and ``outputs/``.
        scratch_candidates: Preferred scratch roots, tried in order before the
            ``<persistent_root>/tmp`` fallback.
        create_persistent: Whether automatic resolution may create a missing
            persistent root. Only per-user data is created on demand; shared and
            system roots need ownership and group permissions set by an
            administrator.
        legacy: ``True`` when ``runs/`` or ``outputs/`` still sit directly in the
            installation directory.
    """

    name: str
    persistent_root: Path
    scratch_candidates: tuple[Path, ...]
    create_persistent: bool
    legacy: bool = False

    def scratch_fallback(self, persistent_root: Path) -> Path:
        """Return the last-resort scratch root below ``persistent_root``."""

        return persistent_root / SCRATCH_FALLBACK_DIRNAME


def _home_directory() -> Path | None:
    """Return the invoking user's home, or ``None`` when it cannot contain an install.

    A service account whose home is ``/`` would otherwise make every config path a
    "user" installation.
    """

    try:
        home = Path("~").expanduser()
    except RuntimeError:
        return None
    if not home.is_absolute() or home == Path(home.anchor):
        return None
    # Config paths are resolved, so compare against the resolved home as well.
    return home.resolve()


def _is_legacy_instance(base: Path, data_names: tuple[str, ...]) -> bool:
    """Return whether ``base`` predates the ``var/`` data directory."""

    if (base / INSTANCE_DATA_DIRNAME).exists():
        return False
    return any((base / name).is_dir() for name in data_names)


def select_layout(
    config_path: Path | None,
    *,
    runs_dirname: str = "runs",
    output_dirname: str = "outputs",
    env: Mapping[str, str] | None = None,
) -> InstallLayout:
    """Choose automatic runtime locations from the primary configuration path.

    Args:
        config_path: Resolved primary configuration file, or ``None`` when
            LLDP-Runner runs from built-in defaults.
        runs_dirname: Configured run-state directory name, used to recognize a
            legacy installation.
        output_dirname: Configured output directory name, used the same way.
        env: Environment used for ``XDG_RUNTIME_DIR``; defaults to ``os.environ``.

    Returns:
        The :class:`InstallLayout` for that installation.
    """

    env = os.environ if env is None else env
    home = _home_directory()

    if config_path is not None and config_path.parent == Path(SYSTEM_CONFIG_DIR).resolve():
        return InstallLayout(
            name="system",
            persistent_root=Path(SYSTEM_PERSISTENT_ROOT),
            scratch_candidates=tuple(Path(item) for item in SYSTEM_SCRATCH_ROOTS),
            create_persistent=False,
        )

    if config_path is None or (
        home is not None
        and config_path.parent == home
        and config_path.name == USER_HOME_CONFIG_NAME
    ):
        # Without a usable home directory, keep the historical last resort of
        # the current working directory.
        base = Path(USER_INSTANCE_DIR).expanduser() if home is not None else Path.cwd()
        name = "user"
    else:
        base = config_path.parent
        name = "user" if home is not None and base.is_relative_to(home) else "shared"

    if name == "user":
        runtime_dir = env.get("XDG_RUNTIME_DIR", "")
        scratch = (Path(runtime_dir) / "lldp-runner",) if os.path.isabs(runtime_dir) else ()
    else:
        scratch = tuple(Path(item) for item in SHARED_SCRATCH_ROOTS)

    legacy = _is_legacy_instance(base, (runs_dirname, output_dirname))
    return InstallLayout(
        name=name,
        persistent_root=base if legacy else base / INSTANCE_DATA_DIRNAME,
        scratch_candidates=scratch,
        create_persistent=name == "user",
        legacy=legacy,
    )
