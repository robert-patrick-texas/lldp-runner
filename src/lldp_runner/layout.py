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
    lives in ``<dir>/var``, where a file directly in the home directory (or no
    file) uses ``~/lldp-runner``, and scratch uses the per-user
    ``$XDG_RUNTIME_DIR``.

The layout follows the configuration path as the operator or launcher named it.
Symbolic links are not resolved, so a ``config.toml`` that links to a file kept
elsewhere still belongs to the installation directory that holds the link.

Every installation other than the default one for its layout gets its own
scratch name, such as ``/dev/shm/lldp-runner-srv-lab`` for
``/srv/lab/config.toml``, so two installations on one host never share a
``current`` run or scoreboard.

A shared or user installation created before this layout existed kept
``runs/`` and ``outputs/`` directly in the installation directory. That legacy
layout is still honored while ``<dir>/var`` does not exist. History that the
selected layout does not use is reported so operators can move it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lldp_runner.defaults import (
    INSTANCE_DATA_DIRNAME,
    SCRATCH_FALLBACK_DIRNAME,
    SHARED_DEFAULT_INSTANCE_DIR,
    SHARED_SCRATCH_BASES,
    SYSTEM_CONFIG_DIR,
    SYSTEM_PERSISTENT_ROOT,
    SYSTEM_SCRATCH_ROOTS,
    USER_INSTANCE_DIR,
)

_SCRATCH_NAME_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)


@dataclass(slots=True, frozen=True)
class InstallLayout:
    """Automatic runtime locations for one installation.

    Args:
        name: ``shared``, ``system``, or ``user``.
        persistent_root: Root holding ``runs/`` and ``outputs/``, or ``None``
            when no automatic location exists (see ``unavailable``).
        scratch_candidates: Preferred scratch roots, tried in order before the
            ``<persistent_root>/tmp`` fallback.
        create_persistent: Whether automatic resolution may create a missing
            persistent root. Only per-user data is created on demand; shared and
            system roots need ownership and group permissions set by an
            administrator.
        legacy: ``True`` when ``runs/`` or ``outputs/`` still sit directly in the
            installation directory and are used as the persistent root.
        unused_history: Older ``runs/``/``outputs/`` directories that this layout
            does not use.
        unavailable: Why no automatic persistent root exists, when it does not.
    """

    name: str
    persistent_root: Path | None
    scratch_candidates: tuple[Path, ...]
    create_persistent: bool
    legacy: bool = False
    unused_history: tuple[Path, ...] = ()
    unavailable: str = ""

    def scratch_fallback(self, persistent_root: Path) -> Path:
        """Return the last-resort scratch root below ``persistent_root``."""

        return persistent_root / SCRATCH_FALLBACK_DIRNAME


def scratch_name(base: Path, *, default: Path, relative_to: Path) -> str:
    """Return the scratch directory name for the installation in ``base``.

    The ``default`` installation for a layout keeps the plain ``lldp-runner``
    name. Any other installation appends its path below ``relative_to`` (the
    filesystem root for shared installations, the home directory for per-user
    ones), with ``/`` replaced by ``-`` and every other byte outside
    ``[A-Za-z0-9._-]`` replaced by ``_``: ``/srv/lab`` becomes
    ``lldp-runner-srv-lab``. ``scripts/shared-setup.sh`` and
    ``scripts/svc-setup.sh`` implement the same rule in Bash.
    """

    if base == default:
        return "lldp-runner"
    raw = os.fsencode("-".join(base.relative_to(relative_to).parts))
    return "lldp-runner-" + "".join(
        chr(byte) if byte in _SCRATCH_NAME_BYTES else "_" for byte in raw
    )


def _home_directories() -> tuple[Path, ...]:
    """Return the invoking user's home as written and resolved.

    Nothing is returned when the home directory cannot hold an installation. A
    service account whose home is ``/`` would otherwise make every config path a
    "user" installation.
    """

    try:
        home = Path("~").expanduser()
    except RuntimeError:
        return ()
    if not home.is_absolute() or home == Path(home.anchor):
        return ()
    home = Path(os.path.normpath(home))
    resolved = home.resolve()
    return (home,) if resolved == home else (home, resolved)


def _real_directories(base: Path, names: tuple[str, ...]) -> tuple[Path, ...]:
    """Return ``base/<name>`` entries that are real directories, not symlinks."""

    found: list[Path] = []
    for name in names:
        path = base / name
        if path.is_dir() and not path.is_symlink():
            found.append(path)
    return tuple(found)


def select_layout(
    config_location: Path | None,
    *,
    runs_dirname: str = "runs",
    output_dirname: str = "outputs",
    env: Mapping[str, str] | None = None,
) -> InstallLayout:
    """Choose automatic runtime locations from the primary configuration path.

    Args:
        config_location: Absolute path of the primary configuration file as it
            was named, without resolving symbolic links, or ``None`` when
            LLDP-Runner runs from built-in defaults.
        runs_dirname: Configured run-state directory name, used to recognize
            legacy history.
        output_dirname: Configured output directory name, used the same way.
        env: Environment used for ``XDG_RUNTIME_DIR``; defaults to ``os.environ``.

    Returns:
        The :class:`InstallLayout` for that installation.
    """

    env = os.environ if env is None else env
    data_names = (runs_dirname, output_dirname)
    location = None if config_location is None else Path(os.path.normpath(config_location))

    if location is not None and location.parent == Path(SYSTEM_CONFIG_DIR):
        return InstallLayout(
            name="system",
            persistent_root=Path(SYSTEM_PERSISTENT_ROOT),
            scratch_candidates=tuple(Path(item) for item in SYSTEM_SCRATCH_ROOTS),
            create_persistent=False,
        )

    homes = _home_directories()
    in_home = location is not None and any(location.is_relative_to(home) for home in homes)
    user_base = Path(os.path.normpath(Path(USER_INSTANCE_DIR).expanduser())) if homes else None

    if location is None or (in_home and location.parent in homes):
        # No file, or a file directly in the home directory: never use $HOME
        # itself as the installation directory.
        if user_base is None:
            return InstallLayout(
                name="user",
                persistent_root=None,
                scratch_candidates=(),
                create_persistent=False,
                unavailable=(
                    "no configuration file was found and the home directory cannot "
                    "hold LLDP-Runner data; use --config or set paths.persistent_root"
                ),
            )
        base = user_base
        name = "user"
    else:
        base = location.parent
        name = "user" if in_home else "shared"

    if name == "user":
        assert user_base is not None
        runtime_dir = env.get("XDG_RUNTIME_DIR", "")
        name_in_runtime = scratch_name(base, default=user_base, relative_to=user_base.parent)
        scratch = (Path(runtime_dir) / name_in_runtime,) if os.path.isabs(runtime_dir) else ()
    else:
        shared_name = scratch_name(
            base, default=Path(SHARED_DEFAULT_INSTANCE_DIR), relative_to=Path(base.anchor)
        )
        scratch = tuple(Path(item) / shared_name for item in SHARED_SCRATCH_BASES)

    data_dir = base / INSTANCE_DATA_DIRNAME
    history = _real_directories(base, data_names)
    legacy = bool(history) and not data_dir.exists()
    unused = () if legacy else history
    if name == "user" and user_base is not None and base != user_base:
        # The previous automatic rule always preferred ~/lldp-runner.
        unused += _real_directories(user_base, data_names)

    return InstallLayout(
        name=name,
        persistent_root=base if legacy else data_dir,
        scratch_candidates=scratch,
        create_persistent=name == "user",
        legacy=legacy,
        unused_history=unused,
    )
