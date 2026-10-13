"""Shared ANSI terminal styling for LLDP-Runner human-readable output.

The two neighbor-oriented commands deliberately share one semantic palette so
operators can tune terminal colors without each renderer inventing its own
setting names.  Machine-readable CSV/JSON renderers never call this module.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any

from lldp_runner.config import TerminalConfig
from lldp_runner.defaults import TERMINAL_COLOR_NAMES

RESET = "\x1b[0m"
BOLD = "\x1b[1m"

_COLOR_CODES = {
    "black": "\x1b[30m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "default": "\x1b[39m",
    "none": "",
}
assert set(_COLOR_CODES) == set(TERMINAL_COLOR_NAMES)


@dataclass(frozen=True, slots=True)
class TerminalStyles:
    """Resolved ANSI prefixes for LLDP-Runner semantic terminal roles."""

    heading: str
    success: str
    warning: str
    error: str
    learned: str
    observed_by: str
    inspection_neighbor: str
    metric: str
    bold: str = BOLD


def use_color(stream: Any = sys.stdout, config: TerminalConfig | None = None) -> bool:
    """Return whether terminal styling should be emitted for one output stream.

    ``terminal.color=never`` and the conventional ``NO_COLOR`` environment
    variable are authoritative. Otherwise styling is limited to interactive TTYs.
    """

    if config is not None and config.color == "never":
        return False
    return bool(getattr(stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ


def color_code(name: str) -> str:
    """Return the ANSI foreground sequence for one validated color name."""

    return _COLOR_CODES[name.casefold()]


def build_terminal_styles(config: TerminalConfig) -> TerminalStyles:
    """Build semantic ANSI prefixes from the effective terminal configuration."""

    return TerminalStyles(
        heading=BOLD + color_code(config.heading_color),
        success=color_code(config.success_color),
        warning=color_code(config.warning_color),
        error=color_code(config.error_color),
        learned=BOLD + color_code(config.learned_color),
        observed_by=BOLD + color_code(config.observed_by_color),
        inspection_neighbor=color_code(config.inspection_neighbor_color),
        metric=BOLD + color_code(config.metric_color),
    )


def paint(text: str, style: str, enabled: bool) -> str:
    """Wrap visible text in one ANSI style when color output is enabled."""

    if not enabled or not style:
        return text
    return f"{style}{text}{RESET}"


def format_title_line(
    title: str,
    suffix: str,
    *,
    width: int,
    title_style: str,
    color: bool,
) -> str:
    """Render a styled title with an unstyled suffix right-aligned by visible width.

    ANSI bytes are inserted only after the spacing is calculated so enabling
    color never changes where the timestamp suffix appears on screen.
    """

    visible_width = max(1, int(width))
    gap = max(1, visible_width - len(title) - len(suffix))
    return f"{paint(title, title_style, color)}{' ' * gap}{suffix}"
