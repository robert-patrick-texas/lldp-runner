"""Shared column planning and formatting for neighbor terminal tables.

Both ``get-neighbors`` and ``show-neighbors`` present the same five operator
columns.  Keeping the width policy here prevents the two commands from drifting
when interface names are longer than the configured baseline widths.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import Callable, Iterable


PROTOCOL_WIDTH = 10
MANAGEMENT_MIN_WIDTH = 18
NEIGHBOR_MIN_WIDTH = 18
NEIGHBOR_MAX_WIDTH = 42
TABLE_MAX_WIDTH = 120
DYNAMIC_INTERFACE_MAX_WIDTH = 36
COLUMN_SEPARATORS = 4


@dataclass(frozen=True, slots=True)
class NeighborTableWidths:
    """Visible column widths for the shared five-column neighbor table."""

    table: int
    local: int
    protocol: int
    neighbor: int
    remote_port: int
    management: int

    @property
    def line_width(self) -> int:
        """Return the visible width of a fully padded table row."""

        return (
            self.local
            + self.protocol
            + self.neighbor
            + self.remote_port
            + self.management
            + COLUMN_SEPARATORS
        )


def _desired_interface_width(configured: int, values: Iterable[str]) -> int:
    """Return a bounded content-aware width at or above the configured baseline."""

    longest = max((len(value) for value in values if value), default=0)
    return max(configured, min(longest, DYNAMIC_INTERFACE_MAX_WIDTH))


def _desired_management_width(values: Iterable[str]) -> int:
    """Return a width that preserves every valid IPv6 address in full.

    IPv4 values already fit inside the historical 18-column management field.
    Only syntactically valid IPv6 text expands the column, preventing an
    unrelated malformed or diagnostic value from consuming the rest of the
    table. The original text length is retained so a scoped address, when one is
    supplied by a caller, is not shortened after validation.
    """

    longest_ipv6 = 0
    for value in values:
        text = str(value).strip()
        if not text or text == "-":
            continue
        candidate = text
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        # ``ipaddress`` accepts scoped IPv6 on supported Python releases. Strip
        # only for validation fallback while preserving the displayed scope.
        validation_candidates = (candidate, candidate.split("%", 1)[0])
        parsed = None
        for validation_text in validation_candidates:
            try:
                parsed = ip_address(validation_text)
                break
            except ValueError:
                continue
        if isinstance(parsed, IPv6Address):
            longest_ipv6 = max(longest_ipv6, len(text))
    return max(MANAGEMENT_MIN_WIDTH, longest_ipv6)


def _allocate_growth(local_need: int, remote_need: int, budget: int) -> tuple[int, int]:
    """Split available expansion fairly between Local and Remote Port columns.

    Allocation proceeds one visible column at a time so neither interface column
    consumes all remaining terminal space while the other still has content that
    would benefit from expansion.  The loop is bounded by the 36-column dynamic
    cap, making the behavior deterministic and trivial relative to rendering.
    """

    local_extra = 0
    remote_extra = 0
    while budget > 0 and (local_extra < local_need or remote_extra < remote_need):
        local_remaining = local_need - local_extra
        remote_remaining = remote_need - remote_extra
        if local_remaining >= remote_remaining and local_remaining > 0:
            local_extra += 1
        elif remote_remaining > 0:
            remote_extra += 1
        elif local_remaining > 0:
            local_extra += 1
        budget -= 1
    return local_extra, remote_extra


def plan_neighbor_widths(
    terminal_width: int,
    *,
    configured_local: int,
    configured_remote_port: int,
    local_values: Iterable[str] = (),
    remote_port_values: Iterable[str] = (),
    management_values: Iterable[str] = (),
) -> NeighborTableWidths:
    """Plan shared table widths with bounded content-aware interface expansion.

    ``configured_local`` and ``configured_remote_port`` are baseline widths and
    are never reduced. When the terminal has room, each can grow toward the
    longest value, capped at 36 columns. The management field expands to the
    longest valid IPv6 address and is never shortened below that requirement.
    Expansion first preserves an 18-column Neighbor field; whatever terminal
    budget remains then grows Neighbor up to 42 columns. This keeps long
    interface identifiers visible without cropping the address operators use to
    reach the remote system.
    """

    base_terminal_budget = max(72, min(int(terminal_width), TABLE_MAX_WIDTH))
    management_width = _desired_management_width(management_values)
    fixed_without_interfaces = (
        PROTOCOL_WIDTH + management_width + NEIGHBOR_MIN_WIDTH + COLUMN_SEPARATORS
    )
    minimum_line = configured_local + configured_remote_port + fixed_without_interfaces
    # An IPv6 management address is more useful than a nominal terminal-width
    # cap. If the minimum readable table is wider than the detected terminal,
    # emit that wider line rather than replacing part of the address with an
    # ellipsis. Operators can scroll/copy the complete plain-text row.
    terminal_budget = max(base_terminal_budget, minimum_line)
    growth_budget = max(0, terminal_budget - minimum_line)

    desired_local = _desired_interface_width(configured_local, local_values)
    desired_remote = _desired_interface_width(configured_remote_port, remote_port_values)
    local_need = max(0, desired_local - configured_local)
    remote_need = max(0, desired_remote - configured_remote_port)
    local_extra, remote_extra = _allocate_growth(local_need, remote_need, growth_budget)

    local_width = configured_local + local_extra
    remote_width = configured_remote_port + remote_extra
    used_without_neighbor = (
        local_width
        + PROTOCOL_WIDTH
        + remote_width
        + management_width
        + COLUMN_SEPARATORS
    )
    remaining = terminal_budget - used_without_neighbor
    neighbor_width = max(NEIGHBOR_MIN_WIDTH, min(NEIGHBOR_MAX_WIDTH, remaining))
    line_width = used_without_neighbor + neighbor_width

    return NeighborTableWidths(
        table=max(line_width, terminal_budget),
        local=local_width,
        protocol=PROTOCOL_WIDTH,
        neighbor=neighbor_width,
        remote_port=remote_width,
        management=management_width,
    )


def _fit(value: str, width: int) -> str:
    """Truncate one already-sanitized cell to a visible width."""

    if width <= 1:
        return value[:width]
    return value if len(value) <= width else value[: width - 1] + "…"


def format_neighbor_header(widths: NeighborTableWidths) -> str:
    """Return the shared whitespace-padded five-column neighbor header."""

    return (
        f"{'Local':<{widths.local}} {'Protocol':<{widths.protocol}} "
        f"{'Neighbor':<{widths.neighbor}} {'Remote Port':<{widths.remote_port}} "
        f"{'Mgmt':<{widths.management}}"
    )


def format_neighbor_row(
    widths: NeighborTableWidths,
    *,
    local: str,
    protocol: str,
    neighbor: str,
    remote_port: str,
    management: str,
    protocol_style: Callable[[str], str] | None = None,
) -> str:
    """Return one aligned row, optionally styling the already-padded protocol cell."""

    local_cell = _fit(local, widths.local)
    protocol_cell = f"{_fit(protocol, widths.protocol):<{widths.protocol}}"
    neighbor_cell = _fit(neighbor, widths.neighbor)
    remote_cell = _fit(remote_port, widths.remote_port)
    management_cell = _fit(management, widths.management)
    if protocol_style is not None:
        protocol_cell = protocol_style(protocol_cell)
    return (
        f"{local_cell:<{widths.local}} {protocol_cell} "
        f"{neighbor_cell:<{widths.neighbor}} {remote_cell:<{widths.remote_port}} "
        f"{management_cell:<{widths.management}}"
    )
