"""Shared terminal-neighbor table width planning regressions."""

from lldp_runner.neighbor_table import format_neighbor_row, plan_neighbor_widths


def test_interface_columns_expand_from_configured_baselines() -> None:
    """Long interface values consume spare width before they are truncated."""

    widths = plan_neighbor_widths(
        120,
        configured_local=18,
        configured_remote_port=18,
        local_values=["Gi1/0/1"],
        remote_port_values=["Port-Identifier-Longer-Than-Eighteen"],
    )

    assert widths.local == 18
    assert widths.remote_port == 36
    assert widths.neighbor >= 18
    assert widths.line_width <= 120


def test_dynamic_growth_preserves_neighbor_readability() -> None:
    """Competing long interface values never consume the Neighbor minimum."""

    widths = plan_neighbor_widths(
        120,
        configured_local=18,
        configured_remote_port=18,
        local_values=["L" * 50],
        remote_port_values=["R" * 50],
    )

    assert widths.local > 18
    assert widths.remote_port > 18
    assert widths.neighbor == 18
    assert widths.line_width == 120


def test_ipv6_management_address_is_never_cropped_even_on_narrow_terminal() -> None:
    """The Mgmt field may widen past the terminal budget to retain full IPv6 text."""

    address = "2001:db8:8000:da02:1234:5678:9abc:def0"
    widths = plan_neighbor_widths(
        72,
        configured_local=18,
        configured_remote_port=18,
        management_values=[address],
    )
    row = format_neighbor_row(
        widths,
        local="Gi1/0/1",
        protocol="lldp",
        neighbor="workstation.example",
        remote_port="00:11:22:33:44:55",
        management=address,
    )

    assert widths.management == len(address)
    assert widths.line_width > 72
    assert row.endswith(address)
    assert "…" not in row[-widths.management :]
