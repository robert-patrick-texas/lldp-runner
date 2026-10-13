"""Regression tests for the shared dynamic-position CSV input reader."""

from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.csv_input import CsvInputError, read_csv_rows


def test_reordered_case_insensitive_selectors_comments_and_quotes(tmp_path: Path) -> None:
    path = tmp_path / "input.csv"
    path.write_text(
        "# comment\n\n"
        " Notes , IPV4 , Preferred_Name , extra\n"
        '"has, comma", 198.18.0.1 , Switch1.Example , ignored\n',
        encoding="utf-8",
    )

    rows = read_csv_rows(
        path,
        fields=["preferred_name", "ipv4", "notes"],
    )

    assert len(rows) == 1
    assert rows[0].line_number == 4
    assert list(rows[0].values) == ["preferred_name", "ipv4", "notes"]
    assert rows[0].values == {
        "preferred_name": "Switch1.Example",
        "ipv4": "198.18.0.1",
        "notes": "has, comma",
    }


def test_case_sensitive_header_matching_is_optional(tmp_path: Path) -> None:
    path = tmp_path / "case.csv"
    path.write_text("Name,IPv4\nswitch1,198.18.0.1\n", encoding="utf-8")

    rows = read_csv_rows(path, fields=["name", "ipv4"])
    assert rows[0].values == {"name": "switch1", "ipv4": "198.18.0.1"}

    with pytest.raises(CsvInputError, match="missing expected header field"):
        read_csv_rows(
            path,
            fields=["name", "ipv4"],
            case_sensitive_headers=True,
        )


def test_blank_and_duplicate_headers_are_rejected(tmp_path: Path) -> None:
    blank = tmp_path / "blank.csv"
    blank.write_text("name,,ipv4\na,,1\n", encoding="utf-8")
    with pytest.raises(CsvInputError, match="blank field name"):
        read_csv_rows(blank)

    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text("name,ipv4,NAME\na,1,b\n", encoding="utf-8")
    with pytest.raises(CsvInputError, match="duplicate header"):
        read_csv_rows(duplicate)

    rows = read_csv_rows(duplicate, case_sensitive_headers=True)
    assert rows[0].values == {"name": "a", "ipv4": "1", "NAME": "b"}


def test_short_rows_return_blank_values_unless_mismatch_is_strict(tmp_path: Path) -> None:
    path = tmp_path / "short.csv"
    path.write_text("name,ipv4,notes\nswitch1,198.18.0.1\n", encoding="utf-8")

    rows = read_csv_rows(path, fields=["name", "ipv4", "notes"])
    assert rows[0].values["notes"] == ""

    with pytest.raises(CsvInputError, match="row has 2 columns but header has 3"):
        read_csv_rows(path, error_on_column_mismatch=True)


def test_missing_selected_header_can_be_returned_as_blank(tmp_path: Path) -> None:
    path = tmp_path / "missing.csv"
    path.write_text("name\nswitch1\n", encoding="utf-8")

    rows = read_csv_rows(
        path,
        fields=["name", "ipv4"],
        error_on_missing_fields=False,
    )
    assert rows[0].values == {"name": "switch1", "ipv4": ""}


def test_field_bounds_can_error_or_silently_crop(tmp_path: Path) -> None:
    path = tmp_path / "bounds.csv"
    path.write_text("a,b,c\n1,2,3\n", encoding="utf-8")

    rows = read_csv_rows(path, max_fields=2, drop_extra_fields=True)
    assert rows[0].values == {"a": "1", "b": "2"}

    with pytest.raises(CsvInputError, match="field count 3 violates maximum 2"):
        read_csv_rows(
            path,
            max_fields=2,
            error_on_field_bounds=True,
        )

    too_short = tmp_path / "too-short.csv"
    too_short.write_text("a,b\n1\n", encoding="utf-8")
    with pytest.raises(CsvInputError, match="field count 1 violates minimum 2"):
        read_csv_rows(
            too_short,
            min_fields=2,
            error_on_field_bounds=True,
        )


def test_physical_line_limit_can_error_or_crop(tmp_path: Path) -> None:
    path = tmp_path / "length.csv"
    path.write_text("a,b,c\n1,2,3,discarded\n", encoding="utf-8")

    with pytest.raises(CsvInputError, match="physical line length"):
        read_csv_rows(path, max_line_length=5)

    rows = read_csv_rows(path, max_line_length=5, crop_long_lines=True)
    assert rows[0].values == {"a": "1", "b": "2", "c": "3"}


def test_multiline_fields_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "multiline.csv"
    path.write_text('name,notes\nswitch1,"line one\nline two"\n', encoding="utf-8")

    with pytest.raises(CsvInputError, match="multiline fields are not supported"):
        read_csv_rows(path)


def test_ascii_only_rejects_non_ascii_without_transliteration(tmp_path: Path) -> None:
    path = tmp_path / "unicode.csv"
    path.write_text("name\nJosé\n", encoding="utf-8")

    assert read_csv_rows(path)[0].values["name"] == "José"
    with pytest.raises(CsvInputError, match="contains non-ASCII input"):
        read_csv_rows(path, ascii_only=True)


def test_single_character_delimiter_and_standard_csv_escaping(tmp_path: Path) -> None:
    path = tmp_path / "semicolon.csv"
    path.write_text('name;notes\nswitch1;"He said ""hello"""\n', encoding="utf-8")

    rows = read_csv_rows(path, delimiter=";")
    assert rows[0].values == {"name": "switch1", "notes": 'He said "hello"'}

    with pytest.raises(ValueError, match="delimiter must be one"):
        read_csv_rows(path, delimiter="||")


def test_extra_columns_are_discarded_by_header_and_selector(tmp_path: Path) -> None:
    path = tmp_path / "extra.csv"
    path.write_text("name,ipv4\nswitch1,198.18.0.1,ignored,also ignored\n", encoding="utf-8")

    rows = read_csv_rows(path, fields=["ipv4"])
    assert rows[0].values == {"ipv4": "198.18.0.1"}
