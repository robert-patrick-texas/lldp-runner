"""Shared CSV input parsing for operator-supplied LLDP-Runner data files.

This module owns CSV syntax, physical-line safety limits, header matching, field
selection, and source diagnostics.  Callers remain responsible for domain
semantics such as validating IP addresses, credential strategies, or required
non-blank values.

LLDP-Runner intentionally uses Python's standard-library :mod:`csv` parser and
supports one physical line per CSV record.  Multiline quoted fields are rejected
so source line numbers, comment filtering, and line-length controls stay
predictable for Network Operations.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence


@dataclass(frozen=True, slots=True)
class CsvInputRow:
    """One parsed CSV data record with its original physical source line."""

    line_number: int
    values: dict[str, str]


class CsvInputError(ValueError):
    """Raised when a CSV input violates the shared structural contract."""


def _validate_options(
    *,
    delimiter: str,
    min_fields: int | None,
    max_fields: int | None,
    max_line_length: int,
) -> None:
    """Fail early when caller-supplied parser limits are internally invalid."""

    if len(delimiter) != 1 or delimiter in {"\r", "\n", "\x00"}:
        raise ValueError("CSV delimiter must be one non-newline, non-NUL character")
    if min_fields is not None and min_fields < 0:
        raise ValueError("min_fields must be non-negative")
    if max_fields is not None and max_fields < 0:
        raise ValueError("max_fields must be non-negative")
    if min_fields is not None and max_fields is not None and min_fields > max_fields:
        raise ValueError("min_fields must not exceed max_fields")
    if max_line_length < 1:
        raise ValueError("max_line_length must be at least 1")


def _match_key(value: str, *, case_sensitive: bool) -> str:
    """Return the lookup key used for headers and caller field selectors."""

    return value if case_sensitive else value.casefold()


def _parse_physical_record(
    path: Path,
    line_number: int,
    text: str,
    *,
    delimiter: str,
) -> list[str]:
    """Parse one physical CSV line and reject multiline/invalid CSV syntax."""

    try:
        values = next(csv.reader([text], delimiter=delimiter, strict=True))
    except csv.Error as exc:
        raise CsvInputError(
            f"CSV {path}:{line_number}: invalid CSV record or multiline field "
            f"(multiline fields are not supported): {exc}"
        ) from exc
    # Existing LLDP-Runner CSV consumers have historically trimmed surrounding
    # cell whitespace after CSV parsing.  Keep that predictable behavior in the
    # common layer while leaving blank strings valid for caller semantics.
    return [value.strip() for value in values]


def _check_ascii(path: Path, line_number: int, values: Sequence[str]) -> None:
    """Reject non-ASCII parsed values without lossy transliteration."""

    for index, value in enumerate(values, 1):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CsvInputError(
                f"CSV {path}:{line_number}: field {index} contains non-ASCII input"
            ) from exc


def _apply_field_bounds(
    path: Path,
    line_number: int,
    values: list[str],
    *,
    min_fields: int | None,
    max_fields: int | None,
    error_on_field_bounds: bool,
    drop_extra_fields: bool,
) -> list[str]:
    """Validate/crop absolute parsed field counts before header selection."""

    count = len(values)
    below = min_fields is not None and count < min_fields
    above = max_fields is not None and count > max_fields
    if error_on_field_bounds and (below or above):
        expected: list[str] = []
        if min_fields is not None:
            expected.append(f"minimum {min_fields}")
        if max_fields is not None:
            expected.append(f"maximum {max_fields}")
        raise CsvInputError(
            f"CSV {path}:{line_number}: field count {count} violates "
            + " and ".join(expected)
        )
    if above and drop_extra_fields and max_fields is not None:
        return values[:max_fields]
    return values


def _iter_active_lines(
    path: Path,
    *,
    encoding: str,
    comment_prefixes: Sequence[str],
    max_line_length: int,
    crop_long_lines: bool,
) -> Iterator[tuple[int, str]]:
    """Yield nonblank/noncomment physical lines with bounded reads.

    ``readline`` is deliberately size-limited so the configured line ceiling is
    also a memory-safety boundary for unexpectedly large operator input.  When
    cropping is enabled, any unread remainder of that physical line is consumed
    in bounded chunks before the next source line is considered.
    """

    try:
        handle = path.open("r", encoding=encoding, newline=None)
    except (OSError, UnicodeError) as exc:
        raise CsvInputError(f"unable to open CSV input {path}: {exc}") from exc

    with handle:
        line_number = 0
        try:
            while True:
                raw_line = handle.readline(max_line_length + 2)
                if raw_line == "":
                    break
                line_number += 1

                complete = raw_line.endswith("\n")
                text = raw_line.rstrip("\r\n")
                overlong = len(text) > max_line_length or (
                    not complete and len(raw_line) > max_line_length
                )
                if overlong:
                    if not crop_long_lines:
                        raise CsvInputError(
                            f"CSV {path}:{line_number}: physical line length exceeds "
                            f"maximum {max_line_length}"
                        )
                    text = text[:max_line_length]
                    if not complete:
                        # Discard the rest without materializing an unbounded
                        # physical line in memory.
                        while True:
                            remainder = handle.readline(8192)
                            if remainder == "" or remainder.endswith("\n"):
                                break

                stripped = text.lstrip()
                if not stripped:
                    continue
                if any(stripped.startswith(prefix) for prefix in comment_prefixes):
                    continue
                if "\x00" in text:
                    raise CsvInputError(
                        f"CSV {path}:{line_number}: NUL input is not supported"
                    )
                yield line_number, text
        except UnicodeError as exc:
            raise CsvInputError(f"CSV {path}: invalid {encoding} input: {exc}") from exc


def iter_csv_rows(
    path: Path,
    *,
    fields: Sequence[str] | None = None,
    delimiter: str = ",",
    encoding: str = "utf-8-sig",
    ascii_only: bool = False,
    case_sensitive_headers: bool = False,
    comment_prefixes: Sequence[str] = ("#",),
    min_fields: int | None = None,
    max_fields: int | None = None,
    error_on_field_bounds: bool = False,
    max_line_length: int = 65535,
    crop_long_lines: bool = False,
    drop_extra_fields: bool = True,
    error_on_missing_fields: bool = True,
    error_on_column_mismatch: bool = False,
) -> Iterator[CsvInputRow]:
    """Yield parsed CSV rows using dynamic header-based field positions.

    Header matching is case-insensitive by default.  When ``fields`` is supplied,
    only those fields are returned and dictionary insertion order follows the
    caller's selector order.  Missing selected header fields either raise or
    return as blank strings according to ``error_on_missing_fields``.

    Blank values are always syntactically valid.  With
    ``error_on_column_mismatch=False``, short data rows are padded logically with
    blank values for missing header columns.  Extra parsed columns are discarded
    by default.  Caller-specific semantic validation intentionally lives outside
    this module.
    """

    _validate_options(
        delimiter=delimiter,
        min_fields=min_fields,
        max_fields=max_fields,
        max_line_length=max_line_length,
    )
    if any(not prefix for prefix in comment_prefixes):
        raise ValueError("comment prefixes must not be empty")

    requested = list(fields) if fields is not None else None
    if requested is not None:
        requested_keys = [
            _match_key(name, case_sensitive=case_sensitive_headers) for name in requested
        ]
        if len(set(requested_keys)) != len(requested_keys):
            raise ValueError("requested CSV fields contain duplicates")

    active = _iter_active_lines(
        path,
        encoding=encoding,
        comment_prefixes=comment_prefixes,
        max_line_length=max_line_length,
        crop_long_lines=crop_long_lines,
    )
    try:
        header_line, header_text = next(active)
    except StopIteration:
        if requested and error_on_missing_fields:
            raise CsvInputError(f"CSV {path}: no header record was found")
        return

    header = _parse_physical_record(
        path, header_line, header_text, delimiter=delimiter
    )
    if ascii_only:
        _check_ascii(path, header_line, header)
    header = _apply_field_bounds(
        path,
        header_line,
        header,
        min_fields=min_fields,
        max_fields=max_fields,
        error_on_field_bounds=error_on_field_bounds,
        drop_extra_fields=drop_extra_fields,
    )

    if any(not name for name in header):
        raise CsvInputError(f"CSV {path}:{header_line}: header contains a blank field name")
    header_keys = [
        _match_key(name, case_sensitive=case_sensitive_headers) for name in header
    ]
    if len(set(header_keys)) != len(header_keys):
        seen: set[str] = set()
        duplicates: list[str] = []
        for name, key in zip(header, header_keys, strict=True):
            if key in seen and name not in duplicates:
                duplicates.append(name)
            seen.add(key)
        raise CsvInputError(
            f"CSV {path}:{header_line}: duplicate header field(s): "
            + ", ".join(duplicates)
        )

    header_index = {key: index for index, key in enumerate(header_keys)}
    if requested is None:
        selected: list[tuple[str, int | None]] = [
            (name, index) for index, name in enumerate(header)
        ]
    else:
        selected = []
        missing: list[str] = []
        for name in requested:
            key = _match_key(name, case_sensitive=case_sensitive_headers)
            index = header_index.get(key)
            if index is None:
                missing.append(name)
            selected.append((name, index))
        if missing and error_on_missing_fields:
            raise CsvInputError(
                f"CSV {path}:{header_line}: missing expected header field(s): "
                + ", ".join(missing)
            )

    header_width = len(header)
    for line_number, text in active:
        values = _parse_physical_record(path, line_number, text, delimiter=delimiter)
        if ascii_only:
            _check_ascii(path, line_number, values)
        values = _apply_field_bounds(
            path,
            line_number,
            values,
            min_fields=min_fields,
            max_fields=max_fields,
            error_on_field_bounds=error_on_field_bounds,
            drop_extra_fields=drop_extra_fields,
        )
        parsed_width = len(values)
        if error_on_column_mismatch and parsed_width != header_width:
            raise CsvInputError(
                f"CSV {path}:{line_number}: row has {parsed_width} columns but "
                f"header has {header_width}"
            )

        record: dict[str, str] = {}
        for output_name, index in selected:
            record[output_name] = "" if index is None or index >= len(values) else values[index]
        yield CsvInputRow(line_number=line_number, values=record)


def read_csv_rows(path: Path, **kwargs: Any) -> list[CsvInputRow]:
    """Return :func:`iter_csv_rows` output as a list for small configuration files."""

    return list(iter_csv_rows(path, **kwargs))
