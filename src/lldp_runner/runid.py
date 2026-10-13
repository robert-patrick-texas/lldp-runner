"""Run-ID format validation and stateless counter expansion.

Run IDs are directory names, state identifiers, log context, and output metadata.
Keeping format parsing in one module prevents path creation, resume behavior, and
operator tools from developing subtly different ideas of what constitutes a safe
run identifier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

SAFE_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
COUNTER_TOKEN = "{counter}"
# Deliberately small, documented strftime vocabulary.  %f gives operators a
# high-precision collision-avoidance option while %Z preserves the historic
# default run ID.
_ALLOWED_DIRECTIVES = frozenset("YymdHMSfjZz")


@dataclass(slots=True, frozen=True)
class RunIdTemplate:
    """Compiled view of one configured run-ID format for a specific wall clock.

    Args:
        format_text: Original operator configuration string.
        expanded_template: ``strftime``-expanded text retaining ``{counter}``.
        counter_regex: Regex matching the current timestamp namespace and
            capturing an existing numeric counter, or ``None`` when no counter is
            configured.
    """

    format_text: str
    expanded_template: str
    counter_regex: re.Pattern[str] | None

    @property
    def uses_counter(self) -> bool:
        """Return whether this template contains the LLDP-Runner counter token."""

        return self.counter_regex is not None


def _validate_directives(format_text: str) -> None:
    """Reject unsupported/incomplete strftime directives before path creation."""

    index = 0
    while index < len(format_text):
        if format_text[index] != "%":
            index += 1
            continue
        if index + 1 >= len(format_text):
            raise ValueError("paths.run_id_format ends with an incomplete '%' directive")
        directive = format_text[index + 1]
        if directive not in _ALLOWED_DIRECTIVES:
            raise ValueError(
                "paths.run_id_format contains unsupported strftime directive "
                f"%{directive}; supported directives are %Y %y %m %d %H %M %S "
                "%f %j %Z %z"
            )
        index += 2


def validate_run_id_component(run_id: str, *, label: str = "run ID") -> str:
    """Validate one run identifier as a single portable filesystem component.

    Args:
        run_id: Candidate run identifier.
        label: Operator-facing value name used in diagnostics.

    Returns:
        The unchanged identifier when valid.

    Raises:
        ValueError: If the value is empty, a special directory name, contains a
            path separator/unsafe filename character, or otherwise cannot safely
            be used as one directory component.
    """

    value = str(run_id)
    if not value or value in {".", ".."} or SAFE_RUN_ID_RE.fullmatch(value) is None:
        raise ValueError(
            f"{label} must be one non-empty path component using only "
            "letters, digits, '.', '_', and '-'"
        )
    return value


def validate_run_id_format(format_text: str) -> str:
    """Validate the configurable ``paths.run_id_format`` language.

    Args:
        format_text: Literal safe filename characters, supported ``strftime``
            directives, and optionally one ``{counter}`` token.

    Returns:
        The unchanged format string when structurally valid.

    Raises:
        ValueError: If syntax is unsafe, counter usage is ambiguous, or a
            directive is outside LLDP-Runner's documented subset.
    """

    if not isinstance(format_text, str):
        raise ValueError("paths.run_id_format must be a string")
    text = format_text
    if not text:
        raise ValueError("paths.run_id_format must be a non-empty string")
    if text.count(COUNTER_TOKEN) > 1:
        raise ValueError("paths.run_id_format may contain {counter} at most once")
    remainder = text.replace(COUNTER_TOKEN, "")
    if "{" in remainder or "}" in remainder:
        raise ValueError(
            "paths.run_id_format supports only the optional {counter} placeholder"
        )
    _validate_directives(remainder)
    literal = re.sub(r"%[A-Za-z%]", "", remainder)
    if literal and SAFE_RUN_ID_RE.fullmatch(literal) is None:
        raise ValueError(
            "paths.run_id_format literal text may use only letters, digits, '.', '_', "
            "and '-'"
        )
    return text


def compile_run_id_template(format_text: str, when: datetime) -> RunIdTemplate:
    """Expand timestamp directives while retaining a stateless counter namespace.

    Args:
        format_text: Validated run-ID format string.
        when: Timezone-aware wall clock used for ``strftime`` expansion.

    Returns:
        :class:`RunIdTemplate` for generating a candidate and matching existing
        counters that share the same expanded time/literal namespace.

    Raises:
        ValueError: If formatting produces an unsafe run ID.
    """

    validate_run_id_format(format_text)
    marker = "LLDPRUNNERCOUNTERTOKEN"
    expanded = when.strftime(format_text.replace(COUNTER_TOKEN, marker))
    expanded = expanded.replace(marker, COUNTER_TOKEN)
    sample = expanded.replace(COUNTER_TOKEN, "00")
    validate_run_id_component(sample, label="formatted paths.run_id_format")
    if COUNTER_TOKEN not in expanded:
        return RunIdTemplate(format_text, expanded, None)
    pattern = "^" + re.escape(expanded).replace(re.escape(COUNTER_TOKEN), r"(?P<counter>\d+)") + "$"
    return RunIdTemplate(format_text, expanded, re.compile(pattern))


def next_counter(template: RunIdTemplate, existing_names: Iterable[str]) -> int:
    """Return the next stateless two-digit counter for a compiled namespace.

    Args:
        template: Counter-bearing template from :func:`compile_run_id_template`.
        existing_names: Existing run-associated directory names to inspect.

    Returns:
        Integer counter from 0 through 99.  Rendering always zero-pads to two
        digits so lexical ordering matches numeric ordering inside the namespace.

    Raises:
        ValueError: If the format has no counter or the next value exceeds 99.
    """

    if template.counter_regex is None:
        raise ValueError("run-ID template does not contain {counter}")
    highest = -1
    for name in existing_names:
        match = template.counter_regex.fullmatch(str(name))
        if match is None:
            continue
        highest = max(highest, int(match.group("counter")))
    candidate = highest + 1
    if candidate > 99:
        raise ValueError(
            "run ID counter exhausted: next counter would exceed 99; check configured "
            "values for paths.runs_dirname and paths.run_id_format to prevent "
            "collision; consider using a higher-precision timestamp in "
            "paths.run_id_format"
        )
    return candidate


def render_run_id(template: RunIdTemplate, counter: int | None = None) -> str:
    """Render one safe run ID from a timestamp-expanded template.

    Args:
        template: Compiled format namespace.
        counter: Required value 0..99 when ``{counter}`` is present; omitted for a
            timestamp/literal-only format.

    Returns:
        Safe run-ID directory component.

    Raises:
        ValueError: If counter presence/range is inconsistent with the template.
    """

    if template.uses_counter:
        if counter is None or not 0 <= counter <= 99:
            raise ValueError("run ID counter must be between 00 and 99")
        value = template.expanded_template.replace(COUNTER_TOKEN, f"{counter:02d}")
    else:
        if counter is not None:
            raise ValueError("counter supplied for run-ID format without {counter}")
        value = template.expanded_template
    return validate_run_id_component(value)
