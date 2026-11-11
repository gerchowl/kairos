"""Shared date/time validation for every slot-writing surface.

Issue #70 / PR #92 round-2 finding 4: the REST API models, MCP (which uses the
same models), the web owner form, the web /new path, and the capability
console's `_parse_dates` must all refuse the same inputs, and name the field
and the rule rather than echoing the submitted value (finding 5). This module
is that single source of truth, so the four call sites cannot drift and a
regression test can pin each predicate once.

The predicates refuse what a `DATE` / `TIME` column would raise on at next
read -- the previous versions accepted them on the way in (so the row was
written) and raised a 500 on the next ordinary page view. See
`tests/test_api.py::test_finding_4_slot_date_and_time_are_validated_at_the_model`
and the capability-console counterparts.

Why regex *and* `fromisoformat`:

  * Python's `date.fromisoformat` accepts the ISO-8601 extended forms but is
    lax about zero-padding on some runtimes and strict on others; it also
    accepts strings like `"2026-01-05T12:00"` on recent Pythons. Front-stop
    with a tight regex so the shape is exact (`YYYY-MM-DD`), then let
    `fromisoformat` check the arithmetic (February 30th, month 13, ...).
  * `time.fromisoformat` accepts `HH:MM` and `HH:MM:SS`; MySQL `TIME` columns
    round-trip as `HH:MM:SS` so we must accept that shape and normalise to
    `HH:MM` for the rest of the app (which compares strings). The previous
    round refused `"09:00:00"` and broke tests pinning that round-trip.
  * Both predicates cap the input length so an oversized string cannot cost
    a regex walk. The cap is generous (32 chars) rather than tight -- the
    goal is "no 10 MB input", not an exact length guard.

`InvalidDate` / `InvalidTime` are plain `ValueError` subclasses so Pydantic
`field_validator`s and plain Python `try/except` both see them. Messages
*name the field and the rule* -- they never include the submitted value in
full. A short (<= 40-char) excerpt is included only when it is obviously a
format mistake the reader needs to see, and even then it is bounded by
`_excerpt()` so a 1 MB echo cannot leave.
"""

from __future__ import annotations

import logging
import re
from datetime import date as _date
from datetime import time as _time

log = logging.getLogger("kairos.validation")

# Shape guards: tight, zero-padded, no T-separator, no microseconds. The arithmetic
# check (`fromisoformat`) comes after and refuses "2026-02-30" etc.
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Accept HH:MM or HH:MM:SS so a MySQL TIME round-trip (which carries seconds)
# is not refused by the input layer it has already round-tripped through.
_TIME_RE = re.compile(r"^\d{2}:\d{2}(:\d{2})?$")

# Ceiling on the input string before any pattern work -- the regex is linear
# in its input, so a 1 MB string would walk it. 32 characters comfortably
# covers both shapes.
_MAX_INPUT_LEN = 32

# Ceiling on any echo in a refusal message (finding 5): a 1 MB bad input must
# never produce a 1 MB refusal.
_EXCERPT_LEN = 40


class InvalidDate(ValueError):
    """Raised by `validate_date` for anything a DATE column could not store."""


class InvalidTime(ValueError):
    """Raised by `validate_time` for anything a TIME column could not store."""


def _excerpt(s: object) -> str:
    """A bounded printable excerpt, never more than `_EXCERPT_LEN` chars.

    Non-strings render as their type name rather than `repr` so a huge
    `dict` or `list` cannot leak through the "short excerpt" exception.
    """
    if not isinstance(s, str):
        return f"<{type(s).__name__}>"
    if len(s) > _EXCERPT_LEN:
        return s[:_EXCERPT_LEN] + "..."
    return s


def validate_date(value: object, *, field: str = "date") -> str:
    """Refuse anything a `DATE` column could not store; return the string unchanged.

    `field` names the refused field in the message -- "date", "dates[3]", etc.
    The message never includes `value!r` (finding 5); at most it carries a
    truncated excerpt via `_excerpt`.
    """
    if not isinstance(value, str):
        raise InvalidDate(f"{field} must be a YYYY-MM-DD string")
    if len(value) > _MAX_INPUT_LEN:
        raise InvalidDate(
            f"{field} must be YYYY-MM-DD (got a {len(value)}-char string)"
        )
    if not _DATE_RE.fullmatch(value):
        raise InvalidDate(
            f"{field} must be YYYY-MM-DD (got {_excerpt(value)!r})"
        )
    try:
        _date.fromisoformat(value)
    except ValueError:
        raise InvalidDate(
            f"{field} must be a real calendar date in YYYY-MM-DD "
            f"(got {_excerpt(value)!r})"
        ) from None
    return value


def validate_time(value: object, *, field: str = "time") -> str:
    """Refuse anything a `TIME` column could not store; return it as HH:MM.

    Accepts `HH:MM` and `HH:MM:SS` so MySQL's `TIME` round-trip (which
    carries seconds) is not refused by the input layer it has already
    round-tripped through -- this was the regression round-1 of PR #92
    produced by refusing `HH:MM:SS`. The normalisation to `HH:MM` keeps
    string comparisons elsewhere in the app unchanged.
    """
    if not isinstance(value, str):
        raise InvalidTime(f"{field} must be an HH:MM string")
    if len(value) > _MAX_INPUT_LEN:
        raise InvalidTime(
            f"{field} must be HH:MM (got a {len(value)}-char string)"
        )
    if not _TIME_RE.fullmatch(value):
        raise InvalidTime(
            f"{field} must be HH:MM (got {_excerpt(value)!r})"
        )
    try:
        t = _time.fromisoformat(value)
    except ValueError:
        raise InvalidTime(
            f"{field} must be a real clock time in HH:MM "
            f"(got {_excerpt(value)!r})"
        ) from None
    return f"{t.hour:02d}:{t.minute:02d}"


def validate_time_ordering(start: str, end: str, *, field: str = "time") -> None:
    """Refuse `end <= start` in a time_slot. Both must be valid HH:MM strings.

    Caller is expected to have run `validate_time` on both already -- this
    checks only the ordering, so `start` and `end` are trusted to be `HH:MM`.
    """
    s = _time.fromisoformat(start)
    e = _time.fromisoformat(end)
    if e <= s:
        raise InvalidTime(f"{field}: end must be after start")


# -- Read-path robustness -------------------------------------------------
#
# Existing live-instance data may hold a malformed stored date on a slot --
# the pre-fix write path accepted it and the next read raised. Make the
# read path *skip* the row rather than 500 the page. Logged once per poll
# so the operator sees it but the log does not fill if every view hits it.
#
# Not the inverse of the write validators (which refuse at input): this is
# "the write validator was not here when this row was stored, cope". New
# writes cannot produce bad rows, so the skip is only a migration aid.


_logged_bad_slots: set[str] = set()


def slot_is_readable(slot: dict) -> bool:
    """True if `slot["date"]` (and times, when present) survive their format.

    Returns False for a stored row that would raise on the next read. On the
    first False per (poll_id, slot_id) pair the shape is logged once so an
    operator can migrate the row, then suppressed to keep the log quiet on a
    view that re-renders the same poll.
    """
    try:
        d = slot.get("date")
        if d is None:
            return False
        # DATE columns on both dialects return a `date`; a string here means
        # a row that bypassed the converter (an older row, or a test fixture).
        if isinstance(d, _date):
            pass
        else:
            validate_date(str(d))
        for key in ("start_time", "end_time"):
            v = slot.get(key)
            if v is None:
                continue
            # TIME columns return `timedelta` or `time` on MySQL and
            # `str` on SQLite; a `timedelta` is already-parsed.
            if hasattr(v, "total_seconds") or isinstance(v, _time):
                continue
            validate_time(str(v))
        return True
    except (InvalidDate, InvalidTime) as exc:
        key = f"{slot.get('poll_id', '?')}:{slot.get('id', '?')}"
        if key not in _logged_bad_slots:
            _logged_bad_slots.add(key)
            log.warning(
                "skipping unreadable slot %s (will not be shown or returned): %s",
                key, exc,
            )
        return False
