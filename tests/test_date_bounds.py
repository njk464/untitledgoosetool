"""Tests for the shared date-bound resolution rule (DEC-DATEBOUNDS-001).

Rule under test: explicit date_end=YYYY-MM-DD is an exclusive UTC midnight; a blank
date_end is an aware-UTC snapshot of "now" (injected here so time is frozen).
"""

import configparser
from datetime import datetime, timedelta, timezone

import pytest

from goosey.utils import (
    get_date_range, iter_day_chunks, parse_graph_ts, resolve_date_bounds,
    resume_point, to_date_str, to_graph_ts,
)

NOW = datetime(2026, 11, 2, 13, 15, 22, 123456, tzinfo=timezone.utc)


def conf(start="", end=""):
    c = configparser.ConfigParser()
    c.add_section("filters")
    c.set("filters", "date_start", start)
    c.set("filters", "date_end", end)
    return c


def test_blank_end_is_frozen_now_not_midnight():
    b = resolve_date_bounds(conf("2026-11-02", ""), now=NOW)
    assert b.end == NOW and b.end_is_now
    assert b.end.tzinfo is not None and b.end.utcoffset() == timedelta(0)
    assert b.end.time() != datetime.min.time()
    assert b.start == datetime(2026, 11, 2, tzinfo=timezone.utc)
    assert to_graph_ts(b.end) == "2026-11-02T13:15:22.123456Z"


def test_blank_end_converts_non_utc_now_to_utc():
    tz = timezone(timedelta(hours=-5))
    b = resolve_date_bounds(conf("2026-11-01", ""), now=datetime(2026, 11, 2, 8, 15, tzinfo=tz))
    assert b.end == datetime(2026, 11, 2, 13, 15, tzinfo=timezone.utc)
    assert b.end.utcoffset() == timedelta(0)


def test_naive_now_rejected():
    with pytest.raises(ValueError):
        resolve_date_bounds(conf("2026-11-02", ""), now=datetime(2026, 11, 2, 13, 0))


def test_explicit_end_is_exclusive_utc_midnight():
    b = resolve_date_bounds(conf("2026-10-30", "2026-11-02"), now=NOW)
    assert b.end == datetime(2026, 11, 2, tzinfo=timezone.utc)
    assert not b.end_is_now
    assert to_graph_ts(b.end) == "2026-11-02T00:00:00.000000Z"


def test_no_date_start_means_no_range_and_end_is_now():
    b = resolve_date_bounds(conf("", ""), now=NOW)
    assert not b.has_range and b.start is None
    assert b.end == NOW and b.end_is_now
    assert b.legacy_tuple() == (False, False, False)


def test_legacy_get_date_range_uses_utc_date_for_blank_end():
    # Late-evening UTC must not roll to the local date; date-only legacy value is UTC
    late = datetime(2026, 11, 2, 23, 59, 59, tzinfo=timezone.utc)
    assert get_date_range(conf("2026-11-01", ""), now=late) == (True, "2026-11-01", "2026-11-02")
    assert get_date_range(conf("2026-11-01", "2026-11-02"), now=late) == (True, "2026-11-01", "2026-11-02")


def test_day_chunks_full_days_and_clipped_final():
    start = datetime(2026, 10, 31, tzinfo=timezone.utc)
    chunks = list(iter_day_chunks(start, NOW))
    assert [c[0].date().isoformat() for c in chunks] == ["2026-10-31", "2026-11-01", "2026-11-02"]
    assert [c[3] for c in chunks] == [True, True, False]
    assert to_graph_ts(chunks[0][1]) == "2026-10-31T23:59:59.999999Z"
    # final chunk clipped to now; checkpoint is exactly now, never the end of the day
    assert chunks[-1][1] == NOW and chunks[-1][2] == NOW


def test_day_chunks_explicit_midnight_end_has_no_extra_day():
    start = datetime(2026, 10, 31, tzinfo=timezone.utc)
    end = datetime(2026, 11, 2, tzinfo=timezone.utc)
    chunks = list(iter_day_chunks(start, end))
    assert len(chunks) == 2 and all(c[3] for c in chunks)


def test_resume_point_legacy_and_exact():
    # Legacy full-day checkpoint -> next midnight
    assert resume_point("2026-11-01T23:59:59.999999Z") == datetime(2026, 11, 2, tzinfo=timezone.utc)
    # Exact checkpoint -> resume from the same instant
    assert resume_point("2026-11-02T13:15:22.123456Z") == NOW


def test_formatters():
    assert to_date_str(NOW) == "2026-11-02"
    assert parse_graph_ts("2026-11-02T13:15:22.123456Z") == NOW
    assert parse_graph_ts("2026-11-02").tzinfo is not None
