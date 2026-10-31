from datetime import date

import pytest

from taskcli.dates import parse_due

TODAY = date(2026, 10, 31)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("2026-12-01", "2026-12-01"),
        ("today", "2026-10-31"),
        ("Tomorrow", "2026-11-01"),
        ("+3d", "2026-11-03"),
        ("+0d", "2026-10-31"),
        (" +45d ", "2026-12-15"),
    ],
)
def test_valid(text, expected):
    assert parse_due(text, TODAY) == expected


@pytest.mark.parametrize(
    "text", ["", "next week", "2026-13-01", "2026-02-30", "+d", "-3d", "31/10/2026"]
)
def test_invalid(text):
    with pytest.raises(ValueError, match="bad due date"):
        parse_due(text, TODAY)
