"""Parse due dates typed on the command line. Pure; `today` is injectable for tests."""

from __future__ import annotations

import re
from datetime import date, timedelta

RELATIVE = re.compile(r"\+(\d{1,4})d")


def parse_due(text: str, today: date | None = None) -> str:
    """Return an ISO date. Accepts YYYY-MM-DD, `today`, `tomorrow`, `+Nd`."""
    today = today or date.today()
    word = text.strip().lower()
    if word == "today":
        return today.isoformat()
    if word == "tomorrow":
        return (today + timedelta(days=1)).isoformat()
    m = RELATIVE.fullmatch(word)
    if m:
        return (today + timedelta(days=int(m.group(1)))).isoformat()
    try:
        return date.fromisoformat(word).isoformat()
    except ValueError:
        raise ValueError(
            f"bad due date {text!r}: use YYYY-MM-DD, today, tomorrow or +Nd"
        ) from None
