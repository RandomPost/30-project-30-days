"""Pure scoring: Issues -> score and letter grade."""

from __future__ import annotations

from .models import Issue

COOKIE_CAP = 15  # many bad cookies shouldn't sink a site on their own
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


def grade_for(score: int) -> str:
    return next((g for floor, g in GRADES if score >= floor), "F")


def score(issues: list[Issue]) -> tuple[int, str]:
    if any(i.fatal for i in issues):
        return 0, "F"
    cookie_loss = min(
        sum(i.penalty for i in issues if i.check == "Cookies"), COOKIE_CAP
    )
    other_loss = sum(i.penalty for i in issues if i.check != "Cookies")
    points = max(0, 100 - cookie_loss - other_loss)
    return points, grade_for(points)
