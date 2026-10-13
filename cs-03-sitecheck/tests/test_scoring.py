from sitecheck.models import Issue
from sitecheck.scoring import COOKIE_CAP, grade_for, score


def test_grade_boundaries():
    assert [grade_for(s) for s in (100, 90, 89, 80, 70, 60, 59, 0)] == list("AABBCDFF")


def test_penalties_subtract():
    assert score([Issue("CSP", 20, "r", "f")]) == (80, "B")


def test_fatal_forces_f():
    assert score([Issue("Certificate", 100, "r", "f", fatal=True)]) == (0, "F")


def test_cookie_penalties_capped():
    cookies = [Issue("Cookies", 5, "r", "f")] * 20
    assert score(cookies)[0] == 100 - COOKIE_CAP


def test_score_floor_is_zero():
    assert score([Issue("A", 70, "r", "f"), Issue("B", 70, "r", "f")])[0] == 0
