"""Pure header and cookie analysis: dicts in, Issues out. No I/O."""

from __future__ import annotations

from .models import Issue

SIX_MONTHS = 15_552_000


def _directives(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        key, _, rest = part.strip().replace("=", " ", 1).partition(" ")
        if key:
            out[key.lower()] = rest.strip()
    return out


def check_hsts(value: str | None) -> list[Issue]:
    if not value:
        return [
            Issue(
                "HSTS",
                15,
                "Strict-Transport-Security header is missing",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            )
        ]
    max_age = _directives(value).get("max-age", "").strip("\"'")
    if not max_age.isdigit() or int(max_age) < SIX_MONTHS:
        return [
            Issue(
                "HSTS",
                5,
                f"HSTS max-age is too short or invalid ({max_age or 'unset'})",
                "Use max-age of at least 15552000 seconds (6 months), ideally 1 year.",
            )
        ]
    return []


def check_csp(value: str | None) -> list[Issue]:
    if not value:
        return [
            Issue(
                "CSP",
                20,
                "Content-Security-Policy header is missing",
                "Start with `default-src 'self'` and loosen only what you need.",
            )
        ]
    low = value.lower()
    if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
        return [
            Issue(
                "CSP",
                5,
                "CSP allows 'unsafe-inline' or 'unsafe-eval'",
                "Use nonces or hashes instead of 'unsafe-inline'/'unsafe-eval'.",
            )
        ]
    return []


def check_xfo(value: str | None, csp: str | None) -> list[Issue]:
    if csp and "frame-ancestors" in csp.lower():
        return []  # CSP frame-ancestors supersedes X-Frame-Options
    if (value or "").strip().upper() in ("DENY", "SAMEORIGIN"):
        return []
    return [
        Issue(
            "X-Frame-Options",
            10,
            "No valid X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors",
            "Send `X-Frame-Options: DENY` or `Content-Security-Policy: "
            "frame-ancestors 'none'`.",
        )
    ]


def check_xcto(value: str | None) -> list[Issue]:
    if (value or "").strip().lower() == "nosniff":
        return []
    return [
        Issue(
            "X-Content-Type-Options",
            5,
            "X-Content-Type-Options: nosniff is missing",
            "Send `X-Content-Type-Options: nosniff`.",
        )
    ]


WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


def check_referrer(value: str | None) -> list[Issue]:
    if not value:
        return [
            Issue(
                "Referrer-Policy",
                5,
                "Referrer-Policy header is missing",
                "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            )
        ]
    if value.strip().lower().split(",")[-1].strip() in WEAK_REFERRER:
        return [
            Issue(
                "Referrer-Policy",
                3,
                f"Referrer-Policy `{value}` leaks full URLs",
                "Use `strict-origin-when-cross-origin` or stricter.",
            )
        ]
    return []


def check_cookie(set_cookie: str) -> list[Issue]:
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0] or "?"
    flags = {p.split("=", 1)[0].lower(): p.partition("=")[2] for p in parts[1:]}
    issues = []
    if "secure" not in flags:
        issues.append(
            Issue("Cookies", 5, f"Cookie `{name}` lacks Secure", "Add `; Secure`.")
        )
    if "httponly" not in flags:
        issues.append(
            Issue("Cookies", 5, f"Cookie `{name}` lacks HttpOnly", "Add `; HttpOnly`.")
        )
    if "samesite" not in flags:
        issues.append(
            Issue(
                "Cookies",
                3,
                f"Cookie `{name}` lacks SameSite",
                "Add `; SameSite=Lax` (or Strict).",
            )
        )
    return issues


def analyze_headers(headers: dict[str, str], cookies: list[str]) -> list[Issue]:
    """headers must have lower-cased names; cookies are raw Set-Cookie values."""
    csp = headers.get("content-security-policy")
    issues = (
        check_hsts(headers.get("strict-transport-security"))
        + check_csp(csp)
        + check_xfo(headers.get("x-frame-options"), csp)
        + check_xcto(headers.get("x-content-type-options"))
        + check_referrer(headers.get("referrer-policy"))
    )
    for c in cookies:
        issues += check_cookie(c)
    return issues
