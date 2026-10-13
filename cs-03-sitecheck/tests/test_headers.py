from sitecheck.headers import analyze_headers, check_cookie, check_hsts, check_xfo

GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def checks(issues):
    return {i.check for i in issues}


def test_all_good_headers_no_issues():
    assert analyze_headers(GOOD, ["sid=1; Secure; HttpOnly; SameSite=Lax"]) == []


def test_everything_missing():
    assert checks(analyze_headers({}, [])) == {
        "HSTS",
        "CSP",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    }


def test_hsts_short_max_age_is_minor():
    (i,) = check_hsts("max-age=60")
    assert i.penalty == 5


def test_csp_unsafe_inline_flagged():
    h = {**GOOD, "content-security-policy": "script-src 'self' 'unsafe-inline'"}
    assert checks(analyze_headers(h, [])) == {"CSP"}


def test_frame_ancestors_replaces_xfo():
    assert check_xfo(None, "default-src 'self'; frame-ancestors 'none'") == []
    assert check_xfo("ALLOW-FROM x", None) != []


def test_weak_referrer_policy():
    h = {**GOOD, "referrer-policy": "unsafe-url"}
    assert checks(analyze_headers(h, [])) == {"Referrer-Policy"}


def test_cookie_flags():
    assert len(check_cookie("a=1")) == 3
    assert [i.reason for i in check_cookie("a=1; Secure; HttpOnly")] == [
        "Cookie `a` lacks SameSite"
    ]
    assert check_cookie("a=1; secure; httponly; samesite=strict") == []
