"""One regression test (or two) per planted vulnerability.

On branch `cs-07-vulnerable` these tests FAIL (they prove the flaws are exploitable).
On the fixed branch they PASS. Each test also checks normal behaviour still works, so a
fix can't pass by breaking the feature.
"""

import hashlib

from conftest import db_rows

PASSWORD = "correct horse battery"


# --- 1. SQL injection ---------------------------------------------------------


def test_sqli_login_cannot_bypass_password(browser):
    victim = browser()
    victim.register("victim")
    attacker = browser()
    for username, password in [("victim' --", "x"), ("nobody' OR '1'='1", "x")]:
        attacker.login(username, password)
        assert not attacker.logged_in(), f"logged in with injected {username!r}"
    assert browser().login("victim", PASSWORD).status_code == 302  # sanity


def test_sqli_search_cannot_read_other_users_notes(browser):
    alice, bob = browser(), browser()
    alice.signup("alice")
    alice.add_note("alice-secret-plan", "launch codes")
    bob.signup("bob")
    bob.add_note("bobs-shopping")
    injected = bob.get("/search?q=zzz%25')+OR+1%3D1+--").get_data(as_text=True)
    assert "alice-secret-plan" not in injected
    honest = bob.get("/search?q=shopping").get_data(as_text=True)
    assert "bobs-shopping" in honest  # sanity: real search still works


# --- 2. Stored XSS ------------------------------------------------------------


def test_stored_xss_is_escaped_and_csp_set(browser):
    alice = browser()
    alice.signup("alice")
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    alice.add_note("xss", payload)
    (note_id,) = db_rows(alice.app, "SELECT id FROM notes WHERE title = 'xss'")[0]
    resp = alice.get(f"/note/{note_id}")
    html = resp.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html  # shown as text, not executed
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "script-src 'self'" in csp or "default-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("style-src")[0]


# --- 3. CSRF ------------------------------------------------------------------


def test_csrf_post_without_token_is_rejected(browser):
    alice = browser()
    alice.signup("alice")
    forged = alice.client.post("/notes", data={"title": "forged", "body": "x"})
    assert forged.status_code in (400, 403)
    assert db_rows(alice.app, "SELECT id FROM notes WHERE title = 'forged'") == []


def test_csrf_post_with_valid_token_is_accepted(browser):
    alice = browser()
    alice.signup("alice")
    assert alice.add_note("legit").status_code == 302
    assert db_rows(alice.app, "SELECT id FROM notes WHERE title = 'legit'")


def test_csrf_delete_and_logout_need_a_token(browser):
    alice = browser()
    alice.signup("alice")
    alice.add_note("keep-me")
    (note_id,) = db_rows(alice.app, "SELECT id FROM notes")[0]
    assert alice.client.post(f"/note/{note_id}/delete").status_code in (400, 403)
    assert db_rows(alice.app, "SELECT id FROM notes")
    assert alice.client.post("/logout").status_code in (400, 403)
    assert alice.logged_in()


def test_session_cookie_is_samesite_lax_and_httponly(browser):
    alice = browser()
    resp = alice.signup("alice")
    cookie = resp.headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in cookie
    assert "HttpOnly" in cookie


# --- 4. IDOR ------------------------------------------------------------------


def test_idor_cannot_read_or_delete_another_users_note(browser):
    alice, bob = browser(), browser()
    alice.signup("alice")
    alice.add_note("private")
    (note_id,) = db_rows(alice.app, "SELECT id FROM notes")[0]
    bob.signup("bob")
    assert bob.get(f"/note/{note_id}").status_code == 404
    assert bob.post(f"/note/{note_id}/delete").status_code == 404
    assert alice.get(f"/note/{note_id}").status_code == 200  # owner still can


# --- 5. Weak password hashing -------------------------------------------------


def test_passwords_use_a_salted_slow_hash(browser):
    a, b = browser(), browser()
    a.register("alice", PASSWORD)
    b.register("bob", PASSWORD)
    hashes = [r[0] for r in db_rows(a.app, "SELECT password_hash FROM users")]
    assert len(hashes) == 2
    assert hashlib.md5(PASSWORD.encode()).hexdigest() not in hashes
    assert hashes[0] != hashes[1], "same password must hash differently (salt)"
    assert all(h.startswith(("scrypt:", "pbkdf2:")) for h in hashes)
    assert a.login("alice", PASSWORD).status_code == 302  # sanity: login works


# --- Extra: session signing key -----------------------------------------------


def test_secret_key_is_not_the_hardcoded_dev_value(app):
    assert app.config["SECRET_KEY"] not in ("dev", "", None)
