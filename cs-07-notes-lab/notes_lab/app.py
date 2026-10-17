"""Notes app for the CS-07 break-and-fix lab: the FIXED version.

The original, deliberately vulnerable code is on branch `cs-07-vulnerable`; every fix
is explained in SECURITY_FIXES.md. Still a lab app: it binds to 127.0.0.1 and has no
rate limiting, so do not expose it to a network.
"""

from __future__ import annotations

import hmac
import os
import secrets
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash
from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
"""


MIN_PASSWORD_LENGTH = 8
# Verified against when the username doesn't exist, so timing doesn't reveal accounts.
DUMMY_HASH = generate_password_hash("not-a-real-password")
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def hash_password(password: str) -> str:
    """Salted, slow hash (werkzeug's default scrypt)."""
    return generate_password_hash(password)


def escape_like(term: str) -> str:
    """Make %, _ and the escape character literal inside a LIKE pattern."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def create_app(db_path: str = "notes.db", secret_key: str | None = None) -> Flask:
    app = Flask(__name__)
    # A random per-process key unless one is supplied (sessions then survive restarts).
    app.config["SECRET_KEY"] = (
        secret_key or os.environ.get("NOTES_LAB_SECRET_KEY") or secrets.token_hex(32)
    )
    app.config["DB_PATH"] = db_path
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("NOTES_LAB_HTTPS") == "1"

    def db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    with app.app_context():
        db().executescript(SCHEMA)

    def csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf() -> None:
        """Reject state-changing requests that lack the session's CSRF token."""
        if request.method not in UNSAFE_METHODS:
            return
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Missing or invalid CSRF token")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def current_user_id() -> int | None:
        return session.get("user_id")

    @app.route("/")
    def index():
        uid = current_user_id()
        if uid is None:
            return redirect(url_for("login"))
        rows = db().execute(
            "SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id", (uid,)
        )
        return render_template("notes.html", notes=rows.fetchall())

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            if not username or len(password) < MIN_PASSWORD_LENGTH:
                error = f"Username required, password at least {MIN_PASSWORD_LENGTH}"
                return render_template("register.html", error=error), 400
            pw = hash_password(password)
            try:
                db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, pw),
                )
                db().commit()
            except sqlite3.IntegrityError:
                return render_template("register.html", error="Username taken"), 400
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            row = (
                db()
                .execute(
                    "SELECT id, password_hash FROM users WHERE username = ?",
                    (username,),
                )
                .fetchone()
            )
            stored = row["password_hash"] if row else DUMMY_HASH
            ok = check_password_hash(stored, password)
            if row is None or not ok:
                return render_template("login.html", error="Bad credentials"), 401
            session.clear()  # new session on login (no fixation)
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/notes", methods=["POST"])
    def create_note():
        uid = current_user_id()
        if uid is None:
            abort(401)
        db().execute(
            "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
            (uid, request.form["title"], request.form["body"]),
        )
        db().commit()
        return redirect(url_for("index"))

    @app.route("/note/<int:note_id>")
    def view_note(note_id: int):
        if current_user_id() is None:
            abort(401)
        # Scoped to the owner; 404 (not 403) so note ids can't be probed.
        row = (
            db()
            .execute(
                "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
                (note_id, current_user_id()),
            )
            .fetchone()
        )
        if row is None:
            abort(404)
        return render_template("note.html", note=row)

    @app.route("/note/<int:note_id>/delete", methods=["POST"])
    def delete_note(note_id: int):
        if current_user_id() is None:
            abort(401)
        cur = db().execute(
            "DELETE FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, current_user_id()),
        )
        db().commit()
        if cur.rowcount == 0:
            abort(404)
        return redirect(url_for("index"))

    @app.route("/search")
    def search():
        uid = current_user_id()
        if uid is None:
            abort(401)
        q = request.args.get("q", "")
        pattern = f"%{escape_like(q)}%"
        rows = (
            db()
            .execute(
                "SELECT id, title FROM notes WHERE owner_id = ? "
                "AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')",
                (uid, pattern, pattern),
            )
            .fetchall()
        )
        return render_template("notes.html", notes=rows, query=q)

    return app


def main() -> None:
    # Loopback only, debug off (the Werkzeug debugger allows code execution).
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
