"""LOCAL LAB ONLY. This version is DELIBERATELY VULNERABLE (branch `cs-07-vulnerable`).

It has five planted flaws: SQL injection, stored XSS, CSRF, IDOR and weak password
hashing. It binds to 127.0.0.1 only. Never deploy it or expose it to a network.
"""

from __future__ import annotations

import hashlib
import sqlite3

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


def hash_password(password: str) -> str:
    # VULN (weak hashing): fast, unsalted MD5.
    return hashlib.md5(password.encode()).hexdigest()


def create_app(db_path: str = "notes.db") -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev"  # fixed key for the lab
    app.config["DB_PATH"] = db_path

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

    def current_user_id() -> int | None:
        return session.get("user_id")

    @app.route("/")
    def index():
        uid = current_user_id()
        if uid is None:
            return redirect(url_for("login"))
        rows = db().execute(f"SELECT id, title FROM notes WHERE owner_id = {uid}")
        return render_template("notes.html", notes=rows.fetchall())

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form["username"]
            pw = hash_password(request.form["password"])
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
            pw = hash_password(request.form["password"])
            # VULN (SQL injection): credentials interpolated into the query.
            row = (
                db()
                .execute(
                    f"SELECT id FROM users WHERE username = '{username}' "
                    f"AND password_hash = '{pw}'"
                )
                .fetchone()
            )
            if row is None:
                return render_template("login.html", error="Bad credentials"), 401
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # VULN (CSRF): every state-changing route below accepts a bare cross-site POST.
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
        # VULN (IDOR): no check that the note belongs to the logged-in user.
        row = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        if row is None:
            abort(404)
        return render_template("note.html", note=row)

    @app.route("/note/<int:note_id>/delete", methods=["POST"])
    def delete_note(note_id: int):
        if current_user_id() is None:
            abort(401)
        # VULN (IDOR): any logged-in user can delete any note.
        db().execute("DELETE FROM notes WHERE id = ?", (note_id,))
        db().commit()
        return redirect(url_for("index"))

    @app.route("/search")
    def search():
        uid = current_user_id()
        if uid is None:
            abort(401)
        q = request.args.get("q", "")
        # VULN (SQL injection): the search term is interpolated into the query.
        rows = (
            db()
            .execute(
                f"SELECT id, title FROM notes WHERE owner_id = {uid} "
                f"AND (title LIKE '%{q}%' OR body LIKE '%{q}%')"
            )
            .fetchall()
        )
        return render_template("notes.html", notes=rows, query=q)

    return app


def main() -> None:
    # Bound to loopback only, debug off: this app is intentionally insecure.
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
