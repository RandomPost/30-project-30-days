"""Shared helpers. They work on both the vulnerable and the fixed app, so a regression
test fails on the vulnerable branch because of behaviour, not because of a missing helper.
"""

from __future__ import annotations

import re
import sqlite3

import pytest

from notes_lab import create_app

TOKEN = re.compile(r'name="csrf-token" content="([^"]*)"')


@pytest.fixture
def app(tmp_path):
    app = create_app(str(tmp_path / "test.db"))
    app.config["TESTING"] = True
    return app


class Browser:
    """A tiny cookie-keeping client that fetches CSRF tokens the way a browser would."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()

    def token(self, path: str = "/login") -> str:
        html = self.client.get(path, follow_redirects=True).get_data(as_text=True)
        m = TOKEN.search(html)
        return m.group(1) if m else ""

    def post(self, path: str, data: dict | None = None, **kw):
        data = dict(data or {})
        data.setdefault("csrf_token", self.token())
        return self.client.post(path, data=data, **kw)

    def register(self, username: str, password: str = "correct horse battery"):
        return self.post("/register", {"username": username, "password": password})

    def login(self, username: str, password: str = "correct horse battery"):
        return self.post("/login", {"username": username, "password": password})

    def signup(self, username: str, password: str = "correct horse battery"):
        self.register(username, password)
        return self.login(username, password)

    def add_note(self, title: str, body: str = "body"):
        return self.post("/notes", {"title": title, "body": body})

    def get(self, path: str, **kw):
        return self.client.get(path, **kw)

    def logged_in(self) -> bool:
        with self.client.session_transaction() as sess:
            return "user_id" in sess


@pytest.fixture
def browser(app):
    return lambda: Browser(app)


def db_rows(app, sql: str, params: tuple = ()):
    conn = sqlite3.connect(app.config["DB_PATH"])
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()
