import sqlite3

import pytest

from taskcli import db


def test_fresh_database_is_migrated_to_latest(conn):
    assert db.schema_version(conn) == db.LATEST
    tables = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"tasks", "tags", "task_tags"} <= tables


def test_migrate_is_idempotent(conn):
    assert db.migrate(conn) == []


def test_upgrade_from_old_schema_keeps_data(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript(db.MIGRATIONS[0][2])
    raw.execute("PRAGMA user_version = 1")
    raw.execute("INSERT INTO tasks(title) VALUES ('old task')")
    raw.commit()
    raw.close()
    c = db.connect(path)
    row = c.execute("SELECT title, priority, due_date FROM tasks").fetchone()
    assert (row["title"], row["priority"], row["due_date"]) == ("old task", 2, None)
    assert db.schema_version(c) == db.LATEST


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    bad = db.MIGRATIONS + [(99, "bad", "CREATE TABLE ok(x); CREATE TABLE ok(x);")]
    monkeypatch.setattr(db, "MIGRATIONS", bad)
    monkeypatch.setattr(db, "LATEST", 99)
    c = sqlite3.connect(tmp_path / "x.db")
    c.isolation_level = None
    with pytest.raises(sqlite3.OperationalError):
        db.migrate(c)
    assert db.schema_version(c) == 3  # migrations 1-3 applied, 99 rolled back
    assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='ok'").fetchone()


def test_newer_database_is_refused(tmp_path):
    c = sqlite3.connect(tmp_path / "n.db")
    c.execute(f"PRAGMA user_version = {db.LATEST + 1}")
    with pytest.raises(RuntimeError, match="newer"):
        db.migrate(c)


def test_cascade_removes_tag_links(conn):
    conn.execute("INSERT INTO tasks(title) VALUES ('a')")
    conn.execute("INSERT INTO tags(name) VALUES ('x')")
    conn.execute("INSERT INTO task_tags VALUES (1, 1)")
    conn.execute("DELETE FROM tasks WHERE id = 1")
    assert conn.execute("SELECT COUNT(*) FROM task_tags").fetchone()[0] == 0
