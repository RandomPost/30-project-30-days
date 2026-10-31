"""Task operations. Functions take a connection and return data; nothing prints."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


class TaskNotFound(LookupError):
    pass


@dataclass(frozen=True)
class Task:
    id: int
    title: str
    done: bool
    created_at: str
    completed_at: str | None


def _task(row: sqlite3.Row) -> Task:
    return Task(
        id=row["id"],
        title=row["title"],
        done=bool(row["done"]),
        created_at=row["created_at"],
        completed_at=row["completed_at"],
    )


def add(conn: sqlite3.Connection, title: str) -> Task:
    title = title.strip()
    if not title:
        raise ValueError("title must not be empty")
    cur = conn.execute("INSERT INTO tasks(title) VALUES (?)", (title,))
    return get(conn, cur.lastrowid)


def get(conn: sqlite3.Connection, task_id: int) -> Task:
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise TaskNotFound(f"no task with id {task_id}")
    return _task(row)


def list_tasks(conn: sqlite3.Connection, include_done: bool = False) -> list[Task]:
    sql = "SELECT * FROM tasks"
    if not include_done:
        sql += " WHERE done = 0"
    return [_task(r) for r in conn.execute(sql + " ORDER BY id")]


def complete(conn: sqlite3.Connection, task_id: int) -> Task:
    get(conn, task_id)
    conn.execute(
        "UPDATE tasks SET done = 1, completed_at = datetime('now') "
        "WHERE id = ? AND done = 0",
        (task_id,),
    )
    return get(conn, task_id)


def delete(conn: sqlite3.Connection, task_id: int) -> None:
    get(conn, task_id)
    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
