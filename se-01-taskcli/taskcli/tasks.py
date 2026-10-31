"""Task operations. Functions take a connection and return data; nothing prints."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, replace


class TaskNotFound(LookupError):
    pass


PRIORITIES = {"high": 1, "medium": 2, "low": 3}
PRIORITY_NAMES = {v: k for k, v in PRIORITIES.items()}


TAG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,29}")


def normalize_tag(tag: str) -> str:
    t = tag.strip().lower().lstrip("#")
    if not TAG_RE.fullmatch(t):
        raise ValueError(
            f"bad tag {tag!r}: use letters, digits, - and _ (max 30 characters)"
        )
    return t


def priority_value(name: str) -> int:
    try:
        return PRIORITIES[name.strip().lower()]
    except KeyError:
        raise ValueError(f"priority must be one of: {', '.join(PRIORITIES)}") from None


@dataclass(frozen=True)
class Task:
    id: int
    title: str
    done: bool
    created_at: str
    completed_at: str | None
    due_date: str | None
    priority: int
    tags: tuple[str, ...] = ()

    @property
    def priority_name(self) -> str:
        return PRIORITY_NAMES[self.priority]


def _task(row: sqlite3.Row) -> Task:
    return Task(
        id=row["id"],
        title=row["title"],
        done=bool(row["done"]),
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        due_date=row["due_date"],
        priority=row["priority"],
    )


def add(
    conn: sqlite3.Connection,
    title: str,
    priority: str = "medium",
    due: str | None = None,
    tags: list[str] | None = None,
) -> Task:
    """`due` must already be an ISO date (see dates.parse_due)."""
    title = title.strip()
    if not title:
        raise ValueError("title must not be empty")
    wanted = [normalize_tag(t) for t in tags or []]  # validate before writing anything
    cur = conn.execute(
        "INSERT INTO tasks(title, priority, due_date) VALUES (?, ?, ?)",
        (title, priority_value(priority), due),
    )
    add_tags(conn, cur.lastrowid, wanted)
    return get(conn, cur.lastrowid)


def add_tags(conn: sqlite3.Connection, task_id: int, tags: list[str]) -> Task:
    get(conn, task_id)
    for tag in dict.fromkeys(normalize_tag(t) for t in tags):
        conn.execute("INSERT OR IGNORE INTO tags(name) VALUES (?)", (tag,))
        conn.execute(
            "INSERT OR IGNORE INTO task_tags(task_id, tag_id) "
            "SELECT ?, id FROM tags WHERE name = ?",
            (task_id, tag),
        )
    return get(conn, task_id)


def remove_tags(conn: sqlite3.Connection, task_id: int, tags: list[str]) -> Task:
    get(conn, task_id)
    for tag in (normalize_tag(t) for t in tags):
        conn.execute(
            "DELETE FROM task_tags WHERE task_id = ? "
            "AND tag_id = (SELECT id FROM tags WHERE name = ?)",
            (task_id, tag),
        )
    return get(conn, task_id)


def tag_counts(conn: sqlite3.Connection) -> list[tuple[str, int]]:
    """Tags with the number of open tasks using them, most used first."""
    rows = conn.execute(
        "SELECT g.name, COUNT(t.id) AS n FROM tags g "
        "JOIN task_tags tt ON tt.tag_id = g.id "
        "JOIN tasks t ON t.id = tt.task_id AND t.done = 0 "
        "GROUP BY g.id ORDER BY n DESC, g.name"
    )
    return [(r["name"], r["n"]) for r in rows]


def get(conn: sqlite3.Connection, task_id: int) -> Task:
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise TaskNotFound(f"no task with id {task_id}")
    return _with_tags(conn, [_task(row)])[0]


def _with_tags(conn: sqlite3.Connection, found: list[Task]) -> list[Task]:
    if not found:
        return found
    marks = ",".join("?" * len(found))
    by_task: dict[int, list[str]] = {}
    for r in conn.execute(
        f"SELECT tt.task_id, g.name FROM task_tags tt JOIN tags g ON g.id = tt.tag_id "
        f"WHERE tt.task_id IN ({marks}) ORDER BY g.name",  # marks are only '?'
        [t.id for t in found],
    ):
        by_task.setdefault(r["task_id"], []).append(r["name"])
    return [replace(t, tags=tuple(by_task.get(t.id, ()))) for t in found]


def list_tasks(
    conn: sqlite3.Connection, include_done: bool = False, tag: str | None = None
) -> list[Task]:
    where, args = [], []
    if not include_done:
        where.append("t.done = 0")
    if tag is not None:
        where.append(
            "t.id IN (SELECT tt.task_id FROM task_tags tt "
            "JOIN tags g ON g.id = tt.tag_id WHERE g.name = ?)"
        )
        args.append(normalize_tag(tag))
    sql = "SELECT t.* FROM tasks t"
    if where:
        sql += " WHERE " + " AND ".join(where)
    # open tasks first by priority, then soonest due (undated last), then oldest
    sql += " ORDER BY t.done, t.priority, t.due_date IS NULL, t.due_date, t.id"
    return _with_tags(conn, [_task(r) for r in conn.execute(sql, args)])


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
