"""Typer commands. The only module that prints, reads the environment or exits."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import typer

from . import dates, db, tasks

app = typer.Typer(help="A small task manager on SQLite.", no_args_is_help=True)

DEFAULT_DB = "~/.local/share/taskcli/tasks.db"


def db_path(override: str | None = None) -> str:
    return (
        override or os.environ.get("TASKCLI_DB") or str(Path(DEFAULT_DB).expanduser())
    )


@app.callback()
def main_callback(
    ctx: typer.Context,
    db_file: str = typer.Option(None, "--db", help="Database file (or $TASKCLI_DB)."),
) -> None:
    ctx.obj = db_path(db_file)


def open_db(ctx: typer.Context) -> sqlite3.Connection:
    return db.connect(ctx.obj)


def fail(message: str) -> typer.Exit:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    return typer.Exit(1)


@app.command()
def add(
    ctx: typer.Context,
    title: str = typer.Argument(..., help="What to do."),
    priority: str = typer.Option(
        "medium", "--priority", "-p", help="high, medium or low."
    ),
    due: str = typer.Option(
        None, "--due", "-d", help="YYYY-MM-DD, today, tomorrow, +3d."
    ),
) -> None:
    """Add a task."""
    try:
        due_iso = dates.parse_due(due) if due else None
        t = tasks.add(open_db(ctx), title, priority=priority, due=due_iso)
    except ValueError as e:
        raise fail(str(e))
    typer.echo(f"added #{t.id}: {t.title}")


@app.command("ls")
def list_(
    ctx: typer.Context,
    all_: bool = typer.Option(False, "--all", "-a", help="Include completed tasks."),
) -> None:
    """List open tasks."""
    rows = tasks.list_tasks(open_db(ctx), include_done=all_)
    if not rows:
        typer.echo("no tasks")
    for t in rows:
        due = t.due_date or "-"
        typer.echo(
            f"{t.id:>4}  [{'x' if t.done else ' '}] {t.priority_name:<6} {due:<10} {t.title}"
        )


@app.command()
def done(ctx: typer.Context, task_id: int) -> None:
    """Mark a task complete."""
    try:
        t = tasks.complete(open_db(ctx), task_id)
    except tasks.TaskNotFound as e:
        raise fail(str(e))
    typer.echo(f"completed #{t.id}: {t.title}")


@app.command()
def rm(ctx: typer.Context, task_id: int) -> None:
    """Delete a task."""
    try:
        tasks.delete(open_db(ctx), task_id)
    except tasks.TaskNotFound as e:
        raise fail(str(e))
    typer.echo(f"deleted #{task_id}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
