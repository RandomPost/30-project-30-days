# taskcli

Command-line task manager (`tk`) in Python with Typer and SQLite.

## Layout
- `taskcli/db.py`: connection + schema migrations (`PRAGMA user_version`, ordered `MIGRATIONS` list)
- `taskcli/tasks.py`: task operations on a connection (add, list, complete, delete, tags, search)
- `taskcli/dates.py`: parse due dates (`2026-11-05`, `today`, `tomorrow`, `+3d`)
- `taskcli/cli.py`: Typer commands; the only module that prints or reads env
- `tests/`: pytest, every test uses a temporary database (`conn` fixture)

## Commands
- Install for development: `pip install -e '.[dev]'`
- Test: `pytest`
- Format: `black .`
- Install like a user: `pipx install .` then `tk add "write report" -t work -p high -d tomorrow`
- Database: `$TASKCLI_DB`, else `~/.local/share/taskcli/tasks.db`; `--db PATH` overrides both

## Conventions
- Type hints on all functions; `from __future__ import annotations`
- black, 88 columns; small single-purpose functions
- Schema changes are new migrations in `db.MIGRATIONS`; never edit an existing one
- All SQL uses `?` placeholders, never string formatting of user input
- Library code returns data; only `cli.py` prints and sets exit codes
- Commit after each working feature, with its tests
