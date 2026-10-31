# taskcli (`tk`)

A command-line task manager in Python with Typer and SQLite.

## Install
```
pipx install .            # from this folder; gives you the `tk` command
# or for development
pip install -e '.[dev]' && pytest
```
Data lives in `$TASKCLI_DB`, else `~/.local/share/taskcli/tasks.db` (`--db PATH` overrides both). The schema is created and upgraded automatically.

## Use
```
$ tk add "write report" -t work -p high -d tomorrow
added #1: write report
$ tk add "buy milk" -d +3d -t errand
added #2: buy milk
$ tk ls
   1  [ ] high   2026-11-01 write report  #work
   2  [ ] medium 2026-11-03 buy milk  #errand
$ tk search milk
   2  [ ] medium 2026-11-03 buy milk  #errand
$ tk tags
   1  #errand
   1  #work
$ tk done 2
completed #2: buy milk
$ tk ls -a
   1  [ ] high   2026-11-01 write report  #work
   2  [x] medium 2026-11-03 buy milk  #errand
```
(real output from the pipx-installed command)

| Command | What it does |
|---|---|
| `tk add TITLE [-p high\|medium\|low] [-d DATE] [-t TAG ...]` | add a task; DATE is `YYYY-MM-DD`, `today`, `tomorrow` or `+Nd` |
| `tk ls [-a] [-t TAG]` | open tasks (all with `-a`), sorted by priority, then due date (undated last), then age |
| `tk done ID` / `tk rm ID` | complete / delete |
| `tk tag ID TAG...` / `tk untag ID TAG...` / `tk tags` | manage tags; `tags` counts open tasks per tag |
| `tk search TEXT [-a]` | substring match on title or tag, case-insensitive |

Errors (unknown id, bad date, bad tag) print `error: ...` to stderr and exit 1.

## Design notes
- **Migrations** (`taskcli/db.py`): an ordered list applied once each in a transaction, with the version in `PRAGMA user_version`. A failed migration rolls back; a database newer than the program is refused instead of misread. Three migrations ship: tasks, due date + priority, tags.
- All SQL uses placeholders; search escapes `%` and `_` so they match literally.
- Library functions return data; only `cli.py` prints.

## Tests
56 tests (`pytest`), each on a temporary database: migrations (fresh, upgrade from schema 1 keeping data, rollback, newer-db refusal), task operations, date parsing, tags, search (wildcards, injection text), and the CLI through Typer's test runner.

## Not verified / limits
- `pipx install .` was run from this folder and the installed `tk` exercised; installing from PyPI or git was not done (not published).
- Search is a plain substring match, and SQLite's `LIKE` is case-insensitive for ASCII only: `É` will not match `é`.
- No edit command (change a title or due date), no recurring tasks, no concurrent-writer testing beyond SQLite's own locking.
- Due dates are never checked against the clock for "overdue"; they are just displayed and sorted.
