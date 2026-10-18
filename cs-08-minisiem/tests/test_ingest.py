import pytest

from minisiem.ingest import guess_source, ingest_file, ingest_lines

LINE = "Oct 18 01:00:00 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2\n"


def count(conn):
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def test_unparsable_lines_are_counted_not_stored(conn):
    res = ingest_lines(conn, [LINE, "garbage", ""], "auth", 2026)
    assert (res.parsed, res.skipped) == (1, 1) and count(conn) == 1


def test_unknown_source_is_an_error(conn):
    with pytest.raises(ValueError):
        ingest_lines(conn, [LINE], "windows", 2026)


def test_incremental_file_ingest_reads_only_new_complete_lines(conn, tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(LINE + LINE)
    assert ingest_file(conn, str(f), "auth", 2026).parsed == 2
    assert ingest_file(conn, str(f), "auth", 2026).parsed == 0  # nothing new
    with open(f, "a") as fh:
        fh.write(LINE[:30])  # partial line, no newline yet
    assert ingest_file(conn, str(f), "auth", 2026).parsed == 0
    with open(f, "a") as fh:
        fh.write(LINE[30:])
    assert ingest_file(conn, str(f), "auth", 2026).parsed == 1
    assert count(conn) == 3


def test_truncated_file_is_read_again_from_the_start(conn, tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(LINE * 3)
    ingest_file(conn, str(f), "auth", 2026)
    f.write_text(LINE)  # rotated, smaller
    assert ingest_file(conn, str(f), "auth", 2026).parsed == 1


def test_guess_source():
    assert guess_source("/var/log/auth.log") == "auth"
    assert guess_source("nginx_access.log") == "nginx"
    assert guess_source("syslog") == "syslog"
    assert guess_source("siem.db") is None


def test_events_columns_match_the_documented_schema(conn):
    from minisiem.db import EVENT_FIELDS

    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)")]
    assert [c for c in cols if c != "id"] == list(EVENT_FIELDS)
