import pytest

from taskcli import tasks


def test_add_and_list(conn):
    a = tasks.add(conn, "  write report ")
    assert (a.id, a.title, a.done) == (1, "write report", False)
    tasks.add(conn, "buy milk")
    assert [t.title for t in tasks.list_tasks(conn)] == ["write report", "buy milk"]


def test_empty_title_rejected(conn):
    with pytest.raises(ValueError):
        tasks.add(conn, "   ")


def test_complete_hides_from_default_list(conn):
    t = tasks.add(conn, "x")
    done = tasks.complete(conn, t.id)
    assert done.done and done.completed_at
    assert tasks.list_tasks(conn) == []
    assert [t.id for t in tasks.list_tasks(conn, include_done=True)] == [t.id]


def test_complete_twice_keeps_first_timestamp(conn):
    t = tasks.add(conn, "x")
    first = tasks.complete(conn, t.id).completed_at
    conn.execute("UPDATE tasks SET completed_at = '2000-01-01 00:00:00'")
    assert tasks.complete(conn, t.id).completed_at == "2000-01-01 00:00:00" != first


def test_delete(conn):
    t = tasks.add(conn, "x")
    tasks.delete(conn, t.id)
    with pytest.raises(tasks.TaskNotFound):
        tasks.get(conn, t.id)


@pytest.mark.parametrize("op", [tasks.complete, tasks.delete, tasks.get])
def test_missing_id(conn, op):
    with pytest.raises(tasks.TaskNotFound):
        op(conn, 42)


def test_title_with_sql_metacharacters_is_stored_verbatim(conn):
    t = tasks.add(conn, "x'); DROP TABLE tasks;--")
    assert tasks.get(conn, t.id).title == "x'); DROP TABLE tasks;--"
