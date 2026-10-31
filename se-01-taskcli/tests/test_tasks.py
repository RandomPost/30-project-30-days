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


def test_priority_and_due_are_stored(conn):
    t = tasks.add(conn, "x", priority="high", due="2026-11-05")
    assert (t.priority_name, t.due_date) == ("high", "2026-11-05")
    assert tasks.add(conn, "y").priority_name == "medium"


def test_bad_priority_rejected(conn):
    with pytest.raises(ValueError, match="priority"):
        tasks.add(conn, "x", priority="urgent")


def test_list_order_priority_then_due_then_age(conn):
    tasks.add(conn, "low-early", priority="low", due="2026-01-01")
    tasks.add(conn, "med-undated")
    tasks.add(conn, "med-late", due="2026-12-01")
    tasks.add(conn, "med-soon", due="2026-11-01")
    tasks.add(conn, "high-undated", priority="high")
    assert [t.title for t in tasks.list_tasks(conn)] == [
        "high-undated", "med-soon", "med-late", "med-undated", "low-early",
    ]  # fmt: skip


def test_done_tasks_sort_last_in_all(conn):
    a = tasks.add(conn, "a", priority="high")
    tasks.add(conn, "b", priority="low")
    tasks.complete(conn, a.id)
    assert [t.title for t in tasks.list_tasks(conn, include_done=True)] == ["b", "a"]


def test_tags_on_add_are_normalized_and_deduplicated(conn):
    t = tasks.add(conn, "x", tags=["Work", "#work", "home-lab"])
    assert t.tags == ("home-lab", "work")


@pytest.mark.parametrize("bad", ["", "has space", "a;b", "x" * 31, "-lead", "ünï"])
def test_bad_tag_rejected_before_anything_is_written(conn, bad):
    with pytest.raises(ValueError, match="bad tag"):
        tasks.add(conn, "x", tags=["ok", bad])
    assert tasks.list_tasks(conn, include_done=True) == []


def test_add_and_remove_tags(conn):
    t = tasks.add(conn, "x")
    assert tasks.add_tags(conn, t.id, ["a", "b"]).tags == ("a", "b")
    assert tasks.remove_tags(conn, t.id, ["a", "zzz"]).tags == ("b",)


def test_filter_by_tag(conn):
    tasks.add(conn, "w1", tags=["work"])
    tasks.add(conn, "h1", tags=["home"])
    tasks.add(conn, "both", tags=["work", "home"])
    assert [t.title for t in tasks.list_tasks(conn, tag="work")] == ["w1", "both"]
    assert tasks.list_tasks(conn, tag="nothing") == []


def test_tag_counts_only_count_open_tasks(conn):
    a = tasks.add(conn, "a", tags=["work"])
    tasks.add(conn, "b", tags=["work", "home"])
    tasks.complete(conn, a.id)
    assert tasks.tag_counts(conn) == [("home", 1), ("work", 1)]


def test_deleting_a_task_drops_its_tag_links(conn):
    t = tasks.add(conn, "a", tags=["work"])
    tasks.delete(conn, t.id)
    assert conn.execute("SELECT COUNT(*) FROM task_tags").fetchone()[0] == 0
