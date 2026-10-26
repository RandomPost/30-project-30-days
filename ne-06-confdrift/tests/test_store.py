import pytest

from confdrift.store import Store

R1 = "hostname r1\ninterface eth1\n ip ospf cost 10\n"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "backups")
    s.init()
    return s


def commits(store):
    return store.git("log", "--format=%s").strip().splitlines()


def test_first_run_is_one_commit_with_all_devices(store):
    store.write("r1", R1)
    store.write("r2", "hostname r2\n")
    subject = store.commit_run(total=2)
    assert subject == "backup: first snapshot of 2 device(s): r1, r2"
    assert len(commits(store)) == 1


def test_unchanged_run_makes_no_commit(store):
    store.write("r1", R1)
    store.commit_run(total=1)
    store.write("r1", R1)
    assert store.commit_run(total=1) is None
    assert len(commits(store)) == 1


def test_change_commit_names_device_and_counts_lines(store):
    store.write("r1", R1)
    store.write("r2", "hostname r2\n")
    store.commit_run(total=2)
    store.write("r1", R1.replace("cost 10", "cost 100"))
    store.write("r2", "hostname r2\n")
    subject = store.commit_run(total=2)
    assert subject == "backup: config changed on r1 (+1/-1 lines)"
    body = store.git("log", "-1", "--format=%b")
    assert "1 of 2 device(s) changed" in body
    assert "\n    - ip ospf cost 10\n" in body
    assert "\n    + ip ospf cost 100" in body


def test_one_commit_per_run_for_several_devices(store):
    store.write("r1", R1)
    store.write("r2", "hostname r2\n")
    store.commit_run(total=2)
    store.write("r1", R1 + " x\n")
    store.write("r2", "hostname r2\n y\n")
    store.commit_run(total=2)
    assert len(commits(store)) == 2
    assert commits(store)[0].startswith("backup: config changed on r1, r2")


def test_failed_device_is_listed_and_previous_copy_kept(store):
    store.write("r1", R1)
    store.write("r2", "hostname r2\n")
    store.commit_run(total=2)
    store.write("r1", R1 + " x\n")
    store.commit_run(total=2, failed={"r2": "timed out"})
    body = store.git("log", "-1", "--format=%b")
    assert "r2: timed out" in body
    assert (store.path / "r2.cfg").read_text() == "hostname r2\n"


def test_history_per_device(store):
    store.write("r1", R1)
    store.write("r2", "a\n")
    store.commit_run(total=2)
    store.write("r2", "b\n")
    store.commit_run(total=2)
    assert len(store.history("r1").strip().splitlines()) == 1
    assert len(store.history("r2").strip().splitlines()) == 2


def test_long_changes_are_truncated_in_body(store):
    store.write("r1", "a\n")
    store.commit_run(total=1)
    store.write("r1", "a\n" + "".join(f"line {i}\n" for i in range(30)))
    store.commit_run(total=1)
    body = store.git("log", "-1", "--format=%b")
    assert "... 18 more" in body
