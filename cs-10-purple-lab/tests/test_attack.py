from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from purplelab import attack


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("attack.t1110.001", "T1110.001"),
        ("attack.t1190", "T1190"),
        ("ATTACK.T1082", "T1082"),
        ("attack.persistence", None),
        ("attack.credential_access", None),
        ("cve.2021.44228", None),
        ("attack.t11", None),
    ],
)
def test_normalize_tag(tag, expected):
    assert attack.normalize_tag(tag) == expected


def test_parent_of():
    assert attack.parent_of("T1110.001") == "T1110"
    assert attack.parent_of("T1190") == "T1190"


def test_covers():
    assert attack.covers("T1110", "T1110.001")
    assert attack.covers("T1110.001", "T1110.001")
    assert not attack.covers("T1110.001", "T1110")
    assert not attack.covers("T1110.003", "T1110.001")
    assert not attack.covers("T1053", "T1190")


def test_table_names_every_planned_technique():
    for tid in ("T1595.002", "T1036.005", "T1053.003", "T1087.001", "T1078"):
        assert attack.name_of(tid)
        assert attack.tactic_of(tid)
    assert attack.name_of("T9999") == "T9999"


def test_tactic_rank_orders_kill_chain():
    assert attack.tactic_rank("reconnaissance") < attack.tactic_rank("discovery")
    assert attack.tactic_rank("nonsense") > attack.tactic_rank("impact")
