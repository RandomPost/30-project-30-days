from vulnreport.models import Dep
from vulnreport.parsers import parse_lockfile, parse_package_lock, parse_poetry_lock
from vulnreport.parsers import parse_requirements
import pytest


def test_requirements_pins_only(fixtures_dir):
    deps = parse_requirements((fixtures_dir / "requirements.txt").read_text())
    assert [(d.name, d.version) for d in deps] == [
        ("jinja2", "2.4.1"),
        ("flask", "2.0.0"),
        ("requests", "2.31.0"),
    ]
    assert {d.ecosystem for d in deps} == {"PyPI"}


def test_poetry_lock(fixtures_dir):
    deps = parse_poetry_lock((fixtures_dir / "poetry.lock").read_text())
    assert [(d.name, d.version) for d in deps] == [
        ("flask", "2.0.0"),
        ("requests", "2.31.0"),
    ]


def test_package_lock_v3_dedupes_and_skips_root_and_links(fixtures_dir):
    deps = parse_package_lock((fixtures_dir / "package-lock.json").read_text())
    assert deps == [Dep("lodash", "4.17.10", "npm", "")]


def test_package_lock_v1_nested():
    text = '{"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}'
    assert [(d.name, d.version) for d in parse_package_lock(text)] == [
        ("a", "1.0.0"),
        ("b", "2.0.0"),
    ]


def test_dispatch_by_filename_and_unsupported():
    assert (
        parse_lockfile("x/requirements.txt", "a==1")[0].source == "x/requirements.txt"
    )
    with pytest.raises(ValueError):
        parse_lockfile("Cargo.lock", "")
