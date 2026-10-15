import os
from pathlib import Path

import pytest

import check_citations as cc
import render

ROOT = Path(__file__).resolve().parent.parent


def make_repo(tmp_path):
    (tmp_path / "a.go").write_text("package a\nfunc Hello() {}\n// secret here\n")
    return tmp_path


def test_render_resolves_line_numbers(tmp_path):
    repo = make_repo(tmp_path)
    text, cites = render.render("see [[a.go|func Hello]] and [[a.go|package a]]", repo)
    assert text == "see `a.go:2` and `a.go:1`"
    assert cites == [("a.go", 2, "func Hello"), ("a.go", 1, "package a")]


def test_render_nth_match_and_missing_fragment(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "b.go").write_text("x\nx\n")
    assert render.render("[[b.go|x|2]]", repo)[0] == "`b.go:2`"
    with pytest.raises(SystemExit):
        render.render("[[b.go|nope]]", repo)


def test_check_passes_and_detects_drift(tmp_path):
    repo = make_repo(tmp_path)
    md, cites = render.render("[[a.go|func Hello]]", repo)
    tsv = "\n".join(f"{p}\t{n}\t{f}" for p, n, f in cites)
    assert cc.check(md, tsv, repo) == []
    (repo / "a.go").write_text("// inserted line\n" + (repo / "a.go").read_text())
    assert any("does not contain" in p for p in cc.check(md, tsv, repo))


def test_check_flags_uncited_in_tsv_and_missing_file(tmp_path):
    repo = make_repo(tmp_path)
    problems = cc.check("`a.go:1` `nope.go:3`", "nope.go\t3\tx", repo)
    assert any("not in citations.tsv: a.go:1" in p for p in problems)
    assert any("missing file: nope.go" in p for p in problems)


def test_committed_model_is_consistent_with_its_tsv():
    md = (ROOT / "THREAT_MODEL.md").read_text()
    rows = cc.load_citations((ROOT / "citations.tsv").read_text())
    assert cc.md_refs(md) == {(p, n) for p, n, _ in rows}
    for heading in ("## 3. Threats, ranked", "```mermaid", "STRIDE"):
        assert heading in md


@pytest.mark.skipif(
    not os.environ.get("FILEBROWSER_CHECKOUT"), reason="set FILEBROWSER_CHECKOUT"
)
def test_citations_match_real_checkout():
    repo = Path(os.environ["FILEBROWSER_CHECKOUT"])
    md = (ROOT / "THREAT_MODEL.md").read_text()
    tsv = (ROOT / "citations.tsv").read_text()
    assert cc.check(md, tsv, repo) == []
