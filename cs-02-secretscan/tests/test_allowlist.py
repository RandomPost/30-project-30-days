from secretscan.allowlist import parse_allowlist
from secretscan.scanner import scan_text

TEXT = """
# comments and blanks are fine
path:docs/*.md
rule:high-entropy-string
fp:abc123abc123   # trailing comment
bogus line
"""


def test_parse():
    a = parse_allowlist(TEXT)
    assert a.paths == ["docs/*.md"]
    assert a.rules == {"high-entropy-string"}
    assert a.fingerprints == {"abc123abc123"}


def test_allows_by_path_rule_and_fingerprint(aws_key, entropy_string):
    (aws,) = scan_text(f"id={aws_key}", "docs/guide.md")
    (ent,) = scan_text(f'x="{entropy_string}"', "src/a.py")
    assert parse_allowlist("path:docs/*.md").allows(aws)
    assert parse_allowlist("rule:high-entropy-string").allows(ent)
    assert parse_allowlist(f"fp:{ent.fingerprint}").allows(ent)
    assert not parse_allowlist("path:docs/*.md").allows(ent)
