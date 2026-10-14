import pytest

from conftest import VULNS
from vulnreport.models import Dep
from vulnreport.severity import cvss3_score, fixed_versions, severity_of, to_finding


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_known_scores(vector, expected):
    assert cvss3_score(vector) == expected


def test_cvss_unparseable_or_v4():
    assert cvss3_score("CVSS:4.0/AV:N") is None
    assert cvss3_score("CVSS:3.1/garbage") is None


def test_severity_from_vector_label_and_unknown():
    assert severity_of(VULNS["vuln_high"]) == ("CRITICAL", 9.8)
    assert severity_of(VULNS["vuln_medium_label"]) == ("MEDIUM", None)
    assert severity_of(VULNS["vuln_low"]) == ("LOW", 3.3)
    assert severity_of({"id": "x"}) == ("UNKNOWN", None)


def test_fixed_version_matches_only_this_package():
    dep = Dep("Jinja2", "2.4.1", "PyPI")
    assert fixed_versions(VULNS["vuln_medium_label"], dep) == ("3.1.3",)
    assert fixed_versions(VULNS["vuln_medium_label"], Dep("jinja2", "1", "npm")) == ()


def test_to_finding():
    f = to_finding(VULNS["vuln_high"], Dep("jinja2", "2.4.1", "PyPI"))
    assert (f.vuln_id, f.severity, f.fixed) == (
        "GHSA-test-high-0001",
        "CRITICAL",
        ("2.11.3",),
    )
