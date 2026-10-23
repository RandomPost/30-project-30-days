from pathlib import Path

import pytest

from pcaplens import samples
from pcaplens.analyze import analyze
from pcaplens.detect import detect_all
from pcaplens.reader import read_packets

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "samples" / "public"


@pytest.fixture(scope="session")
def sample_files(tmp_path_factory):
    return samples.make_samples(tmp_path_factory.mktemp("pcaps"))


@pytest.fixture(scope="session")
def run(sample_files):
    """name -> (packets, analysis, findings) for each crafted capture."""
    out = {}
    for name, path in sample_files.items():
        pk = list(read_packets(path))
        a = analyze(pk)
        out[name] = (pk, a, detect_all(pk, a))
    return out


def kinds(findings):
    return {(f.kind, f.subject) for f in findings}
