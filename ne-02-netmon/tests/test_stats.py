import pytest

from netmon.stats import Sample, jitter, percentile, summarize


def s(ts, lat):
    return Sample(ts, lat is not None, lat)


def test_percentile_interpolates():
    assert percentile([10], 95) == 10
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([0, 100], 95) == 95
    assert percentile([5, 1, 3], 100) == 5  # unsorted input


def test_jitter_is_mean_absolute_consecutive_difference():
    assert jitter([10, 20, 10, 30]) == pytest.approx((10 + 10 + 20) / 3)
    assert jitter([5, 5, 5]) == 0
    assert jitter([7]) is None and jitter([]) is None


def test_summary_with_loss():
    samples = [s(0, 10), s(1, None), s(2, 30), s(3, None)]
    sm = summarize(samples)
    assert (sm.count, sm.ok_count, sm.loss_pct) == (4, 2, 50.0)
    assert (sm.avg_ms, sm.min_ms, sm.max_ms) == (20, 10, 30)
    assert sm.jitter_ms == 20  # the lost probes are skipped, not treated as zeros


def test_summary_all_lost_and_empty():
    sm = summarize([s(0, None), s(1, None)])
    assert sm.loss_pct == 100.0 and sm.avg_ms is None and sm.jitter_ms is None
    assert summarize([]).count == 0 and summarize([]).loss_pct == 0.0
