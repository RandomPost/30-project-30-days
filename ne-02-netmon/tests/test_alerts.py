from netmon.alerts import AlertTracker, Thresholds
from netmon.stats import Sample


def feed(tracker, latencies, start=0):
    events = []
    for i, lat in enumerate(latencies, start=start):
        events += tracker.add(Sample(float(i), lat is not None, lat))
    return events


def test_no_alerts_on_healthy_link():
    t = AlertTracker(Thresholds(window=5))
    assert feed(t, [10, 11, 10, 12, 11, 10, 11, 12]) == []


def test_waits_for_evidence_before_judging():
    t = AlertTracker(Thresholds(window=10, max_loss_pct=20))
    assert feed(t, [None, None, None]) == []  # 3 probes is too few to call it
    assert [str(e) for e in feed(t, [None, None], start=3)] == [
        "ALERT loss 100.0% (limit 20%)"
    ]


def test_alert_fires_once_then_recovers_once():
    t = AlertTracker(Thresholds(window=4, max_loss_pct=40))
    events = feed(t, [10] * 4 + [None] * 4 + [10] * 4)
    assert [(e.state, e.metric) for e in events] == [
        ("ALERT", "loss"),
        ("RECOVERED", "loss"),
    ]


def test_latency_and_jitter_alerts():
    t = AlertTracker(Thresholds(window=5, max_latency_ms=100, max_jitter_ms=50))
    events = feed(t, [10, 300, 10, 300, 10])
    metrics = {(e.state, e.metric) for e in events}
    assert ("ALERT", "jitter") in metrics and ("ALERT", "latency") in metrics


def test_threshold_is_strictly_greater_than():
    t = AlertTracker(Thresholds(window=5, max_latency_ms=100))
    assert feed(t, [100] * 5) == []  # equal to the limit is not over it


def test_all_lost_window_does_not_crash_latency_checks():
    t = AlertTracker(Thresholds(window=5))
    events = feed(t, [None] * 6)
    assert [e.metric for e in events] == ["loss"]
