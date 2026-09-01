"""Core identities: confusion counts and base-rate projection."""

import pytest

from harness.metrics import confusion_at, precision_at_base_rate, project, sweep

FIXTURE = [
    (0.9, True),
    (0.8, True),
    (0.6, False),
    (0.4, True),
    (0.2, False),
    (0.1, False),
]


def test_confusion_at_midpoint():
    c = confusion_at(FIXTURE, 0.5)
    assert (c.tp, c.fp, c.tn, c.fn) == (2, 1, 2, 1)
    assert c.recall == pytest.approx(2 / 3)
    assert c.fpr == pytest.approx(1 / 3)


def test_sweep_matches_confusion_at():
    for point in sweep(FIXTURE):
        assert point.confusion == confusion_at(FIXTURE, point.threshold)


def test_base_rate_half_matches_measured_precision():
    scored = [(0.9, True)] * 455 + [(0.1, True)] * 45 + [(0.9, False)] * 30 + [(0.1, False)] * 470
    c = confusion_at(scored, 0.5)
    assert precision_at_base_rate(c.tpr, c.fpr, 0.5) == pytest.approx(c.precision)
    assert project(c, base_rate=0.5)["precision"] == pytest.approx(455 / 485)


def test_production_projection():
    scored = [(0.9, True)] * 455 + [(0.1, True)] * 45 + [(0.9, False)] * 30 + [(0.1, False)] * 470
    p = project(confusion_at(scored, 0.5), base_rate=0.005, volume=1_000_000)
    assert p["attacks_caught"] == pytest.approx(4550)
    assert p["legitimate_blocked"] == pytest.approx(59700)
    assert p["precision"] == pytest.approx(0.070817, abs=1e-6)
