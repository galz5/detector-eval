"""Metrics over (score, is_attack) pairs. No detector or sklearn imports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple, Sequence

DEFAULT_BASE_RATE = 0.005
DEFAULT_VOLUME = 1_000_000

Scored = Sequence[tuple[float, bool]]


def _div(num: float, den: float) -> float:
    return num / den if den else 0.0


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def actual_positives(self) -> int:
        return self.tp + self.fn

    @property
    def actual_negatives(self) -> int:
        return self.fp + self.tn

    @property
    def accuracy(self) -> float:
        return _div(self.tp + self.tn, self.n)

    @property
    def recall(self) -> float:
        return _div(self.tp, self.actual_positives)

    @property
    def tpr(self) -> float:
        return self.recall

    @property
    def fpr(self) -> float:
        return _div(self.fp, self.actual_negatives)

    @property
    def precision(self) -> float:
        return _div(self.tp, self.tp + self.fp)


class SweepPoint(NamedTuple):
    threshold: float
    confusion: Confusion


def confusion_at(scored: Scored, threshold: float) -> Confusion:
    tp = fp = tn = fn = 0
    for score, is_attack in scored:
        flagged = score >= threshold
        if is_attack and flagged:
            tp += 1
        elif is_attack:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return Confusion(tp=tp, fp=fp, tn=tn, fn=fn)


def sweep(scored: Scored) -> list[SweepPoint]:
    if not scored:
        return []
    ordered = sorted(scored, key=lambda row: -row[0])
    positives = sum(1 for _, is_attack in ordered if is_attack)
    negatives = len(ordered) - positives
    points: list[SweepPoint] = []
    tp = fp = 0
    for index, (score, is_attack) in enumerate(ordered):
        if is_attack:
            tp += 1
        else:
            fp += 1
        if index + 1 == len(ordered) or ordered[index + 1][0] != score:
            points.append(
                SweepPoint(
                    score,
                    Confusion(tp=tp, fp=fp, tn=negatives - fp, fn=positives - tp),
                )
            )
    return points


def precision_at_base_rate(tpr: float, fpr: float, base_rate: float) -> float:
    """P = (p * TPR) / (p * TPR + (1-p) * FPR). TPR/FPR are prior-independent."""
    if not 0.0 <= base_rate <= 1.0:
        raise ValueError(f"base_rate must be in [0, 1], got {base_rate}")
    tp = base_rate * tpr
    fp = (1.0 - base_rate) * fpr
    return _div(tp, tp + fp)


def project(
    confusion: Confusion,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    volume: int = DEFAULT_VOLUME,
) -> dict:
    attacks = volume * base_rate
    benign = volume * (1.0 - base_rate)
    tp = attacks * confusion.tpr
    fp = benign * confusion.fpr
    return {
        "base_rate": base_rate,
        "volume": volume,
        "tpr": confusion.tpr,
        "fpr": confusion.fpr,
        "precision": precision_at_base_rate(confusion.tpr, confusion.fpr, base_rate),
        "attacks_caught": tp,
        "attacks_missed": attacks * (1.0 - confusion.tpr),
        "legitimate_blocked": fp,
        "total_flags": tp + fp,
    }


def recall_at_max_fpr(scored: Scored, max_fpr: float) -> SweepPoint | None:
    best: SweepPoint | None = None
    for point in sweep(scored):
        if point.confusion.fpr <= max_fpr:
            if best is None or point.confusion.recall > best.confusion.recall:
                best = point
    return best
