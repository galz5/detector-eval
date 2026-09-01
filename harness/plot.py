"""One trade-off figure: recall vs FPR, and production precision vs recall."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from harness.metrics import SweepPoint, precision_at_base_rate


def plot_tradeoff(points: Sequence[SweepPoint], path: Path, *, base_rate: float) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    recalls = [p.confusion.recall for p in points]
    fprs = [p.confusion.fpr for p in points]
    projected = [
        precision_at_base_rate(p.confusion.tpr, p.confusion.fpr, base_rate) for p in points
    ]

    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 4.5))
    left.plot(fprs, recalls)
    left.set_xscale("symlog", linthresh=1e-3)
    left.set_xlabel("false positive rate")
    left.set_ylabel("recall")
    left.set_title("Detection vs cost to legitimate users")
    left.grid(alpha=0.3)

    right.plot(recalls, projected)
    right.set_xlabel("recall")
    right.set_ylabel(f"precision at {base_rate:.2%} base rate")
    right.set_title("Production precision-recall")
    right.grid(alpha=0.3)

    for i, p in enumerate(points):
        if p.threshold <= 0.5:
            left.plot(fprs[i], recalls[i], "o", color="crimson")
            left.annotate("default 0.5", (fprs[i], recalls[i]), xytext=(8, -12), textcoords="offset points", color="crimson")
            right.plot(recalls[i], projected[i], "o", color="crimson")
            right.annotate(f"default 0.5\n{projected[i]:.1%}", (recalls[i], projected[i]), xytext=(-70, 8), textcoords="offset points", color="crimson")
            break

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)
