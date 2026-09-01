"""Call the given detector. Use score, never detect()['label'] (frozen at 0.5)."""

from __future__ import annotations

import sys
from pathlib import Path

from harness.data import Row

ROOT = Path(__file__).resolve().parent.parent
starter = str(ROOT / "starter")
if starter not in sys.path:
    sys.path.insert(0, starter)

from detector import THRESHOLD, detect  # noqa: E402

__all__ = ["THRESHOLD", "score_rows"]


def score_rows(rows: list[Row]) -> list[tuple[float, bool, str]]:
    """Return (score, is_attack, axis) for each row."""
    return [(detect(row.prompt)["score"], row.is_attack, row.axis) for row in rows]
