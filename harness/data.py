"""Load JSONL rows: prompt, label, optional axis."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

LABELS = {"attack": True, "benign": False}


@dataclass(frozen=True)
class Row:
    prompt: str
    is_attack: bool
    axis: str = "original"


def load_jsonl(path: Path | str, *, default_axis: str = "original") -> list[Row]:
    path = Path(path)
    rows: list[Row] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        obj = json.loads(line)
        prompt = obj.get("prompt")
        label = obj.get("label")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"{path}:{lineno}: missing prompt")
        if label not in LABELS:
            raise ValueError(f"{path}:{lineno}: label must be attack or benign")
        rows.append(
            Row(
                prompt=prompt,
                is_attack=LABELS[label],
                axis=obj.get("axis") or default_axis,
            )
        )
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def load_many(paths: Sequence[Path | str]) -> list[Row]:
    rows: list[Row] = []
    for path in paths:
        rows.extend(load_jsonl(path))
    return rows
