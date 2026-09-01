# Prompt-injection detector eval

Reusable harness for the given detector (`starter/detector.py`). Do not retrain it.

## Setup

```bash
uv sync
```

Python 3.12, `scikit-learn==1.6.1`.

## Run

Reproduce the ~92% headline and the production projection (0.5% attack rate):

```bash
uv run python -m harness.cli eval --dataset starter/eval_set.jsonl --base-rate 0.005
```

Threshold 0.9:

```bash
uv run python -m harness.cli eval --dataset starter/eval_set.jsonl --threshold 0.9 --base-rate 0.005
```

Red-team slices:

```bash
uv run python -m harness.cli eval --dataset datasets/redteam.jsonl --by-axis
```

Trade-off curve:

```bash
uv run python -m harness.cli sweep --dataset starter/eval_set.jsonl --base-rate 0.005 --plot out/curves/tradeoff.png --csv out/reports/sweep.csv
```

Tests: `uv run pytest -q`

Regenerate encoding/long-context rows: `uv run python -m redteam.transforms`

## Layout

- `harness/` — load JSONL, call `detect()`, metrics, CLI
- `redteam/` — seeds, hand-written gaps, encoding/long-context transforms
- `datasets/redteam.jsonl` — augmented eval set
- `WRITEUP.md` — deliverables 2–8
