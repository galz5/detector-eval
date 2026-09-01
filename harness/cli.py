"""CLI: score a dataset, report metrics, optionally sweep thresholds.

    uv run python -m harness.cli eval --dataset starter/eval_set.jsonl --base-rate 0.005
    uv run python -m harness.cli sweep --dataset starter/eval_set.jsonl --plot out/curves/tradeoff.png
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from harness.data import load_many
from harness.metrics import (
    DEFAULT_BASE_RATE,
    DEFAULT_VOLUME,
    confusion_at,
    precision_at_base_rate,
    project,
    recall_at_max_fpr,
    sweep,
)
from harness.score import THRESHOLD, score_rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eval")
    subs = parser.add_subparsers(dest="command", required=True)

    ev = subs.add_parser("eval", help="confusion matrix + base-rate projection")
    ev.add_argument("--dataset", nargs="+", required=True, type=Path)
    ev.add_argument("--threshold", type=float, default=THRESHOLD)
    ev.add_argument("--base-rate", type=float, default=DEFAULT_BASE_RATE)
    ev.add_argument("--volume", type=int, default=DEFAULT_VOLUME)
    ev.add_argument("--by-axis", action="store_true")
    ev.add_argument("--json", type=Path)

    sw = subs.add_parser("sweep", help="threshold trade-off")
    sw.add_argument("--dataset", nargs="+", required=True, type=Path)
    sw.add_argument("--base-rate", type=float, default=DEFAULT_BASE_RATE)
    sw.add_argument("--volume", type=int, default=DEFAULT_VOLUME)
    sw.add_argument("--csv", type=Path)
    sw.add_argument("--plot", type=Path)
    sw.add_argument(
        "--fpr-budget",
        nargs="+",
        type=float,
        default=[0.05, 0.01, 0.005, 0.001, 0.0],
    )
    return parser


def _pairs(scored: list[tuple[float, bool, str]]) -> list[tuple[float, bool]]:
    return [(score, is_attack) for score, is_attack, _ in scored]


def cmd_eval(args: argparse.Namespace) -> int:
    scored = score_rows(load_many(args.dataset))
    pairs = _pairs(scored)
    c = confusion_at(pairs, args.threshold)
    proj = project(c, base_rate=args.base_rate, volume=args.volume)

    print(f"dataset      {', '.join(str(p) for p in args.dataset)}  n={c.n}  threshold={args.threshold}")
    print()
    print("                 pred attack   pred benign")
    print(f"  actual attack  {c.tp:>11}   {c.fn:>11}")
    print(f"  actual benign  {c.fp:>11}   {c.tn:>11}")
    print()
    print(f"accuracy     {c.accuracy:.4f}   (headline on this set)")
    print(f"recall/TPR   {c.recall:.4f}   ({c.tp}/{c.actual_positives} attacks caught)")
    print(f"FPR          {c.fpr:.4f}   ({c.fp}/{c.actual_negatives} benign flagged)")
    print(f"precision    {c.precision:.4f}   on this set's prior — not production")
    print()
    print(f"Projected onto {proj['volume']:,} requests at {proj['base_rate']:.2%} attack rate:")
    print(f"  attacks caught            {proj['attacks_caught']:>10,.0f}")
    print(f"  attacks missed            {proj['attacks_missed']:>10,.0f}")
    print(f"  legitimate blocked        {proj['legitimate_blocked']:>10,.0f}")
    print(f"  production precision      {proj['precision']:>10.2%}")

    axis_rows = None
    if args.by_axis:
        print()
        print(f"  {'axis':<16}{'n':>5}{'recall':>9}{'fpr':>8}")
        grouped: dict[str, list[tuple[float, bool]]] = defaultdict(list)
        for score, is_attack, axis in scored:
            grouped[axis].append((score, is_attack))
        axis_rows = []
        for axis in sorted(grouped):
            ac = confusion_at(grouped[axis], args.threshold)
            print(f"  {axis:<16}{ac.n:>5}{ac.recall:>9.3f}{ac.fpr:>8.3f}")
            axis_rows.append(
                {"axis": axis, "n": ac.n, "recall": ac.recall, "fpr": ac.fpr, "tp": ac.tp, "fp": ac.fp, "fn": ac.fn, "tn": ac.tn}
            )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "datasets": [str(p) for p in args.dataset],
            "threshold": args.threshold,
            "tp": c.tp,
            "fp": c.fp,
            "tn": c.tn,
            "fn": c.fn,
            "accuracy": c.accuracy,
            "recall": c.recall,
            "fpr": c.fpr,
            "precision_on_this_set": c.precision,
            "projection": proj,
            "by_axis": axis_rows,
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nwrote {args.json}")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    pairs = _pairs(score_rows(load_many(args.dataset)))
    points = sweep(pairs)
    print(f"{len(points)} operating points  n={len(pairs)}  base-rate={args.base_rate:.2%}")
    print()
    print(f"  {'FPR budget':>11}{'threshold':>11}{'recall':>9}{'proj. prec':>12}")
    for budget in args.fpr_budget:
        best = recall_at_max_fpr(pairs, budget)
        if best is None:
            print(f"  {budget:>11.4f}{'n/a':>11}")
            continue
        prec = precision_at_base_rate(best.confusion.tpr, best.confusion.fpr, args.base_rate)
        print(f"  {budget:>11.4f}{best.threshold:>11.4f}{best.confusion.recall:>9.4f}{prec:>12.2%}")

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["threshold", "tp", "fp", "tn", "fn", "recall", "fpr", "projected_precision"],
            )
            writer.writeheader()
            for point in points:
                writer.writerow(
                    {
                        "threshold": point.threshold,
                        "tp": point.confusion.tp,
                        "fp": point.confusion.fp,
                        "tn": point.confusion.tn,
                        "fn": point.confusion.fn,
                        "recall": point.confusion.recall,
                        "fpr": point.confusion.fpr,
                        "projected_precision": precision_at_base_rate(
                            point.confusion.tpr, point.confusion.fpr, args.base_rate
                        ),
                    }
                )
        print(f"\nwrote {args.csv}")

    if args.plot:
        from harness.plot import plot_tradeoff

        plot_tradeoff(points, args.plot, base_rate=args.base_rate)
        print(f"wrote {args.plot}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "eval":
        return cmd_eval(args)
    if args.command == "sweep":
        return cmd_sweep(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
