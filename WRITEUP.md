# Can we ship this detector?

**Verdict: don't-ship as an inline blocker. Shadow-only, with conditions, if product insists on rolling something out.**

The given detector scores **92.5% accuracy** on `starter/eval_set.jsonl` at threshold 0.5. That number is real and reproducible. It does not describe production risk.

Assumed product context: **inline guardrail on every LLM request** (the brief). False positive = a paying user is blocked. False negative = an injection reaches the model. Those costs are not equal, and attacks are **well under 1%** of traffic. I use **0.5%** as the working base rate.

---

## 2. The right metric

**Reject accuracy.** The eval set is 500/500. Production is not. Accuracy mixes two error types and hides the prior.

What we report:

| Metric | Why |
|---|---|
| **Recall (TPR)** | Share of attacks caught |
| **FPR** | Share of legitimate traffic blocked |
| **Precision at the real base rate** | Share of flags that are real attacks |
| **Recall at a max FPR** | Operating point: fix user cost, then ask what coverage you get |

TPR and FPR do not depend on how common attacks are. Precision does:

```
precision(p) = (p × TPR) / (p × TPR + (1 − p) × FPR)
```

Cost asymmetry (this product): blocking a normal request is user-visible and frequent; a missed injection is serious but rare. So we **do not** optimize accuracy. We pick a **maximum tolerable FPR**, then take the highest recall that stays under it.

---

## 3. Base-rate reality check

On the given set, threshold **0.5**:

| | pred attack | pred benign |
|---|---|---|
| actual attack | 455 | 45 |
| actual benign | 30 | 470 |

TPR = **0.91**, FPR = **0.06**, accuracy = **0.925**, precision *on this set* = **0.938**.

At **0.5% attacks**, per million requests:

| Outcome | Count |
|---|---|
| Attacks caught | 4,550 |
| Attacks missed | 450 |
| Legitimate blocked | **59,700** |
| **Precision** | **7.08%** (1 real attack per ~14 flags) |

That is what “92% accuracy” becomes.

At threshold **0.90** on the same set: TPR **0.898**, FPR **0.002**, projected precision **69%**, ~1,990 legitimate blocks per million. The model’s *ranking* is decent; **0.5 is the wrong knob**.

---

## 4. Red-team: which axes break it

Grew the set along the brief’s axes (encodings via code; paraphrase / non-English / benign-but-scary / indirect by hand). Labels kept; duplicates avoided. File: `datasets/redteam.jsonl` (181 rows).

Recall / FPR at threshold **0.5**:

| Axis | n | Recall | FPR |
|---|---|---|---|
| seed (plain, not from eval_set) | 22 | 0.83 | 0.00 |
| paraphrase | 8 | 1.00 | 0.00 |
| non_english | 8 | 0.80 | 0.00 |
| indirect (injection in a document) | 3 | 1.00 | 0.00 |
| base64 / rot13 / leetspeak / zero_width | 22 each | **0.00** | 0.00 |
| homoglyph | 22 | 0.17 | 0.00 |
| long_context (payload after 2000 chars) | 22 | 1.00* | **1.00*** |
| benign_scary | 8 | — | **0.75** |

\*Not detection: `detector.py` scores only the first **2000** characters. The buried payload is never seen. Attack and benign long docs all scored **0.86** on this filler — above 0.5 — so everything long is blocked. At threshold **0.90** long_context recall and FPR both go to **0** (payload still invisible; filler no longer flags).

At **0.90**, encodings stay at recall **0**. Paraphrase drops to **0.25**. Benign-scary FPR stays **0.75** (regex still fires).

**Breaks:** encodings, truncation/long context, benign language that quotes attacks (`developer mode`, “ignore previous instructions” in a class/bug-report). **Does not prove robustness:** paraphrase/non-English looked easy on a tiny hand set; do not treat those as green.

---

## 5. Threshold calibration

Sweep on the original set (`out/curves/tradeoff.png`, `out/reports/sweep.csv`):

| Max FPR | Threshold | Recall | Precision @ 0.5% |
|---|---|---|---|
| 5% | 0.85 | 0.91 | 28% |
| 1% / 0.5% | **0.90** | **0.90** | **69%** |
| 0.1% / 0% | 0.99 | 0.41 | 100% |

The cliff at ~0.99 is a **regex hit**: `\bdeveloper mode\b` flags *“How do I enable developer mode in Chrome?”* at score **0.99**. You cannot tune that FP away without going above 0.99 and dumping recall.

**Operating point for this product:** do **not** block at 0.5. If anything is automated, **~0.90** is the least-bad point *on the original set*. It is **not** safe on the red-team set (encodings still miss; benign-scary still flags).

**Per tenant:** a bank-like tenant wants a higher threshold (or review queue). An internal tool can accept more FPR. Do not ship one global 0.5.

A mid-band “review” queue between 0.6 and 0.9 on this eval set is almost all noise (~55k reviews per million for ~60 extra attacks). Not worth staffing from this data.

---

## 6. Drift and monitoring (design only)

Production has no labels. Catch degradation before users do:

1. **Flag rate per tenant** vs a baseline after launch. Spikes = new FP mode or attack campaign.
2. **Score histogram** (mean, p50, p90). Shift without traffic mix change = drift.
3. **Sample unflagged traffic**, not only flags. Sampling only alerts hides false negatives forever.
4. **User appeals** (“why was I blocked?”) as a labeled FP stream.
5. **Scheduled eval** on a frozen holdout *and* a refreshed red-team set (encodings, long docs, quoted attacks).
6. **Shadow first:** log `score` and would-block; do not enforce until flag rate and sampled FN/FP are acceptable.

---

## 7. Verdict

**Don't-ship** as an inline block on every request.

**Conditions if forced to put something in the path:**

- Shadow / log only until the red-team gaps are closed.
- Never use threshold 0.5 for blocking.
- Treat regex hits as **advisory**, not auto-block (or drop `\bdeveloper mode\b` until it is scoped).
- Do not claim coverage of encoded or over-length payloads; `MAX_CHARS = 2000` is a hard miss.

**Residual risk:** obfuscated injections pass; long RAG/docs are either all blocked or all ignored depending on threshold; security-adjacent benign prompts get hit by signatures.

---

## 8. Next steps (order)

| # | Area | Action | Why first | Effort / impact |
|---|---|---|---|---|
| 1 | **Eval** | Freeze this holdout; stop using 50/50 accuracy as a ship gate | Stops the wrong headline | Low / high |
| 2 | **Data** | Grow benign-scary + encodings + long-context with real tenant-like docs | Current set cannot see these failures | Med / high |
| 3 | **Detector** | Fix truncation (score the tail or chunk); don't `max()` regex to 0.99 | Unblockable FPs and invisible payloads | Med / high |
| 4 | **Monitoring** | Shadow + per-tenant flag rate + unlabeled sampling | Catch the next miss in prod | Med / high |
| 5 | Retrain | Only after the eval set is honest | Retraining on the current set would overfit templates | High / unknown |

With more time: larger labeled red-team, per-layer metrics in the harness, tenant-specific thresholds from shadow data — marked as out of this 3–4h scope.

---

## How to run

See [README.md](README.md). Numbers above come from:

```bash
uv run python -m harness.cli eval --dataset starter/eval_set.jsonl --base-rate 0.005
uv run python -m harness.cli eval --dataset datasets/redteam.jsonl --by-axis
uv run python -m harness.cli sweep --dataset starter/eval_set.jsonl --plot out/curves/tradeoff.png
```
