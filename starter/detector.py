"""
Prompt-injection / jailbreak classifier (v1).

Two layers, combined by taking the higher score:
  1. A small set of high-precision regex signatures for well-known injection
     phrasings — a fast, auditable short-circuit.
  2. A TF-IDF (word 1-2 grams) + logistic-regression model (`model.joblib`), fit on
     an internal labeled corpus, for everything the signatures don't cover.

    score = max(rule_score, model P(attack))          # flagged when score >= THRESHOLD
    detect(prompt: str) -> {"label": "attack" | "benign", "score": float in [0, 1]}

Requires scikit-learn (see requirements.txt) to deserialize the model.
"""
import os
import re
import joblib

THRESHOLD = 0.5
MAX_CHARS = 2000       # prompts are scored over their first MAX_CHARS
RULE_SCORE = 0.99      # confidence assigned to an exact signature hit

# high-precision known-bad signatures (fast path)
_RULES = [
    re.compile(r"ignore (all |your |the )?(previous|prior|above) (instructions|prompts?|rules)"),
    re.compile(r"disregard (all |the )?(previous|prior|above) (instructions|prompts?|rules)"),
    re.compile(r"\bdo anything now\b"),
    re.compile(r"\bdeveloper mode\b"),
    re.compile(r"reveal (your |the )?(system )?(prompt|instructions)"),
]

_MODEL = joblib.load(os.path.join(os.path.dirname(__file__), "model.joblib"))
_ATTACK = list(_MODEL.classes_).index(1)


def detect(prompt: str) -> dict:
    text = prompt[:MAX_CHARS]
    model_score = float(_MODEL.predict_proba([text])[0][_ATTACK])
    rule_hit = any(rx.search(text.lower()) for rx in _RULES)
    score = max(model_score, RULE_SCORE if rule_hit else 0.0)
    return {"label": "attack" if score >= THRESHOLD else "benign", "score": round(score, 4)}
