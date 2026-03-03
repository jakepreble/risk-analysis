from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass(frozen=True)
class ControlScore:
    score: float                      
    category_scores: Dict[str, float] 
    details: Dict[str, Any]


def score_controls(responses: Dict[str, str], weights_spec: Dict[str, Any]) -> ControlScore:
    categories = weights_spec.get("categories", {})
    questions = weights_spec.get("questions", [])

    bucket: Dict[str, List[float]] = {c: [] for c in categories.keys()}
    answered: Dict[str, str] = {}

    for q in questions:
        if not isinstance(q, dict):
            continue
        qid = q.get("id")
        cat = q.get("category")
        scoring_map = q.get("scoring", {})
        if not qid or not cat or not isinstance(scoring_map, dict):
            continue

        ans = responses.get(qid, "unknown")
        pts = scoring_map.get(ans, scoring_map.get("unknown", 70))
        bucket.setdefault(cat, []).append(float(pts))
        answered[qid] = ans

    category_scores: Dict[str, float] = {}
    for cat, scores in bucket.items():
        category_scores[cat] = (sum(scores) / len(scores)) if scores else 0.0

    total = 0.0
    for cat, meta in categories.items():
        w = float(meta.get("weight", 0.0))
        total += w * category_scores.get(cat, 0.0)

    if responses.get("breach_3y") == "yes":
        total = max(total, 70.0)

    return ControlScore(
        score=round(total, 2),
        category_scores={k: round(v, 2) for k, v in category_scores.items()},
        details={"answered": answered},
    )