from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, Tuple

@dataclass(frozen=True)
class RiskResult:
    vendor_name: str
    total_score: float
    tier: str
    category_score: Dict[str, float]

def _tier_from_score(score: float) -> str:
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    return "HIGH"

def score_vendor(vendor_name: str, responses: Dict[str, str], weights_spec: Dict[str, Any]) -> RiskResult:
    categories = weights_spec["categories"]
    questions = weights_spec["questions"]

    bucket: Dict[str, list[float]] = {c: [] for c in categories.keys()}

    for q in questions:
        qid = q["id"]
        category = q["category"]
        scoring_map = q["scoring"]

        answer = responses.get(qid, "unknown")

        points = scoring_map.get(answer, scoring_map.get("unknown", 70))

        if category not in bucket:
            bucket[category] = []
        bucket[category].append(float(points))

    category_scores: Dict[str, float] = {}
    for cat, scores in bucket.items():
        category_scores[cat] = (sum(scores) / len(scores)) if scores else 0.0

    total = 0.0
    for cat, meta in categories.items():
        w = float(meta["weight"])
        total += w * category_scores.get(cat, 0.0)

    tier = _tier_from_score(total)
    return RiskResult(
        vendor_name=vendor_name,
        total_score=round(total,2),
        tier=tier,
        category_scores={k: round(v, 2) for k, v in category_scores.items()},
    )