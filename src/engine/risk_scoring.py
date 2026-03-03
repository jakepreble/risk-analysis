from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class RiskResult:
    vendor_name: str
    total_score: float
    tier: str
    category_score: Dict[str, float]

    @property
    def category_scores(self) -> Dict[str, float]:
        return self.category_score


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

        bucket.setdefault(category, []).append(float(points))

    category_scores: Dict[str, float] = {}
    for cat, scores in bucket.items():
        category_scores[cat] = (sum(scores) / len(scores)) if scores else 0.0

    total = 0.0
    for cat, meta in categories.items():
        total += float(meta["weight"]) * category_scores.get(cat, 0.0)

    return RiskResult(
        vendor_name=vendor_name,
        total_score=round(total, 2),
        tier=_tier_from_score(total),
        category_score={k: round(v, 2) for k, v in category_scores.items()},
    )