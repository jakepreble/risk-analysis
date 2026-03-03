from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

@dataclass(frozen=True)
class ImpactModel:
    multiplier: float
    details: Dict[str, Any]

def impact_multiplier(data_profile: Dict[str, Any]) -> ImpactModel:

    if not isinstance(data_profile, dict) or not data_profile:
        return ImpactModel(multiplier=1.0, details={"reason": "no data profile"})
    
    details: Dict[str, Any] = {}
    mult = 1.0

    handles_pii = bool(data_profile.get("handles_pii"))
    handles_financial = bool(data_profile.get("handles_financials"))

    details["handles_pii"] = handles_pii
    details["handles_financials"] = handles_financial

    if handles_pii:
        mult += 0.2
    if handles_financial:
        mult += 0.3

    try:
        records = int(data_profile.get("records_estimate", 0))
    except Exception:
        records = 0
    details["records_estimate"] = records

    if records >= 500_000:
        mult += 0.2
        details["records_penalty"] = 0.2
    elif records >= 100_000:
        mult += 0.1
        details["records_penalty"] = 0.1
    else:
        details ["records_penalty"] = 0.0

    return ImpactModel(multiplier=round(mult, 2), details=details)