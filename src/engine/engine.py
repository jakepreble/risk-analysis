from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Set

from .control_scoring import ControlScore, score_controls
from .exposure_scoring import ExposureScore, score_exposure
from .impact_model import ImpactModel, impact_multiplier
from .vulnerability_scoring import VulnerabilityScore, score_vul

@dataclass(frozen=True)
class RiskResult:
    vendor_name: str
    total_score: float
    tier: str

    control: ControlScore
    exposure: ExposureScore
    vulnerabilities: VulnerabilityScore
    impact: ImpactModel
    amplifications: Dict[str, float]

def tier_from_score(score: float) -> str:
    if score <= 30:
        return "LOW"
    if score <= 65:
        return "MEDIUM"
    return "HIGH"

def _ports(open_ports: Any) -> Set[int]:
    if not isinstance(open_ports, list):
        return set()
    s: Set[int] = set()
    for p in open_ports:
        try:
            s.add(int(p))
        except Exception:
            pass
    return s

def score_vendor(vendor_data: Dict[str, Any], weights_spec: Dict[str, Any]) -> RiskResult:
    vendor_name = str(vendor_data.get("vendor_name", "(unknown vendor)"))

    responses = vendor_data.get("responses", {})
    external_scan = vendor_data.get("external_scan", {})
    vulns = vendor_data.get("vulnerabilities", {})
    data_profile = vendor_data.get("data_profile", {})

    if not isinstance(responses, dict):
        responses = {}
    if not isinstance(external_scan, dict):
        external_scan = {}
    if not isinstance(vulns, dict):
        vulns = {}
    if not isinstance(data_profile, dict):
        data_profile = {}

    control = score_controls(responses, weights_spec)
    exposure = score_exposure(external_scan)
    vulnerabilities = score_vul(vulns)
    impact = impact_multiplier(data_profile)

    base = float(control.score) + float(exposure.score) + float(vulnerabilities.score)

    amplifications: Dict[str, float] = {}
    ports = _ports(external_scan.get("open_ports", []))

    try:
        max_cvss = float(vulns.get("max_cvss", 0.0))
    except Exception:
        max_cvss = 0.0
    if max_cvss >= 9.0 and 3389 in ports:
        amplifications["critical_cvss_and_open_rdp"] = 20.0

    tls_grade = str(external_scan.get("tls_grade", "A")).upper().strip()
    if tls_grade in {"C", "D", "E", "F"} and bool(data_profile.get("handles_pii")):
        amplifications["weak_tls_plus_pii"] = 8.0

    try:
        critical_cves = int(vulns.get("critical_cves", 0))
    except Exception:
        critical_cves = 0
    if responses.get("breach_3y") == "yes" and critical_cves > 0:
        amplifications["breach_plus_critical_cves"] = 10.0

    base += sum(amplifications.values())

    final = base * float(impact.multiplier)
    final = max(0.0, min(100.0, round(final, 2)))

    return RiskResult(
        vendor_name=vendor_name,
        total_score=final,
        tier=tier_from_score(final),
        control=control,
        exposure=exposure,
        vulnerabilities=vulnerabilities,
        impact=impact,
        amplifications=amplifications,
    )