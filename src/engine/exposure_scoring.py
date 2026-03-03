from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

@dataclass(frozen=True)
class ExposureScore:
    score: float
    details: Dict[str, Any]

def _ports_set(open_ports: Any) -> Set[int]:
    if not isinstance(open_ports, list):
        return set()
    ports: Set[int] = set()
    for p in open_ports:
        try:
            ports.add(int(p))
        except Exception:
            pass
    return ports

def score_exposure(external_scan: Dict[str, Any]) -> ExposureScore:

    if not isinstance(external_scan, dict) or not external_scan:
        return ExposureScore(score=0.0, details={"reason", "no external scan data"})
    
    details: Dict[str, Any] = {}
    score = 0.0

    ports = _ports_set(external_scan.get("open_ports", []))
    details["open_ports"] = sorted(list(ports))

    if 22 in ports: #SSH
        score += 10
        details["ssh_exposed_penalty"] = 10
    if 3389 in ports: #RDP
        score += 20
        details["rdp_exposed_penalty"] = 20
    
    # Admin/critical exposed services
    try:
        cse = float(external_scan.get("critical_services_exposed", 0))
    except Exception:
        cse = 0.0
    details["critical_services_exposed"] = cse
    score += 10 * cse
    details["critical_services_exposed"] = 10 * cse

    # TLS grade
    tls_grade = str(external_scan.get("tls_grade", "A")).upper().strip()
    details["tls_grade"] = tls_grade
    if tls_grade in {"C", "D", "E", "F"}:
        score += 10
        details["tls_penalty"] = 10
    elif tls_grade == "B":
        score += 3
        details["tls_penalty"] = 3
    else:
        details["tls_penalty"] = 0

    # Missing security headers
    try:
        shm = float(external_scan.get("security_headers_missing", 0))
    except Exception:
        shm = 0.0
    details["security_headers_missing"] = shm
    header_penalty = min(10.0, shm * 2.0)
    score += header_penalty
    details["security_headers_penalty"] = header_penalty

    return ExposureScore(score=round(score, 2), details=details)

