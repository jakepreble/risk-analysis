import argparse
import json
from pathlib import Path
import re

from .engine.engine import score_vendor


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}")
    

def _validate_inputs(vendor_data: dict, weights_data: dict) -> list[str]:
    warnings: list[str] = []

    if "vendor_name" not in vendor_data or not str(vendor_data.get("vendor_name", "")).strip():
        warnings.append("missing vendor_name")

    responses = vendor_data.get("responses")
    if not isinstance(responses, dict):
        warnings.append("invalid responses type")
        return warnings
    
    questions = weights_data.get("questions", [])
    if not isinstance(questions, list) or not questions:
        warnings.append("weights file has no questions[]")
        return warnings
    
    expected_qids = [q.get("id") for q in questions if isinstance(q, dict) and q.get("id")]
    
    missing = [qid for qid in expected_qids if qid not in responses]
    if missing:
        warnings.append(f"missing answers for: {', '.join(missing)}")

    unknown = [qid for qid in expected_qids if responses.get(qid) == "unknown"]
    if unknown:
        warnings.append(f"answers marked unknown: {', '.join(unknown)}")
    
    extra = sorted([k for k in responses.keys() if k not in set(expected_qids)])
    if extra:
        warnings.append(f"unrecognized answers ignored: {', '.join(extra)}")

    return warnings


def _format_table(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return ""
    k_w = max(len(k) for k, _ in rows)
    lines: list[str] = []
    for k, v in rows:
        lines.append(f"{k.ljust(k_w)} : {v}")
    return "\n".join(lines)

def _recommendations(result) -> list[str]:
    recs: list[str] = []

    cat_scores: dict[str, float] = dict(getattr(result.control, "category_scores", {}) or {})

    def sc(cat: str) -> float:
        try:
            return float(cat_scores.get(cat, 0.0))
        except Exception:
            return 0.0

    vuln_score = float(getattr(result.vulnerabilities, "score", 0.0))
    exposure_score = float(getattr(result.exposure, "score", 0.0))
    impact_mult = float(getattr(result.impact, "multiplier", 1.0))

    if vuln_score >= 15:
        recs.append("Address elevated vulnerabilities before onboarding and request remediation evidence.")
    elif vuln_score > 0:
        recs.append("Review vulnerability findings and confirm patching expectations are documented.")

    if exposure_score >= 12:
        recs.append("Reduce unnecessary internet exposure and confirm all externally reachable services are expected.")
    elif exposure_score > 0:
        recs.append("Validate external exposure and restrict access to sensitive services where possible.")

    if impact_mult >= 1.5:
        recs.append("Because vendor impact is high, require stronger contractual and monitoring controls.")

    if sc("access_control") > 60:
        recs.append("Require stronger access controls such as MFA and SSO before onboarding.")
    if sc("data_protection") > 60:
        recs.append("Confirm encryption protections and key-management practices.")
    if sc("compliance") > 60:
        recs.append("Request current compliance evidence and clarify audit coverage.")
    if sc("incident_history") > 60:
        recs.append("Review prior incidents and consider enhanced approval before onboarding.")

    if not recs:
        recs.append("No major follow-up actions identified based on the current inputs.")

    return recs


def _confidence_label(warnings: list[str]) -> str:
    if not warnings:
        return "HIGH"

    joined = " | ".join(warnings).lower()
    # Missing/invalid answers tend to understate or destabilize the score
    if "invalid" in joined or "missing answers" in joined or "no questions" in joined:
        return "LOW"
    return "MEDIUM"

def _vuln_counts(result) -> dict[str, int]:
    """Best-effort extraction of vuln severity counts from result."""
    possible_sources: list[object] = []

    # 1) Scored result object
    v = getattr(result, "vulnerabilities", None)
    if v is not None:
        possible_sources.append(v)

    for source in possible_sources:
        # If source itself is already a severity-count dict like
        # {"critical": 1, "high": 3, "medium": 4}
        if isinstance(source, dict):
            lowered = {str(k).lower(): v for k, v in source.items()}
            if any(k in lowered for k in ("critical", "high", "medium", "low", "info")):
                out: dict[str, int] = {}
                for k, val in lowered.items():
                    try:
                        out[k] = int(val)
                    except Exception:
                        continue
                if out:
                    return out

            # Common nested shapes
            for key in ("counts", "severity_counts", "by_severity", "summary"):
                d = source.get(key)
                if isinstance(d, dict):
                    out: dict[str, int] = {}
                    for k, val in d.items():
                        try:
                            out[str(k).lower()] = int(val)
                        except Exception:
                            continue
                    if out:
                        return out

            # Findings list inside raw dict
            findings = source.get("findings") or source.get("items") or source.get("vulns")
            if isinstance(findings, list):
                out: dict[str, int] = {}
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    sev = f.get("severity") or f.get("sev") or f.get("level")
                    if sev is None:
                        continue
                    key = str(sev).lower()
                    out[key] = out.get(key, 0) + 1
                if out:
                    return out

        # Object-style result.vulnerabilities
        for attr in ("counts", "severity_counts", "by_severity", "summary"):
            d = getattr(source, attr, None)
            if isinstance(d, dict):
                out: dict[str, int] = {}
                for k, val in d.items():
                    try:
                        out[str(k).lower()] = int(val)
                    except Exception:
                        continue
                if out:
                    return out

        findings = getattr(source, "findings", None)
        if isinstance(findings, list):
            out: dict[str, int] = {}
            for f in findings:
                sev = None
                if isinstance(f, dict):
                    sev = f.get("severity") or f.get("sev") or f.get("level")
                else:
                    sev = getattr(f, "severity", None) or getattr(f, "sev", None) or getattr(f, "level", None)
                if sev is None:
                    continue
                key = str(sev).lower()
                out[key] = out.get(key, 0) + 1
            if out:
                return out

    return {}

def _format_vuln_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "(no counts available)"
    order = ["critical", "high", "medium", "low", "info"]
    parts: list[str] = []
    for k in order:
        if k in counts:
            parts.append(f"{k}={counts[k]}")
    # include any other severities
    for k in sorted([k for k in counts.keys() if k not in set(order)]):
        parts.append(f"{k}={counts[k]}")
    return ", ".join(parts)

def _exposure_threats(result, limit: int = 3) -> list[str]:
    """Best-effort extraction of exposure findings from result."""
    possible_sources: list[object] = []

    e = getattr(result, "exposure", None)
    if e is not None:
        possible_sources.append(e)

    out: list[str] = []

    for source in possible_sources:
        candidates = []

        if isinstance(source, dict):
            for key in ("threats", "findings", "signals", "exposures", "services", "ports"):
                val = source.get(key)
                if isinstance(val, list):
                    candidates = val
                    break
        else:
            for attr in ("threats", "findings", "signals", "exposures"):
                val = getattr(source, attr, None)
                if isinstance(val, list):
                    candidates = val
                    break

        for item in candidates:
            if len(out) >= limit:
                return out

            if isinstance(item, str):
                s = item.strip()
                if s:
                    out.append(s)
                continue

            if isinstance(item, dict):
                name = item.get("name") or item.get("title") or item.get("type") or item.get("signal")
                port = item.get("port")
                service = item.get("service") or item.get("protocol")
                host = item.get("host") or item.get("ip") or item.get("target")
                bits = [str(x) for x in [name, host] if x]
                if port or service:
                    bits.append(f"{service or ''}{':' if service and port else ''}{port or ''}".strip(":"))
                s = " — ".join(bits).strip()
                if s:
                    out.append(s)
                continue

            name = getattr(item, "name", None) or getattr(item, "title", None) or getattr(item, "type", None)
            if name:
                out.append(str(name))

    return out

def _print_single_report(result, warnings: list[str], show_warnings: bool) -> None:
    print("\n=== Vendor Risk Report ===")

    # Compute base + multiplier contributions
    control = float(getattr(result.control, "score", 0.0))
    exposure = float(getattr(result.exposure, "score", 0.0))
    vulns = float(getattr(result.vulnerabilities, "score", 0.0))
    amps_total = float(sum(getattr(result, "amplifications", {}).values())) if getattr(result, "amplifications", None) else 0.0
    mult = float(getattr(result.impact, "multiplier", 1.0))

    total = float(getattr(result, "total_score", 0.0))

    # --- New: vuln counts and exposure threats
    vuln_counts = _vuln_counts(result)
    exposure_threats = _exposure_threats(result, limit=3)


    def _level(score: float) -> str:
        if score >= 20:
            return "HIGH"
        if score >= 8:
            return "MODERATE"
        if score > 0:
            return "LOW"
        return "NONE"

    def _clean_category_name(name: str) -> str:
        return name.replace("_", " ").title()

    def _category_driver_text(name: str, score: float) -> str:
        if name == "compliance":
            return "Compliance gap: missing or insufficient compliance evidence"
        if name == "access_control":
            return "Access control gap: weak authentication controls"
        if name == "data_protection":
            return "Data protection gap: unclear or insufficient encryption safeguards"
        if name == "incident_history":
            return "Incident history gap: prior incidents or limited incident transparency"
        return f"Questionnaire gap: {_clean_category_name(name)} ({score:g})"

    # Header
    tier = getattr(result, "tier", "")
    tier_colored = _color_tier(tier)
    confidence = _confidence_label(warnings)

    if tier == "HIGH":
        decision = "ESCALATE FOR SECURITY REVIEW"
    elif tier == "MEDIUM":
        decision = "REVIEW BEFORE APPROVAL"
    elif tier == "LOW":
        decision = "APPROVE"
    else:
        decision = "UNKNOWN"

    header_rows = [
        ("Vendor", getattr(result, "vendor_name", "")),
        ("Total Risk Score (0-100)", f"{total}"),
        ("Risk Tier", f"{tier_colored}"),
        ("Assessment Confidence", confidence),
        ("Decision", decision),
    ]
    print(_format_table(header_rows))

    # Executive summary (1–2 lines)
    cat_scores = dict(getattr(result.control, "category_scores", {}) or {})
    top_cats = sorted(cat_scores.items(), key=lambda kv: kv[1], reverse=True)[:2]
    top_cat_str = ", ".join([f"{k} ({float(v):g})" for k, v in top_cats if float(v) > 0]) or "no major questionnaire drivers"

    summary_parts: list[str] = []
    if exposure > 0:
        summary_parts.append("elevated external exposure")
    if vulns > 0:
        summary_parts.append("elevated vulnerability risk")
    if top_cat_str != "no major questionnaire drivers":
        summary_parts.append("questionnaire control gaps")

    if not summary_parts:
        summary_text = "No major risk signals detected from questionnaire or external signals."
    else:
        summary_text = f"This vendor is {tier} risk due to " + ", ".join(summary_parts) + "."

    print("\nSummary:")
    print(f"  {summary_text}")

    # Hybrid breakdown with contribution
    print("\n" + "-" * 40)
    print("Hybrid Breakdown:")
    breakdown_rows = [
        ("Questionnaire controls", f"{control:.2f} | {_level(control)}"),
        ("External exposure", f"{exposure:.2f} | {_level(exposure)}"),
        ("Vulnerabilities", f"{vulns:.2f} | {_level(vulns)}"),
    ]
    if amps_total > 0:
        breakdown_rows.append(("Amplifications", f"{amps_total:.2f} | {_level(amps_total)}"))
    breakdown_rows.append(("Impact multiplier", f"x{mult:g}"))
    print(_format_table(breakdown_rows))

    # Key drivers (single concise section)
    print("\n" + "-" * 40)
    print("Key Drivers:")
    drivers: list[str] = []

    for k, v in top_cats:
        try:
            score_val = float(v)
        except Exception:
            continue
        if score_val > 0:
            drivers.append(_category_driver_text(k, score_val))

    if exposure >= 12:
        drivers.append(f"External exposure: elevated ({exposure:.2f})")
    elif exposure > 0:
        drivers.append(f"External exposure: present ({exposure:.2f})")

    if exposure_threats:
        for t in exposure_threats[:2]:
            drivers.append(f"Exposure finding: {t}")

    if vulns >= 15:
        drivers.append(f"Vulnerabilities: elevated ({vulns:.2f})")
    elif vulns > 0:
        drivers.append(f"Vulnerabilities: present ({vulns:.2f})")

    if vuln_counts:
        drivers.append(f"Vulnerability breakdown: {_format_vuln_counts(vuln_counts)}")

    if amps_total > 0:
        drivers.append(f"Amplifying factors increased the score by {amps_total:.2f} before impact scaling.")

    if mult > 1.0:
        drivers.append(f"Business impact increased the overall score with a {mult:g}x multiplier.")

    if not drivers:
        print("  - No dominant drivers identified.")
    else:
        for d in drivers[:6]:
            print(f"  - {d}")

    # Warnings (if requested)
    if warnings and show_warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")

    # Recommendations
    print("\n" + "-" * 40)
    print("Recommended Actions (top priorities):")
    for i, r in enumerate(_recommendations(result)[:3], start=1):
        print(f"  {i}. {r}")

    print()


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _pad_ansi(text: str, width: int) -> str:
    pad = width - _visible_len(text)
    return text if pad <= 0 else text + (" " * pad)


def _pad(text: str, width: int) -> str:
    return text if len(text) >= width else text + (" " * (width - len(text)))


def _score_folder(folder: Path, weights_data: dict) -> list[dict]:
    """Return a list of dicts: {vendor_name, score, tier, file, warnings[]}"""
    results: list[dict] = []

    files = sorted([p for p in folder.iterdir() if p.is_file() and p.suffix.lower() == ".json"])
    for path in files:
        try:
            vendor_data = _load_json(path)
            warnings = _validate_inputs(vendor_data, weights_data)
            result = score_vendor(vendor_data, weights_data)
            results.append(
                {
                    "vendor_name": result.vendor_name,
                    "score": float(result.total_score),
                    "tier": result.tier,
                    "file": str(path),
                    "warnings": warnings,
                }
            )
        except Exception as e:
            results.append(
                {
                    "vendor_name": path.stem,
                    "score": 100.0,
                    "tier": "ERROR",
                    "file": str(path),
                    "warnings": [f"failed to score: {e}"],
                }
            )
    results.sort(key=lambda r: (r["tier"] != "ERROR", r["score"]), reverse=True)
    return results

def _color_tier(tier: str) -> str:
    if tier == "HIGH":
        return f"\033[91m{tier}\033[0m"   # red
    if tier == "MEDIUM":
        return f"\033[93m{tier}\033[0m"   # yellow
    if tier == "LOW":
        return f"\033[92m{tier}\033[0m"   # green
    return tier

def _print_ranking(rows: list[dict], show_warnings: bool) -> None:
    print("\n=== Vendor Risk Ranking ===\n")

    if not rows:
        print("No vendor JSON files found.")
        print()
        return

    # Summary counts
    high_count = sum(1 for r in rows if r.get("tier") == "HIGH")
    medium_count = sum(1 for r in rows if r.get("tier") == "MEDIUM")
    low_count = sum(1 for r in rows if r.get("tier") == "LOW")
    error_count = sum(1 for r in rows if r.get("tier") == "ERROR")

    summary = f"{len(rows)} vendors scored | {high_count} HIGH | {medium_count} MEDIUM | {low_count} LOW"
    if error_count:
        summary += f" | {error_count} ERROR"

    print(summary)
    print()

    name_w = max(10, min(28, max(len(r["vendor_name"]) for r in rows)))

    # Header
    header = f"{'#':<3}  {_pad('Vendor', name_w)}  {'Score':>6}  {'Tier':<6}  File"
    print(header)
    print("-" * len(header))

    for i, r in enumerate(rows, start=1):
        vendor = _pad(r["vendor_name"], name_w)
        score = f"{r['score']:.2f}" if r["tier"] != "ERROR" else "--"
        tier = _pad_ansi(_color_tier(r["tier"]), 6)
        file_short = Path(r["file"]).name
        print(f"{i:<3}  {vendor}  {score:>6}  {tier}  {file_short}")

        if show_warnings and r.get("warnings"):
            for w in r["warnings"]:
                print(f"        └─ {w}")
    print()




def main() -> int:
    parser = argparse.ArgumentParser(description="Vendor Risk Assessment CLI")

    mode = parser.add_mutually_exclusive_group(required=True)
    
    mode.add_argument("--vendor", help="Path to vendor response JSON (e.g., data/sample_vendor.json)")
    mode.add_argument("--folder", help="Folder containing vendor JSON files to compare")
    parser.add_argument("--weights", default="data/risk_weights.json", help="Path to risk weights JSON")
    parser.add_argument("--show-warnings", action="store_true", help="Print validation warnings")
    args = parser.parse_args()

    weights_path = Path(args.weights)
    weights_data = _load_json(weights_path)

    if args.vendor:
        vendor_path = Path(args.vendor)
        vendor_data = _load_json(vendor_path)
        warnings = _validate_inputs(vendor_data, weights_data)

        result = score_vendor(vendor_data, weights_data)
        _print_single_report(result, warnings, args.show_warnings)
        return 0
    

    folder_path = Path(args.folder)
    if not folder_path.exists() or not folder_path.is_dir():
        raise FileNotFoundError(f"Folder not found or not in direcory: {folder_path}")
    
    rows = _score_folder(folder_path, weights_data)
    _print_ranking(rows, args.show_warnings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())  