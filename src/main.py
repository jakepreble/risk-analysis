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
    amplifications = dict(getattr(result, "amplifications", {}) or {})
    meaningful_amps = [(k, float(v)) for k, v in amplifications.items() if float(v) > 0]

    if vuln_score >= 15:
        recs.append("Address elevated vulnerabilities before onboarding and request remediation evidence.")
    elif vuln_score > 0:
        recs.append("Review vulnerability findings and confirm patching expectations are documented.")

    if exposure_score >= 12:
        recs.append("Reduce unnecessary internet exposure and confirm all externally reachable services are expected.")
    elif exposure_score > 0:
        recs.append("Validate external exposure and restrict access to sensitive services where possible.")

    if meaningful_amps:
        amp_names = [k.replace("_", " ") for k, _ in sorted(meaningful_amps, key=lambda kv: kv[1], reverse=True)]
        if len(amp_names) == 1:
            recs.append(f"Address the amplification factor '{amp_names[0]}' and add compensating controls to reduce its impact.")
        else:
            recs.append(
                "Address the main amplification factors ("
                + ", ".join(amp_names[:2])
                + ") and add compensating controls to reduce their impact."
            )

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


# Score confidence based on missing or unsure answers
def _confidence_label(warnings: list[str]) -> str:
    if not warnings:
        return "HIGH"

    joined = " | ".join(warnings).lower()
    if "invalid" in joined or "missing answers" in joined or "no questions" in joined:
        return "LOW"
    return "MEDIUM"




def _print_single_report(result, warnings: list[str], show_warnings: bool) -> None:
    print("\n=== Vendor Risk Report ===")

    # Compute base + multiplier contributions
    control = float(getattr(result.control, "score", 0.0))
    exposure = float(getattr(result.exposure, "score", 0.0))
    vulns = float(getattr(result.vulnerabilities, "score", 0.0))
    amps_total = float(sum(getattr(result, "amplifications", {}).values())) if getattr(result, "amplifications", None) else 0.0
    mult = float(getattr(result.impact, "multiplier", 1.0))

    total = float(getattr(result, "total_score", 0.0))



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

    def _amplification_driver_text(amplifications: dict[str, float]) -> list[str]:
        out: list[str] = []
        for name, value in sorted(amplifications.items(), key=lambda kv: kv[1], reverse=True):
            try:
                score_val = float(value)
            except Exception:
                continue
            if score_val <= 0:
                continue

            clean = name.replace("_", " ")
            if name == "sensitive_data" or name == "sensitive_data_exposure":
                out.append(f"Amplification: sensitive data exposure increased risk ({score_val:.2f})")
            elif name == "operational_dependency":
                out.append(f"Amplification: operational dependency increased risk ({score_val:.2f})")
            elif name == "business_criticality":
                out.append(f"Amplification: business criticality increased risk ({score_val:.2f})")
            elif name == "privileged_access":
                out.append(f"Amplification: privileged access increased risk ({score_val:.2f})")
            else:
                out.append(f"Amplification: {clean} increased risk ({score_val:.2f})")
        return out

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


    if vulns >= 15:
        drivers.append(f"Vulnerabilities: elevated ({vulns:.2f})")
    elif vulns > 0:
        drivers.append(f"Vulnerabilities: present ({vulns:.2f})")


    amp_drivers = _amplification_driver_text(dict(getattr(result, "amplifications", {}) or {}))
    for d in amp_drivers[:2]:
        drivers.append(d)

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


# Markdown export helper for single-vendor report
def _export_markdown_report(result, warnings: list[str]) -> str:
    """Create a polished markdown version of the single-vendor risk report."""
    control = float(getattr(result.control, "score", 0.0))
    exposure = float(getattr(result.exposure, "score", 0.0))
    vulns = float(getattr(result.vulnerabilities, "score", 0.0))
    amps_total = float(sum(getattr(result, "amplifications", {}).values())) if getattr(result, "amplifications", None) else 0.0
    mult = float(getattr(result.impact, "multiplier", 1.0))
    total = float(getattr(result, "total_score", 0.0))

    tier = str(getattr(result, "tier", ""))
    vendor_name = str(getattr(result, "vendor_name", "Unknown Vendor"))
    confidence = _confidence_label(warnings)

    if tier == "HIGH":
        decision = "ESCALATE FOR SECURITY REVIEW"
    elif tier == "MEDIUM":
        decision = "REVIEW BEFORE APPROVAL"
    elif tier == "LOW":
        decision = "APPROVE"
    else:
        decision = "UNKNOWN"

    cat_scores = dict(getattr(result.control, "category_scores", {}) or {})
    top_cats = sorted(cat_scores.items(), key=lambda kv: kv[1], reverse=True)[:2]

    summary_parts: list[str] = []
    if exposure > 0:
        summary_parts.append("elevated external exposure")
    if vulns > 0:
        summary_parts.append("elevated vulnerability risk")
    if any(float(v) > 0 for _, v in top_cats):
        summary_parts.append("questionnaire control gaps")

    if not summary_parts:
        summary_text = "No major risk signals detected from questionnaire or external signals."
    else:
        summary_text = f"This vendor is {tier} risk due to " + ", ".join(summary_parts) + "."

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

    def _amplification_driver_text(amplifications: dict[str, float]) -> list[str]:
        out: list[str] = []
        for name, value in sorted(amplifications.items(), key=lambda kv: kv[1], reverse=True):
            try:
                score_val = float(value)
            except Exception:
                continue
            if score_val <= 0:
                continue

            clean = name.replace("_", " ")
            if name == "sensitive_data" or name == "sensitive_data_exposure":
                out.append(f"Amplification: sensitive data exposure increased risk ({score_val:.2f})")
            elif name == "operational_dependency":
                out.append(f"Amplification: operational dependency increased risk ({score_val:.2f})")
            elif name == "business_criticality":
                out.append(f"Amplification: business criticality increased risk ({score_val:.2f})")
            elif name == "privileged_access":
                out.append(f"Amplification: privileged access increased risk ({score_val:.2f})")
            else:
                out.append(f"Amplification: {clean} increased risk ({score_val:.2f})")
        return out

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

    if vulns >= 15:
        drivers.append(f"Vulnerabilities: elevated ({vulns:.2f})")
    elif vulns > 0:
        drivers.append(f"Vulnerabilities: present ({vulns:.2f})")

    for d in _amplification_driver_text(dict(getattr(result, "amplifications", {}) or {}))[:2]:
        drivers.append(d)

    if mult > 1.0:
        drivers.append(f"Business impact increased the overall score with a {mult:g}x multiplier.")

    lines: list[str] = []
    lines.append(f"# Vendor Risk Report — {vendor_name}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Vendor | {vendor_name} |")
    lines.append(f"| Total Risk Score (0-100) | {total:.2f} |")
    lines.append(f"| Risk Tier | {tier} |")
    lines.append(f"| Assessment Confidence | {confidence} |")
    lines.append(f"| Decision | {decision} |")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(summary_text)
    lines.append("")
    lines.append("## Hybrid Breakdown")
    lines.append("")
    lines.append("| Component | Value |")
    lines.append("|---|---|")
    lines.append(f"| Questionnaire controls | {control:.2f} |")
    lines.append(f"| External exposure | {exposure:.2f} |")
    lines.append(f"| Vulnerabilities | {vulns:.2f} |")
    if amps_total > 0:
        lines.append(f"| Amplifications | {amps_total:.2f} |")
    lines.append(f"| Impact multiplier | x{mult:g} |")
    lines.append("")
    lines.append("## Key Drivers")
    lines.append("")
    if drivers:
        for d in drivers[:5]:
            lines.append(f"- {d}")
    else:
        lines.append("- No dominant drivers identified.")
    lines.append("")
    lines.append("## Recommended Actions")
    lines.append("")
    for i, r in enumerate(_recommendations(result)[:3], start=1):
        lines.append(f"{i}. {r}")
    if warnings:
        lines.append("")
        lines.append("## Validation Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")

    return "\n".join(lines) + "\n"


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
    parser.add_argument("--export-md", help="Export the single vendor report to a markdown file")
    args = parser.parse_args()

    weights_path = Path(args.weights)
    weights_data = _load_json(weights_path)

    if args.vendor:
        vendor_path = Path(args.vendor)
        vendor_data = _load_json(vendor_path)
        warnings = _validate_inputs(vendor_data, weights_data)

        result = score_vendor(vendor_data, weights_data)
        _print_single_report(result, warnings, args.show_warnings)

        if args.export_md:
            md = _export_markdown_report(result, warnings)
            out_path = Path(args.export_md)
            out_path.write_text(md, encoding="utf-8")
            print(f"Markdown report written to: {out_path}")

        return 0
    

    folder_path = Path(args.folder)
    if not folder_path.exists() or not folder_path.is_dir():
        raise FileNotFoundError(f"Folder not found or not in direcory: {folder_path}")
    
    rows = _score_folder(folder_path, weights_data)
    _print_ranking(rows, args.show_warnings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())  