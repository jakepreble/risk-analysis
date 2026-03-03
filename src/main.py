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
    """Return a list of warning messages."""
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
    return "\n".join([f"{k.ljust(k_w)} : {v}" for k, v in rows])

def _recommendations(category_scores: dict[str, float]) -> list[str]:
    """Simple category-based recommendations."""
    recs: list[str] = []

    def sc(cat: str) -> float:
        return float(category_scores.get(cat, 0.0))

    if sc("access_control") > 60:
        recs.append("Require organization-wide MFA and SSO/SAML support before onboarding.")
    if sc("data_protection") > 60:
        recs.append("Confirm encryption at rest/in transit and request details on key management.")
    if sc("compliance") > 60:
        recs.append("Request current SOC 2 Type II and clarify audit cadence.")
    if sc("incident_history") > 60:
        recs.append("Request incident history + postmortems; consider stricter review.")

    if not recs:
        recs.append("No major red flags from questionnaire.")

    return recs

def _print_single_report(result, warnings: list[str], show_warnings: bool) -> None:
    print("\n=== Vendor Risk Report ===")
    header_rows = [
        ("Vendor", result.vendor_name),
        ("Total Risk Score (0-100)", f"{result.total_score}"),
        ("Risk Tier", result.tier),
    ]
    print(_format_table(header_rows))

    print("\nHybrid Breakdown:")
    breakdown_rows = [
        ("Control (questionnaire)", f"{result.control.score}"),
        ("Exposure (external scan)", f"{result.exposure.score}"),
        ("Vulnerabilities", f"{result.vulnerabilities.score}"),
        ("Amplifications", f"{sum(result.amplifications.values()):.2f}"),
        ("Impact multiplier", f"x{result.impact.multiplier}"),
    ]
    print(_format_table(breakdown_rows))

    if warnings and show_warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")

    print("\nCategory Scores:")
    cat_rows = sorted(result.control.category_scores.items(), key=lambda kv: kv[0])
    cat_table = _format_table([(k, f"{v}") for k, v in cat_rows])
    print(cat_table)

    print("\nTop Risk Drivers:")
    drivers = sorted(result.control.category_scores.items(), key=lambda kv: kv[1], reverse=True)[:2]
    for cat, score in drivers:
        print(f"  - {cat} ({score})")

    print("\nRecommended Actions:")
    for r in _recommendations(result.control.category_scores):
        print(f"  - {r}")
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