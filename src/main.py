import argparse
import json
from pathlib import Path

from .engine.risk_scoring import score_vendor

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
        warnings.append(f"missing answers for: {','.join(missing)}")

    unknown = [qid for qid in expected_qids if responses.get(qid) == "unknown"]
    if unknown:
        warnings.append(f"answers marked unknown: {','.join(unknown)}")
    
    extra = sorted([k for k in responses.keys() if k not in set(expected_qids)])
    if extra:
        warnings.append(f"unrecognized answers ignored: {','.join(extra)}")

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

def main() -> int:
    parser = argparse.ArgumentParser(description="Vendor Risk Assessment CLI")
    parser.add_argument("--vendor", required=True, help="Path to vendor response JSON (e.g., data/sample_vendor.json)")
    parser.add_argument("--weights", default="data/risk_weights.json", help="Path to risk weights JSON")
    parser.add_argument("--show-warnings", action="store_true", help="Print validation warnings")
    args = parser.parse_args()

    vendor_path = Path(args.vendor)
    weights_path = Path(args.weights)

    vendor_data = _load_json(vendor_path)
    weights_data = _load_json(weights_path)
    warnings = _validate_inputs(vendor_data, weights_data)

    result = score_vendor(
        vendor_data.get("vendor_name", "(unknown vendor)"),
        vendor_data.get("responses", {}),
        weights_data,
    )

    print("\n=== Vendor Risk Report ===")
    header_rows = [
        ("Vendor", result.vendor_name),
        ("Total Risk Score (0-100)", f"{result.total_score}"),
        ("Risk Tier", result.tier),
    ]
    print(_format_table(header_rows))

    if warnings and args.show_warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")


    print("\nCategory Scores:")
    cat_rows = sorted(result.category_scores.items(), key=lambda kv: kv[0])
    cat_table = _format_table([(k, f"{v}") for k, v in cat_rows])
    print(cat_table)

# Top risk drivers (highest categories)
    drivers = sorted(result.category_scores.items(), key=lambda kv: kv[1], reverse=True)[:2]
    print("\nTop Risk Drivers:")
    for cat, score in drivers:
        print(f"  - {cat} ({score})")

    # Recommendations
    print("\nRecommended Actions:")
    for r in _recommendations(result.category_scores):
        print(f"  - {r}")

    print()


    return 0

if __name__ == "__main__":
    raise SystemExit(main())