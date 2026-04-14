"""
Reporter - Formats and prints IAM policy review results

Optimized with:
- Severity icons for visual scanning
- Confidence score display
- Pretty-printed FIX JSON
- Compact structured sections
"""
import json
from datetime import datetime, timezone

# ANSI colour codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_DIM = "\033[2m"

# Risk level -> (colour, icon, label)
_RISK_META: dict[str, tuple[str, str, str]] = {
    "CRITICAL": (_RED, "[!!!]", "CRITICAL RISK"),
    "HIGH": (_YELLOW, "[!! ]", "HIGH RISK"),
    "MEDIUM": (_BLUE, "[!  ]", "MEDIUM RISK"),
    "LOW": (_GREEN, "[   ]", "LOW RISK"),
}


def _colour(text: str, code: str) -> str:
    """Wrap *text* with an ANSI colour code and reset."""
    return f"{code}{text}{_RESET}"


def _pretty_fix(fix_field: str) -> str:
    """
    Attempt to pretty-print the FIX field as JSON.
    Falls back to the raw string if it can't be parsed.
    """
    # Strip possible markdown fences
    candidate = fix_field.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        # Drop first and last fence lines
        inner = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        candidate = inner.strip()
    try:
        parsed = json.loads(candidate)
        return json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        return fix_field  # Return as-is


def _confidence_bar(score: float, width: int = 20) -> str:
    """
    Build a simple ASCII progress bar for the confidence score.

    Example: [################    ] 0.80
    """
    filled = round(score * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {score:.2f}"


def print_report(review_result: dict, role_name: str) -> None:
    """
    Print a formatted, colour-coded security report to console.

    Args:
        review_result: Dictionary with fields RISK, ISSUES, WHY, FIX,
                       COMPLIANT, and optionally _confidence.
        role_name:     Name of the IAM role that was reviewed.
    """
    risk_value = review_result.get("RISK", "UNKNOWN").strip().upper()
    compliant_value = review_result.get("COMPLIANT", "NO").strip().upper()
    confidence = review_result.get("_confidence", None)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    colour, icon, label = _RISK_META.get(
        risk_value, (_DIM, "[?  ]", f"{risk_value} RISK")
    )

    sep = "-" * 70
    wide_sep = "=" * 70

    # ---- Header ----
    print(_colour(f"{icon} {label}", _BOLD + colour))
    print(_colour(wide_sep, colour))
    print(f"  Role      : {_colour(role_name, _BOLD)}")
    print(f"  Timestamp : {_DIM}{timestamp}{_RESET}")
    if confidence is not None:
        bar = _confidence_bar(confidence)
        conf_colour = _GREEN if confidence >= 0.8 else _YELLOW if confidence >= 0.5 else _RED
        print(f"  Confidence: {_colour(bar, conf_colour)}")
    print(_colour(sep, colour))

    # ---- Compliant status ----
    if compliant_value == "YES":
        status_str = _colour("YES - Policy follows least privilege", _GREEN + _BOLD)
    else:
        status_str = _colour("NO  - Policy requires remediation", _RED + _BOLD)
    print(f"\n  COMPLIANT : {status_str}\n")

    # ---- Issues ----
    print(_colour("  ISSUES FOUND:", _BOLD))
    for line in review_result.get("ISSUES", "(none)").splitlines():
        print(f"    {line}")
    print()

    # ---- Why it matters ----
    print(_colour("  ATTACK IMPACT:", _BOLD))
    for line in review_result.get("WHY", "").splitlines():
        print(f"    {line}")
    print()

    # ---- Fix ----
    print(_colour("  RECOMMENDED FIX (least-privilege policy):", _BOLD + _CYAN))
    fix_text = _pretty_fix(review_result.get("FIX", ""))
    for line in fix_text.splitlines():
        print(f"    {line}")
    print()

    print(_colour(sep, colour))
