"""
Reporter - Formats and prints IAM policy review results
"""

from datetime import datetime
import json


def print_report(review_result, role_name):
    """
    Print a formatted security report to console.

    Args:
        review_result: Dictionary with fields: RISK, ISSUES, WHY, FIX, COMPLIANT
        role_name: Name of the IAM role
    """
    risk_value = review_result.get("RISK", "UNKNOWN").strip().upper()
    compliant_value = review_result.get("COMPLIANT", "NO").strip().upper()

    # Header based on risk level
    if risk_value == "CRITICAL":
        header_color = "\033[91m"  # Red
        header_text = "CRITICAL RISK"
    elif risk_value == "HIGH":
        header_color = "\033[93m"  # Yellow
        header_text = "HIGH RISK"
    elif risk_value == "MEDIUM":
        header_color = "\033[94m"  # Blue
        header_text = "MEDIUM RISK"
    else:
        header_color = "\033[92m"  # Green
        header_text = "LOW RISK"

    reset_ansi = "\033[0m"

    # Header
    header = "=" * 70
    print(header)
    print(f"{header_color}{'='*20} {header_text} {'='*20}{reset_ansi}")
    print(header)

    # Role info
    print(f"\n*Role Name:* {role_name}")

    # Divider
    divider = "-" * 70

    # Review fields
    print(divider)
    print(f"\n*RISK:* {risk_value}")
    print(f"\n*ISSUES:*\n{review_result.get('ISSUES', 'N/A')}")
    print(f"\n*WHY:* {review_result.get('WHY', 'N/A')}")

    # Format FIX JSON for display
    fix_content = review_result.get("FIX", "{}")
    try:
        # Try to parse and reformat if it's JSON
        fix_json = json.loads(fix_content)
        fix_display = json.dumps(fix_json, indent=2)
    except:
        fix_display = fix_content

    print(f"\n*FIX (Least-Privilege):*\n{fix_display}")
    print(f"\n*COMPLIANT:* {compliant_value}")

    # Footer with timestamp
    print("\n" + divider)
    footer = "=" * 70
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f" _Review completed at {timestamp}_ ")
    print(footer)
    print()