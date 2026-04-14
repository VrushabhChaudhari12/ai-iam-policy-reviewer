"""
AI IAM Policy Reviewer - Main entry point

Optimized with:
- CLI argument support (--scenarios, --output-json)
- Per-scenario error isolation (one failure doesn't abort all)
- Summary statistics printed at the end
- Optional JSON report export
"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from mock_policies import get_policy
from reporter import print_report
from reviewer import review_policy
import config

log = logging.getLogger(__name__)

# Default scenarios: (scenario_key, role_name)
DEFAULT_SCENARIOS: list[tuple[str, str]] = [
    ("wildcard_admin", "ProdAdminRole"),
    ("s3_overpermissive", "DataAccessRole"),
    ("assume_role_open", "CrossAccountAdminRole"),
    ("iam_dangerous", "IAMAdminRole"),
]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="AI IAM Policy Reviewer - security analysis for AWS IAM policies"
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        metavar="KEY",
        help="Run only these scenario keys (e.g. wildcard_admin s3_overpermissive).",
    )
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        help="Write all results to a JSON file in addition to console output.",
    )
    parser.add_argument(
        "--log-level",
        default=config.LOG_LEVEL,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: %(default)s).",
    )
    return parser.parse_args(argv)


def run_scenario(scenario_name: str, role_name: str) -> dict | None:
    """
    Run a single scenario: fetch policy -> review -> print report.

    Returns the result dict on success, or None if the scenario failed.
    """
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  SCENARIO : {scenario_name.upper()}")
    print(f"  ROLE     : {role_name}")
    print(f"{sep}\n")

    try:
        policy_json = get_policy(scenario_name)
    except KeyError:
        log.error("Unknown scenario key: '%s'. Skipping.", scenario_name)
        return None

    try:
        result = review_policy(policy_json, role_name)
    except Exception as exc:  # noqa: BLE001
        log.error("Review failed for scenario '%s': %s", scenario_name, exc)
        print(f"  [ERROR] Could not review scenario '{scenario_name}': {exc}\n")
        return None

    print_report(result, role_name)
    print(f"\n{'=' * 70}\n")
    return result


def main(argv: list[str] | None = None) -> int:
    """
    Entry point. Returns exit code (0 = success, 1 = partial failures).
    """
    args = _parse_args(argv)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Resolve scenarios to run
    scenario_map = {k: v for k, v in DEFAULT_SCENARIOS}
    if args.scenarios:
        scenarios = []
        for key in args.scenarios:
            if key not in scenario_map:
                log.warning("Scenario '%s' not found. Available: %s", key, list(scenario_map))
            else:
                scenarios.append((key, scenario_map[key]))
    else:
        scenarios = DEFAULT_SCENARIOS

    # Header
    print("\n" + "=" * 70)
    print("  AI IAM POLICY REVIEWER - Security Analysis")
    print(f"  Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70 + "\n")

    # Run scenarios
    results: list[dict] = []
    failures: list[str] = []

    for scenario_name, role_name in scenarios:
        result = run_scenario(scenario_name, role_name)
        if result is not None:
            result["_scenario"] = scenario_name
            result["_role"] = role_name
            results.append(result)
        else:
            failures.append(scenario_name)

    # Summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    risk_counts: dict[str, int] = {}
    for r in results:
        risk = r.get("RISK", "UNKNOWN").upper()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    for risk, count in sorted(risk_counts.items()):
        print(f"  {risk:<10}: {count} scenario(s)")
    if failures:
        print(f"  FAILED    : {len(failures)} scenario(s) - {', '.join(failures)}")
    avg_conf = (
        sum(r.get("_confidence", 0.0) for r in results) / len(results)
        if results else 0.0
    )
    print(f"  Avg confidence: {avg_conf:.2f}")
    print("=" * 70 + "\n")

    # Optional JSON export
    if args.output_json and results:
        out_path = Path(args.output_json)
        out_path.write_text(
            json.dumps(results, indent=2, default=str), encoding="utf-8"
        )
        print(f"Results written to: {out_path.resolve()}\n")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
