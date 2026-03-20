"""
AI IAM Policy Reviewer - Main entry point

Runs all four IAM policy scenarios and prints formatted security reports.
"""

from mock_policies import get_policy
from reviewer import review_policy
from reporter import print_report


# Define the scenarios to run
SCENARIOS = [
    ("wildcard_admin", "ProdAdminRole"),
    ("s3_overpermissive", "DataAccessRole"),
    ("assume_role_open", "CrossAccountAdminRole"),
    ("iam_dangerous", "IAMAdminRole"),
]


def run_scenario(scenario_name, role_name):
    """
    Run a single scenario: get policy, review, and print report.

    Args:
        scenario_name: The scenario key
        role_name: Name of the IAM role
    """
    # Print scenario name
    print(f"\n{'='*70}")
    print(f"  SCENARIO: {scenario_name.upper()}")
    print(f"  ROLE: {role_name}")
    print(f"{'='*70}\n")

    # Get policy JSON
    policy_json = get_policy(scenario_name)

    # Review the policy
    result = review_policy(policy_json, role_name)

    # Print report
    print_report(result, role_name)

    # Add separator between scenarios
    print("\n" + "=" * 70 + "\n")


def main():
    """Run all scenarios sequentially."""
    print("\n" + "=" * 70)
    print("  AI IAM POLICY REVIEWER - Security Analysis")
    print("=" * 70 + "\n")

    for scenario_name, role_name in SCENARIOS:
        run_scenario(scenario_name, role_name)

    print("\nAll scenarios completed.")


if __name__ == "__main__":
    main()