"""
Mock IAM Policy JSON examples for testing the policy reviewer
"""

import json

SCENARIOS = {
    "wildcard_admin": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    },
    "s3_overpermissive": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    },
    "assume_role_open": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/CrossAccountAdminRole"
            }
        ]
    },
    "iam_dangerous": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:*",
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "iam:PutUserPolicy"
                ],
                "Resource": "*"
            }
        ]
    }
}


def get_policy(scenario):
    """
    Get IAM policy JSON for a given scenario.

    Args:
        scenario: One of 'wildcard_admin', 's3_overpermissive', 'assume_role_open', 'iam_dangerous'

    Returns:
        Formatted JSON string of the policy
    """
    policy = SCENARIOS.get(scenario, SCENARIOS["wildcard_admin"])
    return json.dumps(policy, indent=2)