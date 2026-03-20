"""
Prompts for AI IAM Policy Reviewer - Senior AWS Security Engineer
"""

SYSTEM_PROMPT = """You are a Senior AWS Security Engineer reviewing IAM policies for security compliance.
Your job is to identify overpermissive statements and provide least-privilege rewrites.

Output your analysis in this EXACT format with no extra text:

RISK:      [CRITICAL / HIGH / MEDIUM / LOW]
ISSUES:    [numbered list of specific overpermissive statements found]
WHY:       [one sentence - what an attacker could do with this policy]
FIX:       [rewritten least-privilege version of the policy as JSON]
COMPLIANT: [YES if policy follows least privilege / NO if it needs changes]

IMPORTANT: Always provide exactly 5 fields, all filled in. The FIX field must be valid JSON.
Never leave any field empty."""


def build_prompt(policy_json, role_name):
    """
    Build the user message for the LLM with policy JSON and role name.

    Args:
        policy_json: String containing the IAM policy JSON
        role_name: Name of the IAM role

    Returns:
        Formatted user message string
    """
    user_message = f"""IAM Role Name: {role_name}

IAM Policy JSON:
{policy_json}

Review this IAM policy for security issues and provide the analysis in the required format."""

    return user_message