"""
AI IAM Policy Reviewer - Main review logic using Ollama LLM
"""

import time
import json
from openai import OpenAI

# Configuration
BASE_URL = "http://localhost:11434/v1"
API_KEY = "ollama"
MODEL = "llama3.2"
TIMEOUT_SECONDS = 90
MAX_RETRIES = 3
LOOP_DETECTION_LIMIT = 3

# Required fields in the response
REQUIRED_FIELDS = ["RISK", "ISSUES", "WHY", "FIX", "COMPLIANT"]

# Termination conditions
TERMINATION_CONDITIONS = [
    "CRITICAL",
    "WILDCARD",
    "*",
    "PRINCIPAL *",
    "RESOURCE *",
    "ADMINISTRATOR",
]


def _parse_response(response_text):
    """
    Parse the LLM response to extract the 5 required fields.

    Args:
        response_text: Raw response from the LLM

    Returns:
        Dictionary with the 5 fields, or None if parsing fails
    """
    result = {}
    lines = response_text.strip().split("\n")

    # Track current field and content
    current_field = None
    current_content = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check if line starts with a required field
        field_found = None
        for field in REQUIRED_FIELDS:
            if line.startswith(field + ":"):
                field_found = field
                break

        if field_found:
            # Save previous field content
            if current_field:
                result[current_field] = "\n".join(current_content).strip()

            current_field = field_found
            # Get content after the field name and colon
            value = line[len(field_found) + 1:].strip()
            current_content = [value] if value else []
        elif current_field:
            # Continue collecting content for current field
            current_content.append(line)

    # Save last field
    if current_field:
        result[current_field] = "\n".join(current_content).strip()

    # Validate all 5 fields are present and not empty
    if all(field in result and result[field].strip() for field in REQUIRED_FIELDS):
        return result
    return None


def _check_termination_condition(analysis):
    """
    Check if the analysis indicates a critical condition.

    Args:
        analysis: Parsed analysis dictionary

    Returns:
        True if termination is needed, False otherwise
    """
    risk = analysis.get("RISK", "").upper()
    issues = analysis.get("ISSUES", "").upper()

    for condition in TERMINATION_CONDITIONS:
        if condition in risk or condition in issues:
            return True
    return False


def _detect_loop(previous_results):
    """
    Detect if the same error is repeating.

    Args:
        previous_results: List of previous result dictionaries

    Returns:
        True if same error repeats LOOP_DETECTION_LIMIT times, False otherwise
    """
    if len(previous_results) < LOOP_DETECTION_LIMIT:
        return False

    # Check last N results for same RISK field
    recent = previous_results[-LOOP_DETECTION_LIMIT:]
    risk_values = [r.get("RISK", "") for r in recent]

    # If all same and it's CRITICAL/HIGH, it's a loop
    return len(set(risk_values)) == 1 and risk_values[0] in ["CRITICAL", "HIGH"]


def _validate_fix_json(fix_field):
    """
    Validate that FIX field contains valid JSON.

    Args:
        fix_field: String containing the FIX field content

    Returns:
        True if valid JSON, False otherwise
    """
    try:
        # Try to parse as JSON
        json.loads(fix_field)
        return True
    except json.JSONDecodeError:
        # Check if it starts with ```json and ends with ```
        if "```json" in fix_field:
            try:
                # Extract JSON from markdown code block
                json_str = fix_field.split("```json")[1].split("```")[0].strip()
                json.loads(json_str)
                return True
            except:
                pass
        return False


def review_policy(policy_json, role_name):
    """
    Review an IAM policy using Ollama LLM with four-layer termination safety.

    Args:
        policy_json: String containing IAM policy JSON
        role_name: Name of the IAM role

    Returns:
        Dictionary with fields: RISK, ISSUES, WHY, FIX, COMPLIANT

    Raises:
        Exception: If all retries fail or response is invalid
    """
    from prompts import SYSTEM_PROMPT, build_prompt

    # Build the prompt
    user_message = build_prompt(policy_json, role_name)

    # Initialize the client
    client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=TIMEOUT_SECONDS)

    # Track previous results for loop detection
    previous_results = []

    # Retry logic with exponential backoff
    last_error = None

    for attempt in range(MAX_RETRIES):
        # Layer 4: Loop detection
        if _detect_loop(previous_results):
            raise ValueError(f"Loop detected: same risk level repeated {LOOP_DETECTION_LIMIT} times")

        try:
            # Make the LLM call
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3,
                max_tokens=2000,
            )

            # Extract response text
            response_text = response.choices[0].message.content

            # Validate response - check all 5 fields are present
            result = _parse_response(response_text)

            if result is None:
                # Invalid response format - could retry
                last_error = ValueError(f"Invalid response format - missing required fields")
                if attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    time.sleep(wait_time)
                    continue
                raise last_error

            # Track result for loop detection
            previous_results.append(result)

            # Layer 1: Check termination condition
            if _check_termination_condition(result):
                pass

            # Layer 2: Validate FIX field is valid JSON
            if not _validate_fix_json(result.get("FIX", "")):
                last_error = ValueError("FIX field does not contain valid JSON")
                if attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
                raise last_error

            # Layer 3: Additional validation - ensure fields are meaningful
            if not all(result.get(field, "").strip() for field in REQUIRED_FIELDS):
                last_error = ValueError("Some fields are empty after parsing")
                if attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
                raise last_error

            # All validations passed, return result
            return result

        except Exception as e:
            last_error = e
            error_str = str(e).lower()

            # Check if it's a connection error
            is_connection_error = any(
                keyword in error_str
                for keyword in ["connection", "timeout", "refused", "unreachable"]
            )

            if is_connection_error and attempt < MAX_RETRIES - 1:
                # Exponential backoff: 1s, 2s, 4s
                wait_time = 2 ** attempt
                time.sleep(wait_time)
                continue
            elif not is_connection_error:
                # Non-connection error, don't retry
                raise

    # All retries exhausted
    raise last_error