"""
AI IAM Policy Reviewer - Main review logic using Ollama LLM

Optimized with:
- Centralized config via config.py
- Structured logging
- Improved JSON extraction from markdown blocks
- Confidence scoring
- Smarter retry/backoff logic
"""
import re
import time
import json
import logging
from openai import OpenAI
import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# Required fields in the LLM response
REQUIRED_FIELDS = config.REQUIRED_FIELDS

# Risk escalation keywords that trigger immediate flagging
HIGH_RISK_KEYWORDS = config.HIGH_RISK_KEYWORDS

# How many consecutive identical RISK values counts as a loop
LOOP_DETECTION_LIMIT = 3


def _extract_json_from_text(text: str) -> str:
    """
    Extract JSON string from plain text or markdown code blocks.

    Handles:
    - Raw JSON objects/arrays
    - ```json ... ``` fenced blocks
    - ``` ... ``` fenced blocks

    Returns the extracted JSON string, or the original text if no
    code-fenced block is found.
    """
    # Try fenced ```json block first
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        return match.group(1).strip()
    # Fall back to first { ... } span in the text
    brace_match = re.search(r"(\{[\s\S]*\})", text)
    if brace_match:
        return brace_match.group(1).strip()
    return text.strip()


def _parse_response(response_text: str) -> dict | None:
    """
    Parse the LLM response to extract the required fields.

    Supports both structured-text format (FIELD: value) and a single
    top-level JSON object whose keys match REQUIRED_FIELDS.

    Returns a dict with all required fields, or None on failure.
    """
    # --- Attempt 1: JSON object response ---
    candidate = _extract_json_from_text(response_text)
    try:
        data = json.loads(candidate)
        if isinstance(data, dict) and all(f in data for f in REQUIRED_FIELDS):
            log.debug("Parsed response as JSON object.")
            return {f: str(data[f]).strip() for f in REQUIRED_FIELDS}
    except (json.JSONDecodeError, TypeError):
        pass

    # --- Attempt 2: Key: value line-by-line format ---
    result: dict = {}
    current_field: str | None = None
    current_content: list[str] = []

    for raw_line in response_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        matched_field = next(
            (f for f in REQUIRED_FIELDS if line.upper().startswith(f + ":")),
            None,
        )
        if matched_field:
            if current_field:
                result[current_field] = "\n".join(current_content).strip()
            current_field = matched_field
            value = line[len(matched_field) + 1:].strip()
            current_content = [value] if value else []
        elif current_field:
            current_content.append(line)

    if current_field:
        result[current_field] = "\n".join(current_content).strip()

    if all(f in result and result[f] for f in REQUIRED_FIELDS):
        log.debug("Parsed response as structured text.")
        return result

    log.warning("Failed to parse LLM response. Missing fields: %s",
                [f for f in REQUIRED_FIELDS if f not in result or not result.get(f)])
    return None


def _risk_score(risk_label: str) -> int:
    """Map a RISK label to a numeric score for comparison."""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
        risk_label.upper(), 0
    )


def _check_high_risk(analysis: dict) -> bool:
    """
    Return True if any high-risk keyword appears in RISK or ISSUES,
    or if the risk score is CRITICAL.
    """
    risk = analysis.get("RISK", "").upper()
    issues = analysis.get("ISSUES", "").upper()
    combined = risk + " " + issues
    if any(kw.upper() in combined for kw in HIGH_RISK_KEYWORDS):
        return True
    return _risk_score(risk) >= 4  # CRITICAL


def _detect_loop(previous_results: list[dict]) -> bool:
    """
    Return True if the last LOOP_DETECTION_LIMIT results share the
    same RISK value at HIGH or CRITICAL severity (stuck loop).
    """
    if len(previous_results) < LOOP_DETECTION_LIMIT:
        return False
    recent = previous_results[-LOOP_DETECTION_LIMIT:]
    risk_values = [r.get("RISK", "").upper() for r in recent]
    return len(set(risk_values)) == 1 and risk_values[0] in ("CRITICAL", "HIGH")


def _validate_fix_json(fix_field: str) -> bool:
    """
    Return True if the FIX field contains (or embeds) valid JSON.
    Extracts JSON from markdown code fences before validating.
    """
    candidate = _extract_json_from_text(fix_field)
    try:
        json.loads(candidate)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def _compute_confidence(result: dict) -> float:
    """
    Heuristic confidence score [0.0, 1.0] based on response quality.

    Criteria:
    - All required fields present and non-empty       (+0.4)
    - FIX field contains valid JSON                   (+0.3)
    - RISK label is one of the four expected values   (+0.2)
    - COMPLIANT is exactly YES or NO                  (+0.1)
    """
    score = 0.0
    if all(result.get(f, "").strip() for f in REQUIRED_FIELDS):
        score += 0.4
    if _validate_fix_json(result.get("FIX", "")):
        score += 0.3
    if result.get("RISK", "").upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        score += 0.2
    if result.get("COMPLIANT", "").upper() in ("YES", "NO"):
        score += 0.1
    return round(score, 2)


def review_policy(policy_json: str, role_name: str) -> dict:
    """
    Review an IAM policy using Ollama LLM.

    Implements four-layer termination safety:
        1. High-risk keyword detection -> immediate return (no blocking)
        2. FIX field JSON validation   -> retry on failure
        3. All-fields non-empty check  -> retry on failure
        4. Loop detection              -> raises ValueError

    Adds a ``_confidence`` key to the returned dict.

    Args:
        policy_json: String containing IAM policy JSON.
        role_name:   Name of the IAM role being reviewed.

    Returns:
        dict with keys: RISK, ISSUES, WHY, FIX, COMPLIANT, _confidence

    Raises:
        ValueError: Loop detected or all retries exhausted with bad format.
        Exception:  Unrecoverable LLM / network error.
    """
    from prompts import SYSTEM_PROMPT, build_prompt

    user_message = build_prompt(policy_json, role_name)
    client = OpenAI(
        base_url=config.BASE_URL,
        api_key=config.API_KEY,
        timeout=config.TIMEOUT_SECONDS,
    )

    previous_results: list[dict] = []
    last_error: Exception | None = None

    for attempt in range(config.MAX_RETRIES):
        # Layer 4: loop detection
        if _detect_loop(previous_results):
            raise ValueError(
                f"Loop detected: RISK level identical for {LOOP_DETECTION_LIMIT} consecutive attempts."
            )

        try:
            log.info("Reviewing policy for role '%s' (attempt %d/%d).",
                     role_name, attempt + 1, config.MAX_RETRIES)

            response = client.chat.completions.create(
                model=config.MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                temperature=0.2,       # Lower temp -> more deterministic output
                max_tokens=2048,
            )

            response_text: str = response.choices[0].message.content or ""
            log.debug("Raw LLM response:\n%s", response_text[:500])

            result = _parse_response(response_text)
            if result is None:
                last_error = ValueError("Invalid response format - missing required fields.")
                if attempt < config.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise last_error

            previous_results.append(result)

            # Layer 1: high-risk detection (log, don't block)
            if _check_high_risk(result):
                log.warning("High-risk policy detected for role '%s': %s",
                            role_name, result.get("RISK"))

            # Layer 2: FIX field must be valid JSON
            if not _validate_fix_json(result.get("FIX", "")):
                last_error = ValueError("FIX field does not contain valid JSON.")
                if attempt < config.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise last_error

            # Layer 3: all fields non-empty
            if not all(result.get(f, "").strip() for f in REQUIRED_FIELDS):
                last_error = ValueError("Some required fields are empty after parsing.")
                if attempt < config.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise last_error

            # Attach confidence score
            result["_confidence"] = _compute_confidence(result)
            log.info("Review complete for '%s'. RISK=%s, confidence=%.2f",
                     role_name, result.get("RISK"), result["_confidence"])
            return result

        except Exception as exc:  # noqa: BLE001
            last_error = exc
            err_str = str(exc).lower()
            is_transient = any(
                kw in err_str
                for kw in ("connection", "timeout", "refused", "unreachable", "rate")
            )
            if is_transient and attempt < config.MAX_RETRIES - 1:
                wait = 2 ** attempt
                log.warning("Transient error on attempt %d: %s. Retrying in %ds.",
                            attempt + 1, exc, wait)
                time.sleep(wait)
            else:
                log.error("Unrecoverable error reviewing role '%s': %s", role_name, exc)
                raise

    raise last_error  # type: ignore[misc]
