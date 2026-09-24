"""Verdict independence enforcement for Level 6 disclosure bounds (obligation 6.6).

Acronyms:
    JavaScript Object Notation (JSON);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

from typing import Any


class MalformedRedactionError(ValueError):
    """Raised when a disclosure redaction moves or alters a Tier 1-5 verdict."""


def assert_verdict_independence(
    original_cert: dict[str, Any],
    redacted_cert: dict[str, Any],
) -> None:
    """Enforce obligation [OBJECT]-6.6: Verdict independence.

    Redacting any emitted field to satisfy a disclosure bound leaves every
    verdict this object carries at Tiers 1 through 5 unchanged. A disclosure
    bound never changes a computational verdict -- neither upward nor downward --
    and a redaction that moves one makes the certificate malformed rather than
    more private.

    Raises:
        MalformedRedactionError: If any verdict at Tiers 1-5 was altered, missing,
            or modified by redaction.
    """
    orig_object = (
        original_cert.get("object_name")
        or original_cert.get("domain")
        or original_cert.get("request", {}).get("domain")
    )
    red_object = (
        redacted_cert.get("object_name")
        or redacted_cert.get("domain")
        or redacted_cert.get("request", {}).get("domain")
    )
    if orig_object and red_object and orig_object != red_object:
        raise MalformedRedactionError(
            f"Object identity mismatch during redaction: {orig_object!r} vs {red_object!r}"
        )

    # Check root verdict if present
    if "verdict" in original_cert:
        orig_v = original_cert.get("verdict")
        red_v = redacted_cert.get("verdict")
        if orig_v != red_v:
            raise MalformedRedactionError(
                f"Root computational verdict moved from {orig_v!r} to {red_v!r} by redaction"
            )

    # Check nested result structure from verifier-domain-certification-1
    if "result" in original_cert and isinstance(original_cert["result"], dict):
        orig_res = original_cert["result"]
        red_res = redacted_cert.get("result", {})
        if orig_res.get("status") != red_res.get("status"):
            raise MalformedRedactionError(
                f"Result status moved from {orig_res.get('status')!r} to {red_res.get('status')!r} by redaction"
            )
        orig_checks = orig_res.get("checks", {})
        red_checks = red_res.get("checks", {})
        for check_id, check_data in orig_checks.items():
            if isinstance(check_data, dict):
                orig_out = check_data.get("evaluation", {}).get("outcome")
                red_out = red_checks.get(check_id, {}).get("evaluation", {}).get("outcome")
                if orig_out != red_out:
                    raise MalformedRedactionError(
                        f"Check {check_id} outcome moved from {orig_out!r} to {red_out!r} by redaction"
                    )

    # Check tier-specific verdicts across Tiers 1 through 5
    for tier in range(1, 6):
        tier_key = f"tier_{tier}"
        tier_verdict_key = f"tier_{tier}_verdict"

        # Check explicit tier verdict key
        if tier_verdict_key in original_cert:
            orig_tv = original_cert.get(tier_verdict_key)
            red_tv = redacted_cert.get(tier_verdict_key)
            if orig_tv != red_tv:
                raise MalformedRedactionError(
                    f"Tier {tier} verdict moved from {orig_tv!r} to {red_tv!r} by redaction"
                )

        # Check nested tier structure
        if tier_key in original_cert and isinstance(original_cert[tier_key], dict):
            orig_sub = original_cert[tier_key].get("verdict")
            red_sub = redacted_cert.get(tier_key, {}).get("verdict")
            if orig_sub is not None and orig_sub != red_sub:
                raise MalformedRedactionError(
                    f"Tier {tier} nested verdict moved from {orig_sub!r} to {red_sub!r} by redaction"
                )

    # Check results map if present
    if "results" in original_cert and isinstance(original_cert["results"], dict):
        orig_results = original_cert["results"]
        red_results = redacted_cert.get("results", {})
        for req_id, orig_r in orig_results.items():
            # Check obligations under Tiers 1-5 (pattern: [OBJECT]-[1-5].m or [1-5].m)
            parts = req_id.split("-")[-1].split(".")
            if len(parts) == 2 and parts[0].isdigit():
                tier_num = int(parts[0])
                if 1 <= tier_num <= 5:
                    red_r = red_results.get(req_id)
                    if orig_r != red_r:
                        raise MalformedRedactionError(
                            f"Obligation {req_id} verdict moved from {orig_r!r} to {red_r!r} by redaction"
                        )

