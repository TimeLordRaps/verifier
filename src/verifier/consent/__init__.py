"""Verifier Standard (VSTD) proposed level-7 consent admission mechanisms.

Consent admission never changes a computational verdict. See CONSENT_LEVEL7.md.
"""
from __future__ import annotations

from .engine import (
    ConsentContext, ConsentEvaluation, ConsentKey, ConsentPolicy, ConsentVerdict,
    authenticate_consent, evaluate_consent, recheck_consent,
)

__all__ = ["ConsentContext", "ConsentEvaluation", "ConsentKey", "ConsentPolicy",
           "ConsentVerdict", "authenticate_consent", "evaluate_consent", "recheck_consent"]
