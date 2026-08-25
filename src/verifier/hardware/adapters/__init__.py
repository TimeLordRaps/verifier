"""Terminology: Verifier Standard (VSTD).

Built-in VSTD 3 evidence adapters."""

from .amd import AmdAdapter
from .base import AdapterError, EvidenceAdapter
from .generic import GenericFixtureAdapter
from .intel import IntelGaudiAdapter
from .nvidia import NvidiaAdapter
from .provider import (
    AwsNeuronProviderAdapter,
    GoogleTpuProviderAdapter,
    MicrosoftMaiaProviderAdapter,
    ProviderEvidenceAdapter,
    normalize_provider_evidence,
)

__all__ = [
    "AdapterError",
    "AmdAdapter",
    "EvidenceAdapter",
    "GenericFixtureAdapter",
    "IntelGaudiAdapter",
    "NvidiaAdapter",
    "ProviderEvidenceAdapter",
    "GoogleTpuProviderAdapter",
    "AwsNeuronProviderAdapter",
    "MicrosoftMaiaProviderAdapter",
    "normalize_provider_evidence",
]
