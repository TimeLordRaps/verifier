"""Terminology: identifier (ID); Verifier Standard (VSTD).

Experimental workflow profile; non-normative and verdict-neutral."""

from __future__ import annotations

from .github import GitHubAdapterError, github_snapshot_to_events
from .profile import (
    PROFILE_ID,
    PROFILE_STATUS,
    PROFILE_VERSION,
    WorkflowProfileError,
    canonical_bytes,
    load_manifest,
    manifest_digest,
    seal_manifest,
    validate_manifest,
    verify_repo_artifacts,
)
from .schema import workflow_manifest_schema

__all__ = [
    "GitHubAdapterError",
    "PROFILE_ID",
    "PROFILE_STATUS",
    "PROFILE_VERSION",
    "WorkflowProfileError",
    "canonical_bytes",
    "github_snapshot_to_events",
    "load_manifest",
    "manifest_digest",
    "seal_manifest",
    "validate_manifest",
    "verify_repo_artifacts",
    "workflow_manifest_schema",
]
