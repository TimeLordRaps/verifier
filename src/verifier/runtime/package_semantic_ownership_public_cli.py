"""Audited ownership for Verifier's installed public command dispatcher.

The public command-line interface (CLI) parses requests and delegates both
read-only assessments and effectful operations. This declaration assigns the
one current source path and its accumulated consequence roles. It does not
claim that delegated mechanisms pass, that downstream effects are confined, or
that a command grants release, physical, or financial authority.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
)


PUBLIC_CLI_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-public-cli-dispatch",
        "PROTOCOL",
        ("src/verifier/runtime/public_cli.py",),
        "Installed public command parser, request router, output protocol and delegated operation controller.",
        "One process-facing entrypoint selects read, verification, filesystem, artifact-lifecycle, subprocess and optional hardware handlers, so its protocol, control, observation, policy, transaction and effect boundaries must remain explicit.",
        "The router delegates rather than proves each handler. Process and filesystem effects are possible, but no downstream effect, sandbox, physical actuation, real-money authority, publication, release, deployment, ROBOT or FINBOT role is established by dispatch alone.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    ),
)


__all__ = ["PUBLIC_CLI_OWNERSHIP_SPECS", "SemanticOwnershipSpec"]
