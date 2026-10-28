"""Workflow command-line interface (CLI) routing for Verifier Standard (VSTD) polish.

Preparation can apply a retained recovery plan, but that file-by-file boundary is
not represented as atomic.  Every result remains non-promoting.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from verifier.core.receipt import strict_json_loads


def _handle_preparation(args: argparse.Namespace) -> dict[str, Any]:
    """Run preparation without converting its recovery boundary into polish."""
    from verifier.runtime.gate import _prdel_file
    from verifier.runtime.polish_workflow import (
        REPORT_SCHEMA,
        associate_commit,
        prepare_workflow,
        recover_apply,
    )

    try:
        if args.normalize_text or args.dry_run:
            raise ValueError(
                "text normalization and dry-run select verifier-polish-preparation-1"
            )
        if args.recover or args.associate:
            if any(
                (
                    args.policy,
                    args.policy_digest,
                    args.definition,
                    args.quality_profile,
                    args.quality_profile_digest,
                    args.requirements,
                    args.requirements_digest,
                    args.base,
                    args.resume,
                    args.apply,
                )
            ):
                raise ValueError(
                    "recovery and association cannot select preparation inputs"
                )
            if args.recover:
                if args.commit or args.git_root or args.output:
                    raise ValueError(
                        "recovery uses only the retained plan and selected artifact"
                    )
                return recover_apply(
                    args.artifact, args.recover, rollback=args.rollback
                )
            if not args.commit or args.rollback or args.output:
                raise ValueError(
                    (
                        "association requires one exact commit and "
                        "does not rewrite a bundle"
                    )
                )
            value = strict_json_loads(_prdel_file(args.associate).decode("utf-8"))
            if type(value) is not dict:
                raise ValueError("manifest must be an object")
            if "bundle" in value:
                value = value["bundle"]["manifest"]
            return associate_commit(args.git_root or args.artifact, value, args.commit)
        if args.rollback or not args.policy or not args.policy_digest:
            raise ValueError("preparation requires a separately pinned workflow policy")
        definition_path = None
        if args.definition and args.git_root:
            try:
                definition_path = (
                    Path(args.definition)
                    .absolute()
                    .relative_to(Path(args.git_root).absolute())
                    .as_posix()
                )
            except ValueError:
                pass
        return prepare_workflow(
            args.artifact,
            policy_bytes=_prdel_file(args.policy),
            expected_policy_digest=args.policy_digest,
            definition_bytes=_prdel_file(args.definition) if args.definition else None,
            quality_profile_bytes=(
                _prdel_file(args.quality_profile) if args.quality_profile else None
            ),
            expected_quality_profile_digest=args.quality_profile_digest,
            requirements_bytes=(
                _prdel_file(args.requirements) if args.requirements else None
            ),
            expected_requirements_digest=args.requirements_digest,
            definition_path=definition_path,
            git_root=args.git_root,
            base=args.base,
            head=args.commit,
            output=args.output,
            resume=args.resume,
            apply=args.apply,
        )
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        status = (
            "UNKNOWN"
            if isinstance(error, OSError) and not isinstance(error, FileNotFoundError)
            else "FAIL"
        )
        return {
            "schema_version": REPORT_SCHEMA,
            "status": status,
            "polished": False,
            "promotable": False,
            "reason": "INVALID_OR_UNAVAILABLE_SELECTED_PREPARATION_INPUT",
        }
