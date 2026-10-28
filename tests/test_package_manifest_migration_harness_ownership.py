"""Exact retained HARNESS ownership and effect boundaries for migration."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from verifier.runtime import package_harness_applicability as applicability
from verifier.runtime import package_manifest_migration as migration
from verifier.runtime.tier_zero_profile import value_digest


_LEGACY_HARNESS_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_support.py",
    "src/verifier/core/run_planning.py",
    "src/verifier/core/run_validation.py",
    "src/verifier/core/run_inspection.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_impact.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/runtime/language_runners.py",
    "src/verifier/runtime/package_harness_applicability.py",
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
)

_ADDED_EXECUTION_PATHS = (
    "src/verifier/core/owned_process.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

_LANGUAGE_EXTENSION_PATHS = (
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)


def test_harness_ownership_is_explicit_and_accumulates_execution_roles() -> None:
    """New execution sources retain HARNESS and add TRANSACTION consequences."""
    harness = set(migration._HARNESS_PATHS)
    transaction = set(migration._HARNESS_TRANSACTION_PATHS)
    ledger = set(migration._HARNESS_LEDGER_REVIEW_PATHS)

    assert harness == set((*_LEGACY_HARNESS_PATHS, *_ADDED_EXECUTION_PATHS))
    assert set(_LEGACY_HARNESS_PATHS) <= harness
    assert set(_ADDED_EXECUTION_PATHS) <= transaction
    assert harness <= ledger
    assert len(migration._HARNESS_PATHS) == len(harness) == 15
    assert not any(any(token in path for token in "*?[") for path in harness)


@pytest.mark.parametrize(
    "paths",
    (
        _LANGUAGE_EXTENSION_PATHS[:-1],
        (*_LANGUAGE_EXTENSION_PATHS, "extensions/languages/src/vstd_languages/extra_worker.py"),
    ),
    ids=("missing-worker", "extra-worker"),
)
def test_language_worker_denominator_fails_closed(paths: tuple[str, ...]) -> None:
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_HARNESS_LANGUAGE_OWNERSHIP_DENOMINATOR_DIFFERS",
    ):
        migration._validate_harness_language_ownership_denominator(set(paths))


@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_core_denominator_includes_owned_process_and_fails_closed(
    mutation: str,
) -> None:
    expected = (
        set(migration._VERIFIER_CORE_PATHS)
        | set(migration._CORE_SEMANTIC_PATHS)
        | {
            path
            for path in (*_LEGACY_HARNESS_PATHS, *_ADDED_EXECUTION_PATHS)
            if path.startswith("src/verifier/core/")
        }
    )
    if mutation == "missing":
        candidate = expected - {"src/verifier/core/owned_process.py"}
    else:
        candidate = expected | {"src/verifier/core/unreviewed_extra.py"}
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_CORE_OWNERSHIP_DENOMINATOR_DIFFERS",
    ):
        migration._validate_core_ownership_denominator(candidate)


@pytest.mark.parametrize(
    ("kind", "required"),
    (
        ("LEDGER", migration._HARNESS_LEDGER_REVIEW_PATHS),
        ("TRANSACTION", migration._HARNESS_TRANSACTION_PATHS),
    ),
)
@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_harness_role_review_refuses_partial_or_widened_evidence_denominator(
    tmp_path, kind: str, required: tuple[str, ...], mutation: str
) -> None:
    paths = required[:-1] if mutation == "missing" else (
        *required,
        "src/verifier/runtime/unreviewed_harness_effect.py",
    )
    review = {
        "vstd-harness": {
            "primary_kind": "HARNESS",
            "classification": {
                kind: {
                    "status": "APPLIES" if kind == "TRANSACTION" else "DOES_NOT_APPLY",
                    "reason": "Synthetic exact-denominator check.",
                    "evidence_paths": list(paths),
                }
            },
            "declarations": {},
        }
    }
    row = {
        "object_id": "vstd-harness",
        "kind": "HARNESS",
        "surfaces": ["file:" + path for path in required],
        "classification": {},
        "obligations": {},
    }
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_HARNESS_"
        + kind
        + "_EVIDENCE_DENOMINATOR_DIFFERS",
    ):
        migration._canonical_review_selection(
            tmp_path,
            row,
            {},
            SimpleNamespace(review_document=lambda: review),
            kind,
            "PACKAGE_MIGRATION_HARNESS_" + kind,
            refresh_reviewed=False,
        )


# The admitted 32-row launch denominator that the reviewed advance replaces.  It
# is pinned as evidence and checked against its digest before any transition is
# considered; it is never regenerated from the current catalog.
_ADMITTED_PRIOR_LAUNCHES = (
    {'call_sha256': 'sha256:6cfc63091a06491789ac3c676cbe47b423835df39be943746e5a77083df1ab3c',
     'callee': 'subprocess.run',
     'container_sha256': 'sha256:e9b850c8a263fe7431e5a532e224c5693387883985f404c7eb48c6aa2eb92466',
     'embedded_name': 'WORKER',
     'launch_id': 'extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=1',
     'line': 28,
     'necessity_reason': 'The language worker must invoke the selected compiler in its fresh '
                         'artifact directory.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'extensions/languages/src/vstd_languages/__init__.py',
     'scope': '<module>',
     'source_ast_sha256': 'sha256:991c457ade87b30099a41055a4d95e29498a11f6b65f387ae4f32502f6999f49',
     'source_kind': 'embedded-python-literal',
     'source_sha256': 'sha256:9e5959f493e7552d0eda01b3357894ef5ab1da8a3e1ad3f9bfe65c9c49cf2ae9',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:8ab8c03a43ca545669187e5c9569971be2dc3b916bcd16922c10a3ca5947f025',
     'callee': 'subprocess.run',
     'container_sha256': 'sha256:e9b850c8a263fe7431e5a532e224c5693387883985f404c7eb48c6aa2eb92466',
     'embedded_name': 'WORKER',
     'launch_id': 'extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=2',
     'line': 32,
     'necessity_reason': 'The language worker must execute the newly compiled subject to return '
                         'its exit status.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 2,
     'path': 'extensions/languages/src/vstd_languages/__init__.py',
     'scope': '<module>',
     'source_ast_sha256': 'sha256:991c457ade87b30099a41055a4d95e29498a11f6b65f387ae4f32502f6999f49',
     'source_kind': 'embedded-python-literal',
     'source_sha256': 'sha256:9e5959f493e7552d0eda01b3357894ef5ab1da8a3e1ad3f9bfe65c9c49cf2ae9',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:1e86cfeca94b27d3f64224d76644c98e225ef650cc7baddb4d77ecefb060d046',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/provenance.py|scope=<module>.<locals>.discover_git_provenance|callee=subprocess.run|ordinal=1',
     'line': 154,
     'necessity_reason': 'Git work-tree detection is required before repository provenance can be '
                         'described.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/core/provenance.py',
     'scope': '<module>.<locals>.discover_git_provenance',
     'source_ast_sha256': 'sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:fce1e4748ac1f196cd7f5672c307403af57d5434514a36056f255d1336a25e51',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/provenance.py|scope=<module>.<locals>.discover_git_provenance|callee=subprocess.run|ordinal=2',
     'line': 169,
     'necessity_reason': 'The exact Git commit is required for the repository provenance '
                         'coordinate.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 2,
     'path': 'src/verifier/core/provenance.py',
     'scope': '<module>.<locals>.discover_git_provenance',
     'source_ast_sha256': 'sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:3141316fd08f0168196bfe951d17914dd374ae8ed54c148279695203126e2e6f',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/provenance.py|scope=<module>.<locals>.discover_git_provenance|callee=subprocess.run|ordinal=3',
     'line': 179,
     'necessity_reason': 'The selected branch name is queried so provenance does not infer it from '
                         'a commit alone.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 3,
     'path': 'src/verifier/core/provenance.py',
     'scope': '<module>.<locals>.discover_git_provenance',
     'source_ast_sha256': 'sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:93ada0cd0facddff5ee319d1c0a082b3aa7c1f7e92fb9bd9ab6d61cd76f4221e',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/provenance.py|scope=<module>.<locals>.discover_git_provenance|callee=subprocess.run|ordinal=4',
     'line': 189,
     'necessity_reason': 'The configured remote is queried to distinguish local identity from '
                         'repository origin.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 4,
     'path': 'src/verifier/core/provenance.py',
     'scope': '<module>.<locals>.discover_git_provenance',
     'source_ast_sha256': 'sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:efd89269839d5d65da7c7fea949182ed92a3f8fbdfe44b5dca31ad643fa433d0',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/provenance.py|scope=<module>.<locals>.discover_git_provenance|callee=subprocess.run|ordinal=5',
     'line': 201,
     'necessity_reason': 'Git status is required to retain whether the provenance coordinate has '
                         'local changes.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 5,
     'path': 'src/verifier/core/provenance.py',
     'scope': '<module>.<locals>.discover_git_provenance',
     'source_ast_sha256': 'sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:b96a72f862dd81bd80fe45016a8ad9db8ce8cd2e172c2072bd68382fed84733b',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/core/run.py|scope=<module>.<locals>.capture_run|callee=subprocess.run|ordinal=1',
     'line': 915,
     'necessity_reason': 'A selected verifier command must run for capture_run to collect its '
                         'bounded result; the capture-owned parent-interface record is sealed '
                         'before later result processing.',
     'observation_disposition': 'PARENT_INTERFACE_OBSERVED',
     'ordinal': 1,
     'path': 'src/verifier/core/run.py',
     'scope': '<module>.<locals>.capture_run',
     'source_ast_sha256': 'sha256:ed640ca6782bdbbc7f3310234d73decdb35c89ad03a2fc014e12b2db9f6ca373',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:1dffbf2b43322fdb5e8b408e3ff86d86f7e32f88b64df18a9fedc849768c9bbe',
     'unobserved_gaps': ['inherited-environment',
                         'inherited-stdin',
                         'pid-and-process-tree',
                         'descendants',
                         'network',
                         'undeclared-filesystem',
                         'external-effects']},
    {'call_sha256': 'sha256:95feab46e5ce02bed8ba1b1796c1e0435efe82c6cc84e600b9f1fd42324d3878',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/domains/contracts/sim_resource.py|scope=<module>.<locals>.assess_fresh_sim_resource|callee=subprocess.run|ordinal=1',
     'line': 434,
     'necessity_reason': 'SIM resource capture requires a fresh isolated meter process for the '
                         'selected trajectory.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/domains/contracts/sim_resource.py',
     'scope': '<module>.<locals>.assess_fresh_sim_resource',
     'source_ast_sha256': 'sha256:17f36f4198fa8887182b363779b33b72cfb76a338515b0e59dfbbe665b29faed',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:838da6f7729ff4559bd13163ab2bb2586059750ecc113b9037d6746cca3dfde1',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:5688600163e33882502b1f9ae5d8032d46440a92965e5421d5aea34fb311574a',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/domains/contracts/sim_resource_fresh.py|scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1',
     'line': 133,
     'necessity_reason': 'The fresh SIM mechanism requires a new isolated interpreter for its '
                         'selected bootstrap.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/domains/contracts/sim_resource_fresh.py',
     'scope': '<module>.<locals>._run',
     'source_ast_sha256': 'sha256:85a8e037a305ce7ec93b240d9aa0afa2ce8fa1a803cb661732d6de6551cca061',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:5d8e08c5f9f6837504fc8b187e08d1d2d95ffdf34f67d3602bae55a227a1639d',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:0e64088985bed151304d9a5dff0cf7bd1ba7d420e6059f7bd0e3079e6bd9b137',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/hardware/adapters/amd.py|scope=<module>.<locals>.AmdAdapter.<locals>.discover|callee=subprocess.run|ordinal=1',
     'line': 87,
     'necessity_reason': 'Advanced Micro Devices (AMD) device discovery requires the selected '
                         'vendor utility to report local adapter data.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/hardware/adapters/amd.py',
     'scope': '<module>.<locals>.AmdAdapter.<locals>.discover',
     'source_ast_sha256': 'sha256:c5fb07f671d4144b69080987a4b86c0a02771a6b2369c92db69b208087397f22',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:165c41f69f200e37454e18bb0cf223c54faf99fe98eb181d15595394ca4d2d76',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:26b789b2b8b842e643b0bb56bad49481f62dc604b348bde6c48502e32f13f9b7',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/hardware/adapters/nvidia.py|scope=<module>.<locals>.NvidiaAdapter.<locals>.discover|callee=subprocess.run|ordinal=1',
     'line': 53,
     'necessity_reason': 'NVIDIA device discovery requires the selected vendor utility to report '
                         'local adapter data.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/hardware/adapters/nvidia.py',
     'scope': '<module>.<locals>.NvidiaAdapter.<locals>.discover',
     'source_ast_sha256': 'sha256:17fe035074ec6861091da8b1c6787796e1dd92f0607452329f0e927e2f399bc8',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:4e6a5c41323c7f02a9289cc65fab603b748d594495e7dd865440462841520a42',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:2c72c7be80dcc6ace0eb68bb034b6482833cb2e42f4625d2bc9397872a755bd5',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/interoperability/deriver_self_status.py|scope=<module>.<locals>._execute|callee=subprocess.Popen|ordinal=1',
     'line': 449,
     'necessity_reason': 'The selected external deriver must run for its bounded self-status '
                         'transcript to exist.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/interoperability/deriver_self_status.py',
     'scope': '<module>.<locals>._execute',
     'source_ast_sha256': 'sha256:87feb5bf401b1ff9235f799823b4e87cf01c14c87be99227fe2ca9c772f7748f',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:dea126b0b249a9fe2b08a4ce369c4eeb5dc45fa8155b7492a8fa87a578c4f4fd',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:71d9998e14fca589b1d516f2fd1def39c9647eb71b591cba0e43b5ff47e37ab4',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/interoperability/deriver_self_status.py|scope=<module>.<locals>._recheck_execute|callee=subprocess.Popen|ordinal=1',
     'line': 573,
     'necessity_reason': 'Independent deriver recheck requires a separate fresh process rather '
                         'than replaying one transcript.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/interoperability/deriver_self_status.py',
     'scope': '<module>.<locals>._recheck_execute',
     'source_ast_sha256': 'sha256:87feb5bf401b1ff9235f799823b4e87cf01c14c87be99227fe2ca9c772f7748f',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:dea126b0b249a9fe2b08a4ce369c4eeb5dc45fa8155b7492a8fa87a578c4f4fd',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:fefc3f7b78fdfdd75907e75e1a73a3db06707b3a5cf443bc1396381d4b9e5b49',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/explanation_projection.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1',
     'line': 650,
     'necessity_reason': 'Explanation projection queries selected Git state rather than guessing '
                         'repository metadata.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/explanation_projection.py',
     'scope': '<module>.<locals>._git',
     'source_ast_sha256': 'sha256:01d0ad415a8f2148dfe790a6bce18d9bcb0e44d11bfe440156e6b2af4803b732',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:bacaae61fcb927d78018366d66a1ff7d7936f1dd4bcb6c5ea6fb099d2337d91c',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:b5ab93e1ce18eae9b36b599466e5a3d25dab8d3f92a1ed0ce5f79e728e0c302d',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/gate.py|scope=<module>.<locals>.run_pr_gate|callee=subprocess.run|ordinal=1',
     'line': 525,
     'necessity_reason': 'The pull-request gate queries HEAD so its result is bound to an exact '
                         'repository revision.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/gate.py',
     'scope': '<module>.<locals>.run_pr_gate',
     'source_ast_sha256': 'sha256:e2cdaeffa92c26e68c1a130f0b49205088d5635d7e40f3aef2786d220be29ff3',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:944105d4c12e4a0465301e7c52717a4042ab167e6139d231db6e96dab5d60f67',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:1a2351b12918695e6c73f88cf54c5371ea618d235b3557ad46b268b0515a8734',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/gate_pipeline.py|scope=<module>.<locals>._command|callee=subprocess.Popen|ordinal=1',
     'line': 269,
     'necessity_reason': 'A declared gate command must run for the pipeline to collect its bounded '
                         'output and exit status.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/gate_pipeline.py',
     'scope': '<module>.<locals>._command',
     'source_ast_sha256': 'sha256:b05ad705b33666d429da93787527bd3b39a67febd98059b742b5367ab21e6e73',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:1f1d8fa869a6efe40a84ab9ab46aae3e79eebbf75458d6b47f3fde73184c41cf',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:78813266fac7fb293b9b790a4e45d3ae2902af1689095ffa94efa8676c68d46b',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/manifest_write_worker.py|scope=<module>.<locals>.observe.<locals>.repository|callee=subprocess.run|ordinal=1',
     'line': 47,
     'necessity_reason': 'The manifest-write worker creates a private Git repository to observe '
                         'repository-bound behavior.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/manifest_write_worker.py',
     'scope': '<module>.<locals>.observe.<locals>.repository',
     'source_ast_sha256': 'sha256:2e461dd36e7e66d9ed365a06623577ba131f84378b7ba300fd04fe4f843e61fa',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:e5edc802a8f7ac792a540281d1111058daefa64aaa9a724f97b5471ee4fd9297',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:288a9016396a98bed557a6110c085d2956fb6c50387276f1891e491e1d31122c',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1',
     'line': 225,
     'necessity_reason': 'Namespace admission requires the independent Node reconciler under '
                         'bounded input, output, error, and deadline controls for its '
                         'cross-runtime comparison.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/namespace_admission.py',
     'scope': '<module>.<locals>._run_bounded_reconciler',
     'source_ast_sha256': 'sha256:a69b34a58fdaae572310d711a0f6333f2a73cb07c014182597567898418f0190',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:d4782de8dbfc285a3fe3efb20d1f968a93634e5992e7ab056f842b14a5caa803',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:b4fa577ea2b5c26b7be4e46ab75140952aa6f91a18e7f13a2c01ef08b3b990dc',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1',
     'line': 301,
     'necessity_reason': 'Namespace admission queries the selected source revision to bind the '
                         'admission record.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/namespace_admission.py',
     'scope': '<module>.<locals>._source_revision',
     'source_ast_sha256': 'sha256:a69b34a58fdaae572310d711a0f6333f2a73cb07c014182597567898418f0190',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:d4782de8dbfc285a3fe3efb20d1f968a93634e5992e7ab056f842b14a5caa803',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:6928fb95ea13a383c0ecf65c968f174acca0bdd973730af670cf3e7f9b8b78fd',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/namespace_javascript.py|scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1',
     'line': 31,
     'necessity_reason': 'JavaScript namespace inspection requires a fresh fixed Python worker '
                         'boundary.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/namespace_javascript.py',
     'scope': '<module>.<locals>._run',
     'source_ast_sha256': 'sha256:4a50bd2bd26421d270080b8a5bd24169565d77475bd46e355d7dd9a4bdd109ee',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:e84e53346d634512a5d880597248b83a6d1e6cc8fd1ed89ad94c88736f4d1050',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:85fbce03f249538099714f844afccd17f93d1777391b03e35be21fc8fc7ad006',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/namespace_systems.py|scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1',
     'line': 91,
     'necessity_reason': 'Systems-language namespace inspection requires a fresh fixed Python '
                         'worker boundary.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/namespace_systems.py',
     'scope': '<module>.<locals>._run',
     'source_ast_sha256': 'sha256:48bfee0eb4d5b949ed6254ebace478e4674a9eeee70c8fa894696818d95f8dd8',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:124bc6737eb4d69828c29a12c640dec6846cbf6c188be9fab5910a105e388439',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:4abaacd64144c7ef5c2d7f23020d3203d860df071ebdb7f838f938a200713df2',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/namespace_workflows.py|scope=<module>.<locals>._run|callee=subprocess.Popen|ordinal=1',
     'line': 67,
     'necessity_reason': 'Workflow namespace inspection requires a fresh fixed Python worker '
                         'boundary.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/namespace_workflows.py',
     'scope': '<module>.<locals>._run',
     'source_ast_sha256': 'sha256:2bdeed1da028f181517561ad0e1448467cf046222a245ec347e5c8b776bd4cbe',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:81c8eabb6b0b82c6b22ba8ee149e81b662553be793bb23cc63381c9ea2728b33',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:efddd4e037130fe0e623fe3075b338ce202d6fab2f045b41849a94790a285097',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/package_execution.py|scope=<module>.<locals>.execute_bound|callee=subprocess.run|ordinal=1',
     'line': 302,
     'necessity_reason': 'A selected package execution adapter requires its fixed worker to run in '
                         'a fresh interpreter.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/package_execution.py',
     'scope': '<module>.<locals>.execute_bound',
     'source_ast_sha256': 'sha256:64fed332b182655f52a9b1728373536dc6bb2ae61aeafa884806d693c3aae8cf',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:a8a4a7c696494cf8b00ae298c7cc54699b3497eb1699ff85fe49dc2d50dfea73',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:3d033cef4f408b37ccbe9085804e4fe31f918ededb5488097f987ee9c0fdcc87',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/polish_requirements.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1',
     'line': 164,
     'necessity_reason': 'Polish requirement evidence queries Git so repository state is explicit '
                         'rather than inferred.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/polish_requirements.py',
     'scope': '<module>.<locals>._git',
     'source_ast_sha256': 'sha256:102e7c619cb5959b289f47be6d48bd09f1564642ec8378bbf3a1a03de3e65ba8',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:9db0cdd5c87ac777fc8e5ef97f52820c345eee57f36c64995f381732421001cb',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:796e6e983c2502fd1f2a918b8b54dcea185fe04084a689598c584cb389534404',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/prdel.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1',
     'line': 138,
     'necessity_reason': 'PRDEL metadata queries Git so its source coordinate is captured from the '
                         'selected repository.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/prdel.py',
     'scope': '<module>.<locals>._git',
     'source_ast_sha256': 'sha256:70cfc4370a9ff6e2ed5764f186eeb03ce818535859dfc635cba6959fa29ddf63',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:08091a0e117023f673ed93e3dc3a15083f3a295f4b8a5286c9945e1a09b43a1a',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:6572298ae2a9765b625d1679211bc0dc4d2dd22f332b9fd963a0e28d19b99c36',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/prdel_evidence.py|scope=<module>.<locals>._run_check|callee=subprocess.Popen|ordinal=1',
     'line': 389,
     'necessity_reason': 'PRDEL evidence requires the selected replay checks to run with bounded '
                         'streamed output.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/prdel_evidence.py',
     'scope': '<module>.<locals>._run_check',
     'source_ast_sha256': 'sha256:039a9195872d39915a4a94f564435906082a685b37c6a36e5997fab75aa58238',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:c777c20300db63c849bb68d2a00b7ee61057c41f01167208b5718dba05631e23',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:89085ee5e6c928276b54d46e4c0f10c6c138c491d4223664832a3539fb7fcdc7',
     'callee': 'subprocess.Popen',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/secret_gate.py|scope=<module>.<locals>._process|callee=subprocess.Popen|ordinal=1',
     'line': 158,
     'necessity_reason': 'Secret scanning requires the selected scanner process to receive content '
                         'and return bounded output.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/secret_gate.py',
     'scope': '<module>.<locals>._process',
     'source_ast_sha256': 'sha256:702344ee261072f8d99e0ec4acf8f44374b9e37c9d99e2bdc1e4acb0f35152b5',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:e797d5d9d74f809a75f75a7c5dcbfa662220e8235ed9a82dba45d7605ffb6aac',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:89d2df16a883f3dd50a9c0bdcf2f9e67a4368be15373b4b9f036185acfd748d1',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/self_polish_estate.py|scope=<module>.<locals>._run_git|callee=subprocess.run|ordinal=1',
     'line': 151,
     'necessity_reason': 'Self-polish estate inventory queries Git to bind repository state and '
                         'retained source changes.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/self_polish_estate.py',
     'scope': '<module>.<locals>._run_git',
     'source_ast_sha256': 'sha256:9f0013884101bcebbdf27bb92a2182531dc31930b68bb576e20b86bcd56e60bd',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:a834120045042f216b8a3bd6a5b1a7ac2b66b6e261280bd88ac96c53f74b8274',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:945936464576c96e1cf9ac0442419cfb70e9fbe7f4a0778c667d959039703fc3',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/self_polish_evidence.py|scope=<module>.<locals>._run_pytest|callee=subprocess.run|ordinal=1',
     'line': 467,
     'necessity_reason': 'Selected self-polish tests must run to produce fresh bounded test '
                         'evidence.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/self_polish_evidence.py',
     'scope': '<module>.<locals>._run_pytest',
     'source_ast_sha256': 'sha256:e95f6775c20fa6a1ab1649a8e36efa7cb809d8f62213c5b56d2348af680a04fa',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:492e32066ffcbcbe8d73d5e4743c6b7be31380dd9595abb2ae483d1cc8f64ef3',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:107329286e428cc7af69aaf409b103ae6b4179e714649552c083cad67e915790',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1',
     'line': 274,
     'necessity_reason': 'Tier-zero structural reconciliation requires the independent Node '
                         'implementation.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/tier_zero.py',
     'scope': '<module>.<locals>._node_structural_reconciliation',
     'source_ast_sha256': 'sha256:01a37b3494804355dff96df7a21ac0c56d93a2f3f8db6d52a0e6609ca383fa13',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:54a1dd592b9c14083deb6494b51dc8582a61ef2790fec870ee7f1be781f77b07',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
    {'call_sha256': 'sha256:5303f8e6361bad7d97ac89d02d7b1bb866e22e76306b5b934d497b6128aedd0a',
     'callee': 'subprocess.run',
     'embedded_name': None,
     'launch_id': 'src/verifier/runtime/worker_protocol_worker.py|scope=<module>.<locals>.observe.<locals>.capture|callee=subprocess.run|ordinal=1',
     'line': 62,
     'necessity_reason': 'The worker-protocol control must invoke the original launch function '
                         'while capturing its arguments.',
     'observation_disposition': 'SOURCE_ENUMERATION_ONLY',
     'ordinal': 1,
     'path': 'src/verifier/runtime/worker_protocol_worker.py',
     'scope': '<module>.<locals>.observe.<locals>.capture',
     'source_ast_sha256': 'sha256:c016bb0a6fb69a3cf8fdcad39b7bb58e744f4b6718b8404e170415c27a4ceafa',
     'source_kind': 'python-file',
     'source_sha256': 'sha256:d3f4d18cb87d781bb9fe08b5835d5b7717df6098ddacf484be996d4a94cf057d',
     'unobserved_gaps': ['reachability',
                         'resolved-arguments',
                         'runtime-outcome',
                         'child-effects',
                         'descendants',
                         'sandboxing',
                         'process-apis-outside-vocabulary']},
)
_REPOSITORY = Path(__file__).resolve().parents[1]
_ADDED_ID = (
    "src/verifier/runtime/policy_enforcement_routes.py"
    "|scope=<module>.<locals>.evaluate_routes|callee=subprocess.run|ordinal=1"
)
_MODEL_CORRIGIBILITY_ID = (
    "src/verifier/domains/contracts/model_corrigibility.py"
    "|scope=<module>.<locals>._invoke_worker|callee=subprocess.run|ordinal=1"
)
_CALL_CHANGED_ID = (
    "src/verifier/hardware/adapters/amd.py"
    "|scope=<module>.<locals>.AmdAdapter.<locals>.discover|callee=subprocess.run|ordinal=1"
)
_ANNOTATION_CHANGED_ID = (
    "extensions/languages/src/vstd_languages/__init__.py::WORKER"
    "|scope=<module>|callee=subprocess.run|ordinal=1"
)
_SOURCE_ONLY_ID = (
    "src/verifier/runtime/tier_zero.py"
    "|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1"
)
_SOURCE_AST_REFRESH_PRIOR = {
    (
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>."
        "_run_package_worker|callee=subprocess.run|ordinal=1"
    ): {
        "line": 71,
        "source_sha256": "sha256:d35083d330292ec0feec883d6db60f32edbfc33930b49ec81ec9ec3dee8a16a8",
        "source_ast_sha256": "sha256:aaead622284bbb705e2b8016f73dc2de18b0db48948b8253fc722e037b8045c8",
    },
    (
        "src/verifier/runtime/policy_enforcement_routes.py|scope=<module>.<locals>."
        "evaluate_routes|callee=subprocess.run|ordinal=1"
    ): {
        "line": 657,
        "source_sha256": "sha256:06504a355e697833626b332aaac345d78a384f2f51ea9cdb832163070d4d9a49",
        "source_ast_sha256": "sha256:a71c62acce99b9a32a911d307a4cb901166a3584455386c5c27d42e0299ab54a",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>."
        "<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1"
    ): {
        "line": 2681,
        "source_sha256": "sha256:e8b7dcf573a8f55672e03ccce00fe7e59cf6c38823166d54983110fd596c6bc1",
        "source_ast_sha256": "sha256:f9b40e37734291aee8758d62bbc03031d6fcb34c2ec9d69c23a38ab3822ca176",
    },
}
_DOCUMENTED_APPLICABILITY_PRIOR = {
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_run_bounded_reconciler|callee=subprocess.Popen|ordinal=1"
    ): {
        "line": 237,
        "source_sha256": "sha256:940c101d434c823ecdd58e348f6bc757760eae4505db61037708ac272cbb93c2",
        "source_ast_sha256": "sha256:80f4172359bae0045664441db4eaa690304fd22cb46618a5c99881e0dd46d6c1",
    },
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_source_revision|callee=subprocess.run|ordinal=1"
    ): {
        "line": 313,
        "source_sha256": "sha256:940c101d434c823ecdd58e348f6bc757760eae4505db61037708ac272cbb93c2",
        "source_ast_sha256": "sha256:80f4172359bae0045664441db4eaa690304fd22cb46618a5c99881e0dd46d6c1",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._git|callee=subprocess.run|ordinal=1"
    ): {
        "line": 156,
        "source_sha256": "sha256:5e0fefad8411087f3fce35978c3b015ac9ceee0365b6d796a99602871fe08d4e",
        "source_ast_sha256": "sha256:1541685f79297a5cf0755f7ab5270f5ae8a7b95a7ace9518fe67ff95d1ff7d67",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._step|callee=subprocess.run|ordinal=1"
    ): {
        "line": 200,
        "source_sha256": "sha256:5e0fefad8411087f3fce35978c3b015ac9ceee0365b6d796a99602871fe08d4e",
        "source_ast_sha256": "sha256:1541685f79297a5cf0755f7ab5270f5ae8a7b95a7ace9518fe67ff95d1ff7d67",
    },
}
_CONSERVATIVE_APPLIES_PRIOR = {
    (
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>."
        "_node_structural_reconciliation|callee=subprocess.run|ordinal=1"
    ): {
        "line": 299,
        "source_sha256": "sha256:a52562a178be128968c6cf6894fe4696108683bf40e0e4af3fcc9b0358ac1207",
        "source_ast_sha256": "sha256:d1f2d70caaa7ac986357a6c22fe6a1e8b260c60237c8bffe7ffbdf8cac1a6ff2",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._git|callee=subprocess.run|ordinal=1"
    ): {
        "line": 222,
        "source_sha256": "sha256:536ef2f57ed931ade3d46e5dfeab7c6c7cda7b1b8af2ea1d882c7398a8ffa00a",
        "source_ast_sha256": "sha256:0ba1b662f7861db435536b73082cf1cb26f26ac793c88ed94e3d332a599e0d70",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._step|callee=subprocess.run|ordinal=1"
    ): {
        "line": 266,
        "source_sha256": "sha256:536ef2f57ed931ade3d46e5dfeab7c6c7cda7b1b8af2ea1d882c7398a8ffa00a",
        "source_ast_sha256": "sha256:0ba1b662f7861db435536b73082cf1cb26f26ac793c88ed94e3d332a599e0d70",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>."
        "<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1"
    ): {
        "line": 2734,
        "source_sha256": "sha256:c2767cb729a35f034451755729b544b0729eac031a05882c54e7b7e50f46cb1d",
        "source_ast_sha256": "sha256:71c0c6fc09158ae89265d3cf7ee79b69776ef352112a71b0b20f29331431234e",
    },
}
_NORMALIZED_OUTPUT_PRIOR = {
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_run_bounded_reconciler|callee=subprocess.Popen|ordinal=1"
    ): {
        "line": 259,
        "source_sha256": "sha256:b3977ed1fc4c81e082f8e232627eda6ba7b4ba722c9181f4e31d644238580008",
        "source_ast_sha256": "sha256:bcc45c8ae65c5befc048b56e7abd408fb4240be8242cd9106f41b0e3345d65f8",
    },
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_source_revision|callee=subprocess.run|ordinal=1"
    ): {
        "line": 335,
        "source_sha256": "sha256:b3977ed1fc4c81e082f8e232627eda6ba7b4ba722c9181f4e31d644238580008",
        "source_ast_sha256": "sha256:bcc45c8ae65c5befc048b56e7abd408fb4240be8242cd9106f41b0e3345d65f8",
    },
}
_CONSEQUENCE_PARITY_PRIOR = {
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_run_bounded_reconciler|callee=subprocess.Popen|ordinal=1"
    ): {
        "line": 259,
        "source_sha256": "sha256:d72aaeb5409b6ac9dc4f5f05ad52902e400c67fde8a08afd978d14d6b8b57117",
        "source_ast_sha256": "sha256:c68923aabf290665b20287e70f503bf3f27ba8323ad2427430d15bbfc04448e6",
    },
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_source_revision|callee=subprocess.run|ordinal=1"
    ): {
        "line": 335,
        "source_sha256": "sha256:d72aaeb5409b6ac9dc4f5f05ad52902e400c67fde8a08afd978d14d6b8b57117",
        "source_ast_sha256": "sha256:c68923aabf290665b20287e70f503bf3f27ba8323ad2427430d15bbfc04448e6",
    },
}
_TIER_ZERO_BOUNDARY_PRIOR = {
    (
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>."
        "_node_structural_reconciliation|callee=subprocess.run|ordinal=1"
    ): {
        "line": 317,
        "source_sha256": "sha256:eb34b770cd6c2627f949031aa8ce0ec886dffa6d884dfea5d5f879ed7526a9bf",
        "source_ast_sha256": "sha256:e44453822abbd9a8d56b1ba4246435cea2ff7b7437b5bc6acba9dcda2818f0df",
    },
}
_TIER_ZERO_REASON_RETENTION_PRIOR = {
    (
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>."
        "_node_structural_reconciliation|callee=subprocess.run|ordinal=1"
    ): {
        "line": 342,
        "source_sha256": "sha256:1fe930429e853bd8314b0914d825d9b5d0c55395971100136aee363867f564cc",
        "source_ast_sha256": "sha256:ed4f68becbc8b2477101146b8a868500771b707c5a1d7b850973ebd9ab2fe2f2",
    },
}
_TIER_ZERO_RETENTION_DENOMINATOR_PRIOR = {
    (
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>."
        "_node_structural_reconciliation|callee=subprocess.run|ordinal=1"
    ): {
        "line": 342,
        "source_sha256": "sha256:7dd259dc7ae67a732f34cdc2cf84a09655d902dca55b5f1884dfc1b059ddf6a1",
        "source_ast_sha256": "sha256:3fb476ca0e5bb4e51a154dd6553e9c0d6fe9d58323645a02603df16fbd247c2e",
    },
}
_NAMESPACE_RECONCILIATION_TIMEOUT_PRIOR = {
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_run_bounded_reconciler|callee=subprocess.Popen|ordinal=1"
    ): {
        "line": 264,
        "source_sha256": "sha256:d2ab01561ac48d979e723417aa1c5badbdc16eb2d7bf1c5f85ed6cd9ad5b373d",
        "source_ast_sha256": "sha256:d9f776abd2f6a8c22f1272b425ff2d1b357892fe3cb661b31e3e87a33f715e72",
    },
    (
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>."
        "_source_revision|callee=subprocess.run|ordinal=1"
    ): {
        "line": 340,
        "source_sha256": "sha256:d2ab01561ac48d979e723417aa1c5badbdc16eb2d7bf1c5f85ed6cd9ad5b373d",
        "source_ast_sha256": "sha256:d9f776abd2f6a8c22f1272b425ff2d1b357892fe3cb661b31e3e87a33f715e72",
    },
}
_ROOT_REASON_CAPACITY_PRIOR = {
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._git|callee=subprocess.run|ordinal=1"
    ): {
        "source_sha256": "sha256:13cfbf53bed56607966e00e36d02d9abb71d78cf70f335bbb39c7863e89d1904",
        "source_ast_sha256": "sha256:b4ff1f4a5a05e230c37261b7dc367c2dd6b323924bf9400339a1113d42272e48",
    },
    (
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>."
        "<locals>._step|callee=subprocess.run|ordinal=1"
    ): {
        "source_sha256": "sha256:13cfbf53bed56607966e00e36d02d9abb71d78cf70f335bbb39c7863e89d1904",
        "source_ast_sha256": "sha256:b4ff1f4a5a05e230c37261b7dc367c2dd6b323924bf9400339a1113d42272e48",
    },
}
_FRESH_SIM_REFUSAL_PRIOR = {
    (
        "src/verifier/domains/contracts/sim_resource_fresh.py|"
        "scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1"
    ): {
        "line": 140,
        "source_sha256": "sha256:d254cd1ea4ad229dd5eafcffe246d4d9afe89f4436eb7dcf979fd3b701c9a4f3",
        "source_ast_sha256": "sha256:76dfab9bea5c3ee8694b5909604a9bf75672b27cd2d7736fdba2cef9f8290dd9",
    },
}
_WORKER_PROTOCOL_TIMEOUT_PRIOR = {
    (
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>."
        "_run_package_worker|callee=subprocess.run|ordinal=1"
    ): {
        "line": 71,
        "source_sha256": "sha256:8a746263074c781171f0847ea388e61c2ed14cb6d3330f06084ef04b47dc85bf",
        "source_ast_sha256": "sha256:dff1395254e8165dc9cd95f0134477960ab90a62d0b2c0b3668ae742df3bddd4",
    },
}
_MANIFEST_RETRY_LIMIT_ID = (
    "src/verifier/runtime/manifest_write_worker.py|scope=<module>.<locals>."
    "observe.<locals>.repository|callee=subprocess.run|ordinal=1"
)
_MANIFEST_RETRY_LIMIT_PRIOR = {
    _MANIFEST_RETRY_LIMIT_ID: {
        "source_sha256": "sha256:e5edc802a8f7ac792a540281d1111058daefa64aaa9a724f97b5471ee4fd9297",
        "source_ast_sha256": "sha256:2e461dd36e7e66d9ed365a06623577ba131f84378b7ba300fd04fe4f843e61fa",
    },
}
_PRDEL_LARGE_ARTIFACT_ID = (
    "src/verifier/runtime/prdel.py|scope=<module>.<locals>._git|"
    "callee=subprocess.run|ordinal=1"
)
_PRDEL_LARGE_ARTIFACT_PRIOR = {
    _PRDEL_LARGE_ARTIFACT_ID: {
        "line": 138,
        "source_sha256": (
            "sha256:08091a0e117023f673ed93e3dc3a15083f3a295f4b8a5286c9945e1a09b43a1a"
        ),
        "source_ast_sha256": (
            "sha256:70cfc4370a9ff6e2ed5764f186eeb03ce818535859dfc635cba6959fa29ddf63"
        ),
    },
}


def _catalog_rows() -> list[dict]:
    return [dict(row) for row in applicability.PACKAGE_LAUNCH_DECLARATIONS]


def _prior_rows() -> list[dict]:
    return [dict(row) for row in _ADMITTED_PRIOR_LAUNCHES]


def _live_discovery() -> dict:
    return applicability.discover_repository(_REPOSITORY)


def _pre_worker_protocol_timeout_discovery() -> dict:
    discovery = _pre_manifest_retry_limit_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_WORKER_PROTOCOL_TIMEOUT_PRIOR.get(row["launch_id"], {}),
            }
            for row in discovery["launches"]
        ],
    }


def _pre_manifest_retry_limit_discovery() -> dict:
    discovery = _pre_prdel_large_artifact_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_MANIFEST_RETRY_LIMIT_PRIOR.get(row["launch_id"], {}),
            }
            for row in discovery["launches"]
        ],
    }


def _pre_prdel_large_artifact_discovery() -> dict:
    discovery = _live_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_PRDEL_LARGE_ARTIFACT_PRIOR.get(row["launch_id"], {}),
            }
            for row in discovery["launches"]
        ],
    }


def _pre_namespace_reconciliation_timeout_discovery() -> dict:
    discovery = _pre_fresh_sim_refusal_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_ROOT_REASON_CAPACITY_PRIOR.get(row["launch_id"], {}),
                **_NAMESPACE_RECONCILIATION_TIMEOUT_PRIOR.get(
                    row["launch_id"], {}
                ),
            }
            for row in discovery["launches"]
        ],
    }


def _pre_root_reason_capacity_discovery() -> dict:
    discovery = _pre_fresh_sim_refusal_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_ROOT_REASON_CAPACITY_PRIOR.get(row["launch_id"], {})}
            for row in discovery["launches"]
        ],
    }


def _pre_fresh_sim_refusal_discovery() -> dict:
    discovery = _pre_worker_protocol_timeout_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_FRESH_SIM_REFUSAL_PRIOR.get(row["launch_id"], {})}
            for row in discovery["launches"]
        ],
    }


def _pre_tier_zero_boundary_discovery() -> dict:
    discovery = _pre_namespace_reconciliation_timeout_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_TIER_ZERO_BOUNDARY_PRIOR.get(row["launch_id"], {})}
            for row in discovery["launches"]
        ],
    }


def _tier_zero_boundary_discovery() -> dict:
    discovery = _pre_namespace_reconciliation_timeout_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_TIER_ZERO_REASON_RETENTION_PRIOR.get(row["launch_id"], {}),
            }
            for row in discovery["launches"]
        ],
    }


def _tier_zero_reason_retention_discovery() -> dict:
    discovery = _pre_namespace_reconciliation_timeout_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_TIER_ZERO_RETENTION_DENOMINATOR_PRIOR.get(
                    row["launch_id"], {}
                ),
            }
            for row in discovery["launches"]
        ],
    }


def _source_ast_refresh_prior() -> list[dict]:
    return [
        {**row, **_SOURCE_AST_REFRESH_PRIOR.get(row["launch_id"], {})}
        for row in _documented_applicability_prior()
    ]


def _documented_applicability_prior() -> list[dict]:
    return [
        {**row, **_DOCUMENTED_APPLICABILITY_PRIOR.get(row["launch_id"], {})}
        for row in _conservative_applies_prior()
    ]


def _documented_applicability_discovery_prior() -> dict:
    discovery = _pre_tier_zero_boundary_discovery()
    return {
        **discovery,
        "launches": [
            {
                **row,
                **_CONSERVATIVE_APPLIES_PRIOR.get(row["launch_id"], {}),
                **_DOCUMENTED_APPLICABILITY_PRIOR.get(row["launch_id"], {}),
            }
            for row in discovery["launches"]
        ],
    }


def _conservative_applies_prior() -> list[dict]:
    return [
        {**row, **_CONSERVATIVE_APPLIES_PRIOR.get(row["launch_id"], {})}
        for row in _normalized_output_prior()
    ]


def _conservative_applies_discovery_prior() -> dict:
    discovery = _pre_tier_zero_boundary_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_CONSERVATIVE_APPLIES_PRIOR.get(row["launch_id"], {})}
            for row in _normalized_output_discovery_prior()["launches"]
        ],
    }


def _normalized_output_prior() -> list[dict]:
    return [
        {**row, **_NORMALIZED_OUTPUT_PRIOR.get(row["launch_id"], {})}
        for row in _consequence_parity_prior()
    ]


def _normalized_output_discovery_prior() -> dict:
    discovery = _pre_tier_zero_boundary_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_NORMALIZED_OUTPUT_PRIOR.get(row["launch_id"], {})}
            for row in discovery["launches"]
        ],
    }


def _consequence_parity_prior() -> list[dict]:
    return [
        {**row, **_CONSEQUENCE_PARITY_PRIOR.get(row["launch_id"], {})}
        for row in _tier_zero_boundary_prior()
    ]


def _consequence_parity_discovery_prior() -> dict:
    discovery = _pre_tier_zero_boundary_discovery()
    return {
        **discovery,
        "launches": [
            {**row, **_CONSEQUENCE_PARITY_PRIOR.get(row["launch_id"], {})}
            for row in discovery["launches"]
        ],
    }


def _tier_zero_boundary_prior() -> list[dict]:
    return [
        {**row, **_TIER_ZERO_BOUNDARY_PRIOR.get(row["launch_id"], {})}
        for row in _tier_zero_reason_retention_prior()
    ]


def _tier_zero_reason_retention_prior() -> list[dict]:
    return [
        {**row, **_TIER_ZERO_REASON_RETENTION_PRIOR.get(row["launch_id"], {})}
        for row in _tier_zero_retention_denominator_prior()
    ]


def _tier_zero_retention_denominator_prior() -> list[dict]:
    return [
        {
            **row,
            **_TIER_ZERO_RETENTION_DENOMINATOR_PRIOR.get(row["launch_id"], {}),
        }
        for row in _namespace_reconciliation_timeout_prior()
    ]


def _namespace_reconciliation_timeout_prior() -> list[dict]:
    return [
        {
            **row,
            **_ROOT_REASON_CAPACITY_PRIOR.get(row["launch_id"], {}),
            **_NAMESPACE_RECONCILIATION_TIMEOUT_PRIOR.get(row["launch_id"], {}),
        }
        for row in _fresh_sim_refusal_prior()
    ]


def _root_reason_capacity_prior() -> list[dict]:
    return [
        {**row, **_ROOT_REASON_CAPACITY_PRIOR.get(row["launch_id"], {})}
        for row in _fresh_sim_refusal_prior()
    ]


def _fresh_sim_refusal_prior() -> list[dict]:
    return [
        {**row, **_FRESH_SIM_REFUSAL_PRIOR.get(row["launch_id"], {})}
        for row in _worker_protocol_timeout_prior()
    ]


def _worker_protocol_timeout_prior() -> list[dict]:
    return [
        {
            **row,
            **_WORKER_PROTOCOL_TIMEOUT_PRIOR.get(row["launch_id"], {}),
        }
        for row in _manifest_retry_limit_prior()
    ]


def _manifest_retry_limit_prior() -> list[dict]:
    return [
        {
            **row,
            **_MANIFEST_RETRY_LIMIT_PRIOR.get(row["launch_id"], {}),
        }
        for row in _prdel_large_artifact_prior()
    ]


def _prdel_large_artifact_prior() -> list[dict]:
    return [
        {
            **row,
            **_PRDEL_LARGE_ARTIFACT_PRIOR.get(row["launch_id"], {}),
        }
        for row in _catalog_rows()
    ]


def _replace_row(rows: list[dict], launch_id: str, **changes: object) -> list[dict]:
    return [
        {**row, **changes} if row["launch_id"] == launch_id else row for row in rows
    ]


def _mutated_candidate(name: str) -> tuple[list[dict], list[dict], dict]:
    prior, catalog = _prior_rows(), _catalog_rows()
    discovery = _live_discovery()
    observed = discovery["launches"]
    if name == "partial-missing-added":
        catalog = [row for row in catalog if row["launch_id"] != _ADDED_ID]
    elif name == "extra-unreviewed-row":
        extra = {**catalog[0], "launch_id": catalog[0]["launch_id"] + "|unreviewed"}
        catalog = [*catalog, extra]
    elif name == "reordered-catalog":
        catalog = list(reversed(catalog))
    elif name == "wrong-reason-added":
        catalog = _replace_row(catalog, _ADDED_ID, necessity_reason="Forged reason.")
    elif name == "wrong-reason-model-corrigibility":
        catalog = _replace_row(
            catalog, _MODEL_CORRIGIBILITY_ID, necessity_reason="Forged reason."
        )
    elif name == "partial-missing-model-corrigibility":
        catalog = [row for row in catalog if row["launch_id"] != _MODEL_CORRIGIBILITY_ID]
    elif name == "wrong-disposition-call-changed":
        catalog = _replace_row(
            catalog, _CALL_CHANGED_ID, observation_disposition="FORGED_DISPOSITION"
        )
    elif name == "wrong-gap-annotation":
        annotated = next(
            row for row in catalog if row["launch_id"] == _ANNOTATION_CHANGED_ID
        )
        gaps = [gap for gap in annotated["unobserved_gaps"] if gap != "inherited-environment"]
        catalog = _replace_row(catalog, _ANNOTATION_CHANGED_ID, unobserved_gaps=gaps)
    elif name == "forged-prior-row":
        prior = _replace_row(prior, _CALL_CHANGED_ID, call_sha256="sha256:" + "0" * 64)
    elif name == "future-call-change":
        forged = "sha256:" + "3" * 64
        catalog = _replace_row(catalog, _SOURCE_ONLY_ID, call_sha256=forged)
        observed = _replace_row(observed, _SOURCE_ONLY_ID, call_sha256=forged)
    elif name == "undeclared-source-drift":
        observed = _replace_row(
            observed, _SOURCE_ONLY_ID, source_sha256="sha256:" + "1" * 64
        )
    elif name == "observed-missing-launch":
        observed = observed[:-1]
    elif name == "discovery-not-pass":
        discovery = {**discovery, "status": "FAIL"}
    else:
        raise AssertionError(name)
    return prior, catalog, {**discovery, "launches": observed}


_CANDIDATE_MUTATIONS = (
    "partial-missing-added",
    "partial-missing-model-corrigibility",
    "wrong-reason-model-corrigibility",
    "extra-unreviewed-row",
    "reordered-catalog",
    "wrong-reason-added",
    "wrong-disposition-call-changed",
    "wrong-gap-annotation",
    "forged-prior-row",
    "future-call-change",
    "undeclared-source-drift",
    "observed-missing-launch",
    "discovery-not-pass",
)


def test_reviewed_scope_transition_row_classes_are_the_reviewed_counts() -> None:
    spec = migration._PACKAGE_HARNESS_SCOPE_TRANSITION
    counts = {
        kind: len(spec[kind])
        for kind in ("removed", "added", "call_changed", "annotation_changed", "source_only")
    }
    assert counts == {
        "removed": 2,
        "added": 10,
        "call_changed": 4,
        "annotation_changed": 1,
        "source_only": 5,
    }
    assert len(_prior_rows()) - counts["removed"] + counts["added"] == 40
    assert value_digest(_prior_rows()) == spec["prior"]


def test_reviewed_source_ast_refresh_accepts_exact_current_45_row_advance() -> None:
    spec = migration._PACKAGE_HARNESS_SOURCE_AST_REFRESH_TRANSITION
    assert migration._is_exact_harness_scope_transition(
        _source_ast_refresh_prior(),
        _documented_applicability_prior(),
        _documented_applicability_discovery_prior(),
        transition=spec,
    ) is True


def test_reviewed_documented_applicability_refresh_accepts_exact_current_45_row_advance() -> None:
    spec = migration._PACKAGE_HARNESS_DOCUMENTED_APPLICABILITY_TRANSITION
    assert migration._is_exact_harness_scope_transition(
        _documented_applicability_prior(),
        _conservative_applies_prior(),
        _conservative_applies_discovery_prior(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == set(_DOCUMENTED_APPLICABILITY_PRIOR)


def test_reviewed_conservative_applies_refresh_accepts_exact_current_45_row_advance() -> None:
    spec = migration._PACKAGE_HARNESS_CONSERVATIVE_APPLIES_TRANSITION
    assert value_digest(_conservative_applies_prior()) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        _conservative_applies_prior(),
        _normalized_output_prior(),
        _normalized_output_discovery_prior(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == set(_CONSERVATIVE_APPLIES_PRIOR)


def test_reviewed_normalized_output_refresh_accepts_exact_current_45_row_advance() -> None:
    spec = migration._PACKAGE_HARNESS_NORMALIZED_OUTPUT_TRANSITION
    assert value_digest(_normalized_output_prior()) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        _normalized_output_prior(),
        _consequence_parity_prior(),
        _consequence_parity_discovery_prior(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == set(_NORMALIZED_OUTPUT_PRIOR)


def test_reviewed_consequence_parity_refresh_accepts_exact_current_45_row_advance() -> None:
    spec = migration._PACKAGE_HARNESS_CONSEQUENCE_PARITY_TRANSITION
    assert value_digest(_consequence_parity_prior()) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        _consequence_parity_prior(),
        _tier_zero_boundary_prior(),
        _pre_tier_zero_boundary_discovery(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == set(_CONSEQUENCE_PARITY_PRIOR)


@pytest.mark.parametrize("mutation", _CANDIDATE_MUTATIONS)
def test_reviewed_scope_transition_refuses_partial_reordered_forged_or_future_candidates(
    mutation: str,
) -> None:
    prior, catalog, discovery = _mutated_candidate(mutation)
    assert migration._is_exact_harness_scope_transition(prior, catalog, discovery) is False


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong-reason-added",
        "wrong-reason-model-corrigibility",
        "wrong-disposition-call-changed",
        "wrong-gap-annotation",
        "forged-prior-row",
    ),
)
def test_per_row_pins_refute_candidates_even_when_top_level_digests_are_repinned(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior, catalog, discovery = _mutated_candidate(mutation)
    spec = dict(migration._PACKAGE_HARNESS_SCOPE_TRANSITION)
    spec["prior"] = value_digest(prior)
    spec["catalog"] = value_digest(catalog)
    spec["observed"] = value_digest(discovery["launches"])
    monkeypatch.setattr(migration, "_PACKAGE_HARNESS_SCOPE_TRANSITION", spec)
    assert migration._is_exact_harness_scope_transition(prior, catalog, discovery) is False


def _harness_row(launches: list[dict]) -> tuple[dict, dict]:
    denominator = {
        "schema_version": applicability.MANIFEST_DENOMINATOR_SCHEMA,
        "profile": applicability.PROFILE,
        "launches": launches,
    }
    previous = {
        "surfaces": [applicability.SELECTION_SURFACE],
        "payload": {"direct_launch_denominator": denominator},
    }
    return {"surfaces": [applicability.SELECTION_SURFACE], "payload": {}}, previous


def test_polish_refresh_applies_latest_reviewed_advance_without_advance_flag() -> None:
    row, previous = _harness_row(_prdel_large_artifact_prior())
    migration._refresh_harness_launch_denominator(
        _REPOSITORY,
        row,
        previous,
        select_profile=True,
        refresh_reviewed=True,
        advance_reviewed=False,
    )
    launches = row["payload"]["direct_launch_denominator"]["launches"]
    assert len(launches) == 45
    assert value_digest(launches) == (
        migration._PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION[
            "refreshed"
        ]
    )


def test_reviewed_tier_zero_boundary_refresh_accepts_exact_live_advance() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_BOUNDARY_TRANSITION
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_boundary_prior(),
        _tier_zero_reason_retention_prior(),
        _tier_zero_boundary_discovery(),
        transition=spec,
    ) is True


def test_reviewed_tier_zero_reason_retention_accepts_exact_live_advance() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_REASON_RETENTION_TRANSITION
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_reason_retention_prior(),
        _tier_zero_retention_denominator_prior(),
        _tier_zero_reason_retention_discovery(),
        transition=spec,
    ) is True


def test_reviewed_tier_zero_retention_denominator_accepts_exact_live_advance() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_RETENTION_DENOMINATOR_TRANSITION
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_retention_denominator_prior(),
        _namespace_reconciliation_timeout_prior(),
        _pre_namespace_reconciliation_timeout_discovery(),
        transition=spec,
    ) is True


def test_reviewed_namespace_reconciliation_timeout_accepts_exact_live_advance() -> None:
    spec = migration._PACKAGE_HARNESS_NAMESPACE_RECONCILIATION_TIMEOUT_TRANSITION
    assert value_digest(_namespace_reconciliation_timeout_prior()) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        _namespace_reconciliation_timeout_prior(),
        _root_reason_capacity_prior(),
        _pre_root_reason_capacity_discovery(),
        transition=spec,
    ) is True


def test_reviewed_root_reason_capacity_accepts_exact_live_advance() -> None:
    prior = _root_reason_capacity_prior()
    spec = migration._PACKAGE_HARNESS_ROOT_REASON_CAPACITY_TRANSITION
    assert value_digest(prior) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        prior,
        _fresh_sim_refusal_prior(),
        _pre_fresh_sim_refusal_discovery(),
        transition=spec,
    ) is True


def test_reviewed_fresh_sim_refusal_accepts_exact_live_advance() -> None:
    prior = _fresh_sim_refusal_prior()
    spec = migration._PACKAGE_HARNESS_FRESH_SIM_REFUSAL_TRANSITION
    assert value_digest(prior) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        prior,
        _worker_protocol_timeout_prior(),
        _pre_worker_protocol_timeout_discovery(),
        transition=spec,
    ) is True


def test_reviewed_worker_protocol_timeout_accepts_exact_live_advance() -> None:
    prior = _worker_protocol_timeout_prior()
    spec = migration._PACKAGE_HARNESS_WORKER_PROTOCOL_TIMEOUT_TRANSITION
    assert value_digest(prior) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        prior,
        _manifest_retry_limit_prior(),
        _pre_manifest_retry_limit_discovery(),
        transition=spec,
    ) is True


def test_reviewed_manifest_retry_limit_accepts_exact_live_advance() -> None:
    prior = _manifest_retry_limit_prior()
    spec = migration._PACKAGE_HARNESS_MANIFEST_RETRY_LIMIT_TRANSITION
    assert value_digest(prior) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        prior,
        _prdel_large_artifact_prior(),
        _pre_prdel_large_artifact_discovery(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == {_MANIFEST_RETRY_LIMIT_ID}


def test_reviewed_prdel_large_artifact_accepts_exact_live_advance() -> None:
    prior = _prdel_large_artifact_prior()
    spec = migration._PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION
    assert value_digest(prior) == spec["prior"]
    assert migration._is_exact_harness_scope_transition(
        prior,
        _catalog_rows(),
        _live_discovery(),
        transition=spec,
    ) is True
    assert set(spec["source_only"]) == {_PRDEL_LARGE_ARTIFACT_ID}


def test_reviewed_prdel_large_artifact_refuses_future_source_drift() -> None:
    spec = migration._PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION
    discovery = _live_discovery()
    drifted = _replace_row(
        discovery["launches"],
        _PRDEL_LARGE_ARTIFACT_ID,
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _prdel_large_artifact_prior(),
        _catalog_rows(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_manifest_retry_limit_refuses_future_source_drift() -> None:
    spec = migration._PACKAGE_HARNESS_MANIFEST_RETRY_LIMIT_TRANSITION
    discovery = _live_discovery()
    drifted = _replace_row(
        discovery["launches"],
        _MANIFEST_RETRY_LIMIT_ID,
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _manifest_retry_limit_prior(),
        _catalog_rows(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_tier_zero_boundary_refresh_refuses_unreviewed_live_drift() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_BOUNDARY_TRANSITION
    discovery = _tier_zero_boundary_discovery()
    drifted = _replace_row(
        discovery["launches"],
        next(iter(_TIER_ZERO_BOUNDARY_PRIOR)),
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_boundary_prior(),
        _tier_zero_reason_retention_prior(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_tier_zero_reason_retention_refuses_unreviewed_live_drift() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_REASON_RETENTION_TRANSITION
    discovery = _tier_zero_reason_retention_discovery()
    drifted = _replace_row(
        discovery["launches"],
        next(iter(_TIER_ZERO_REASON_RETENTION_PRIOR)),
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_reason_retention_prior(),
        _tier_zero_retention_denominator_prior(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_tier_zero_retention_denominator_refuses_live_drift() -> None:
    spec = migration._PACKAGE_HARNESS_TIER_ZERO_RETENTION_DENOMINATOR_TRANSITION
    discovery = _live_discovery()
    drifted = _replace_row(
        discovery["launches"],
        next(iter(_TIER_ZERO_RETENTION_DENOMINATOR_PRIOR)),
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _tier_zero_retention_denominator_prior(),
        _catalog_rows(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_consequence_parity_refresh_refuses_unreviewed_live_drift() -> None:
    spec = migration._PACKAGE_HARNESS_CONSEQUENCE_PARITY_TRANSITION
    discovery = _pre_tier_zero_boundary_discovery()
    drifted = _replace_row(
        discovery["launches"],
        next(iter(_CONSEQUENCE_PARITY_PRIOR)),
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _consequence_parity_prior(),
        _catalog_rows(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


def test_reviewed_source_ast_refresh_refuses_unreviewed_live_drift() -> None:
    spec = migration._PACKAGE_HARNESS_SOURCE_AST_REFRESH_TRANSITION
    discovery = _documented_applicability_discovery_prior()
    drifted = _replace_row(
        discovery["launches"],
        next(iter(_SOURCE_AST_REFRESH_PRIOR)),
        source_ast_sha256="sha256:" + "0" * 64,
    )
    assert migration._is_exact_harness_scope_transition(
        _source_ast_refresh_prior(),
        _documented_applicability_prior(),
        {**discovery, "launches": drifted},
        transition=spec,
    ) is False


@pytest.mark.parametrize("advance_reviewed", (False, True))
@pytest.mark.parametrize("mutation", ("drop-last", "forged-call"))
def test_polish_refresh_refuses_other_predecessors_without_writing(
    mutation: str, advance_reviewed: bool
) -> None:
    if mutation == "drop-last":
        prior = _prior_rows()[:-1]
    else:
        prior = _replace_row(_prior_rows(), _CALL_CHANGED_ID, call_sha256="sha256:" + "0" * 64)
    row, previous = _harness_row(prior)
    with pytest.raises(ValueError, match="^PACKAGE_HARNESS_"):
        migration._refresh_harness_launch_denominator(
            _REPOSITORY,
            row,
            previous,
            select_profile=True,
            refresh_reviewed=True,
            advance_reviewed=advance_reviewed,
        )
    assert row["payload"] == {}


def test_polish_refresh_refuses_live_discovery_drift_from_reviewed_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = _live_discovery()
    drifted = _replace_row(
        discovery["launches"], _SOURCE_ONLY_ID, source_sha256="sha256:" + "2" * 64
    )
    drifted_discovery = {**discovery, "launches": drifted}
    monkeypatch.setattr(
        applicability, "discover_repository", lambda _root: drifted_discovery
    )
    row, previous = _harness_row(_prior_rows())
    with pytest.raises(ValueError, match="PACKAGE_HARNESS_SCOPE_TRANSITION_DIFFERS"):
        migration._refresh_harness_launch_denominator(
            _REPOSITORY,
            row,
            previous,
            select_profile=True,
            refresh_reviewed=True,
            advance_reviewed=False,
        )
    assert row["payload"] == {}
