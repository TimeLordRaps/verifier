"""Independent native-result kind boundary for Verifier Standard (VSTD).

The registered checker is trusted code, but a malformed native result must be
refused as a result-contract error. Exact built-in kind text is required before
calling equality; this is not proof of untrusted-code isolation or security-tier
closure. Counts are dimensionless.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import subject_security as security
from test_current_subject_security import fixture, replay


@pytest.mark.parametrize("hostile_comparison", [False, True])
def test_security_native_kind_requires_plain_text_before_comparison(
        hostile_comparison: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = fixture("MODEL")
    certificate, native = replay(request, policy, evidence)
    comparisons: list[str] = []
    class ForeignKind(str):
        def __ne__(self, other: Any) -> bool:
            comparisons.append("foreign comparison executed")
            if hostile_comparison:
                raise AssertionError("foreign native kind comparison executed")
            return False
    altered = {**native, "object_kind": ForeignKind("MODEL")}
    key = (security.SEMANTIC_VERSION, security.coordinate("MODEL"))
    route = routes.select_current_object_route(semantic_version=key[0],
        objective=key[1], represented_kind="MODEL")
    def malformed_native(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return altered
    monkeypatch.setitem(routes._ROUTES, key, replace(route, replay=malformed_native))
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(certificate,
            semantic_version=key[0], objective=key[1], represented_kind="MODEL",
            expected_request=request, policy=policy)
    assert comparisons == []
