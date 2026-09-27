"""Refutable catalogue integration for implemented bounded admission routes."""
from verifier.core.profile_obligations import DOMAIN_BY_ID
from verifier.domains.catalog import UNKNOWN_ONLY_CHECKS


def test_admitted_verifier_routes_are_reachable_normative_mechanisms():
    for coordinate, mechanism in [('VERIFIER-1.4', 'resources'), ('VERIFIER-1.5', 'meta')]:
        assert DOMAIN_BY_ID[coordinate].mechanism == mechanism
        assert coordinate not in UNKNOWN_ONLY_CHECKS.get('VERIFIER', {})
