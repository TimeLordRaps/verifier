from __future__ import annotations

from pathlib import Path

from verifier.runtime.package_semantic_ownership_public_cli import (
    PUBLIC_CLI_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]


def test_public_cli_has_one_exact_consequence_accumulating_owner() -> None:
    assert len(PUBLIC_CLI_OWNERSHIP_SPECS) == 1
    item = PUBLIC_CLI_OWNERSHIP_SPECS[0]
    assert item.object_id == "vstd-public-cli-dispatch"
    assert item.primary_kind == "PROTOCOL"
    assert item.specializations == (
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    )
    assert item.owned_paths == ("src/verifier/runtime/public_cli.py",)
    assert (ROOT / item.owned_paths[0]).is_file()
    assert "delegates rather than proves" in item.consequence_boundary
    assert "no downstream effect" in item.consequence_boundary


def test_public_cli_dispatch_does_not_invent_external_consequence_roles() -> None:
    item = PUBLIC_CLI_OWNERSHIP_SPECS[0]
    roles = {item.primary_kind, *item.specializations}
    assert roles.isdisjoint({"BOT", "ROBOT", "FINBOT", "MARKET"})
    assert "physical actuation" in item.consequence_boundary
    assert "real-money authority" in item.consequence_boundary
