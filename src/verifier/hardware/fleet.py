"""Fleet-boundary and partition-safe accounting checks for VSTD 3."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Iterable, Mapping

from .models import (
    ComputeAccountingObservation,
    FleetManifest,
    FleetMemberStatus,
    FleetObservation,
    LogicalDeviceIdentity,
)


@dataclass(frozen=True)
class FleetVerification:
    valid: bool
    errors: tuple[str, ...]
    expected_member_ids: tuple[str, ...]
    observed_member_ids: tuple[str, ...]


def verify_fleet_observation(
    manifest: FleetManifest,
    observation: FleetObservation,
) -> FleetVerification:
    errors: list[str] = []
    if observation.manifest_id != manifest.manifest_id:
        errors.append("fleet observation references the wrong manifest")
    member_ids = [member.member_id for member in manifest.members]
    if len(member_ids) != len(set(member_ids)):
        errors.append("fleet manifest contains duplicate member ids")
    if len(observation.observed_member_ids) != len(set(observation.observed_member_ids)):
        errors.append("fleet observation contains duplicate observed member ids")
    if len(observation.missing_member_ids) != len(set(observation.missing_member_ids)):
        errors.append("fleet observation contains duplicate missing member ids")
    if len(observation.unexpected_device_ids) != len(set(observation.unexpected_device_ids)):
        errors.append("fleet observation contains duplicate unexpected device ids")
    expected = {
        member.member_id
        for member in manifest.members
        if member.status is FleetMemberStatus.ENROLLED
    }
    observed = set(observation.observed_member_ids)
    missing = expected - observed
    unexpected = observed - expected
    if set(observation.missing_member_ids) != missing:
        errors.append("recorded missing members do not match the manifest/observation difference")
    if set(observation.unexpected_device_ids) != unexpected:
        errors.append("recorded unexpected device ids do not match unregistered observed ids")
    if missing:
        errors.append(f"missing enrolled fleet members: {', '.join(sorted(missing))}")
    if unexpected:
        errors.append(f"unregistered fleet members observed: {', '.join(sorted(unexpected))}")
    return FleetVerification(
        valid=not errors,
        errors=tuple(errors),
        expected_member_ids=tuple(sorted(expected)),
        observed_member_ids=tuple(sorted(observed)),
    )


@dataclass(frozen=True)
class AccountingAggregation:
    totals: Mapping[tuple[str, str, str], str]
    errors: tuple[str, ...]


def aggregate_partition_accounting(
    observations: Iterable[ComputeAccountingObservation],
    logical_identities: Iterable[LogicalDeviceIdentity],
) -> AccountingAggregation:
    """Aggregate disjoint logical scopes without also counting their physical parent."""
    logical = {identity.logical_id: identity for identity in logical_identities}
    totals: dict[tuple[str, str, str], Decimal] = defaultdict(Decimal)
    errors: list[str] = []
    seen_scope_kind: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    fraction_by_parent: dict[str, int] = defaultdict(int)
    for registered_identity in logical.values():
        for physical_id in registered_identity.parent_physical_device_ids:
            fraction_by_parent[physical_id] += registered_identity.capacity_fraction_ppm
    for physical_id, fraction in sorted(fraction_by_parent.items()):
        if fraction > 1_000_000:
            errors.append(f"logical partitions exceed physical capacity for {physical_id}")

    for observation in observations:
        for scope_id in observation.device_scope_ids:
            logical_identity = logical.get(scope_id)
            physical_ids = (
                logical_identity.parent_physical_device_ids if logical_identity else (scope_id,)
            )
            scope_kind = "logical" if logical_identity else "physical"
            for quantity in observation.quantities:
                for physical_id in physical_ids:
                    key = (physical_id, quantity.name, quantity.unit)
                    seen_scope_kind[key].add(scope_kind)
                    if len(seen_scope_kind[key]) > 1:
                        errors.append(
                            f"cannot aggregate physical and logical scopes together for {physical_id} {quantity.name}"
                        )
                        continue
                    totals[key] += Decimal(quantity.value)
    return AccountingAggregation(
        totals={key: format(value, "f") for key, value in sorted(totals.items())},
        errors=tuple(dict.fromkeys(errors)),
    )
