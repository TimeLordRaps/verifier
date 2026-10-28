"""Experimental Verifier Standard (VSTD) computational environment contracts.

JavaScript Object Notation (JSON) records bind exact bytes with Secure Hash
Algorithm 256-bit (SHA-256). They declare boundaries, never runtime enforcement,
correctness, independence, or satisfaction of a numbered profile.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json
import re
from types import UnionType
from typing import Any, ClassVar, Mapping, TypeVar, get_args, get_origin, get_type_hints

from verifier.hardware.models import WorkloadIdentity
from verifier.interoperability.catalog import InteroperabilityComponentDescriptor, InteractionMode
from verifier.interoperability.storage import PackageArtifact


MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 256
T = TypeVar("T", bound="EnvironmentRecord")


class EnvironmentContractError(ValueError):
    """Malformed, ambiguous, unsupported, or out-of-bounds environment record."""


def _text(value: Any) -> str:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > 4096 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise EnvironmentContractError("expected bounded nonempty text without control characters")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise EnvironmentContractError("expected a lowercase SHA-256 digest")
    return value


def _encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, EnvironmentRecord):
        return value.to_dict()
    if is_dataclass(value):
        return {f.name: _encode(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (tuple, list)):
        return [_encode(item) for item in value]
    return value


def _decode(kind: Any, value: Any) -> Any:
    origin, args = get_origin(kind), get_args(kind)
    if origin is UnionType:
        if value is None and type(None) in args:
            return None
        return _decode(next(arg for arg in args if arg is not type(None)), value)
    if origin is tuple:
        if not isinstance(value, (tuple, list)) or len(value) > MAX_ITEMS:
            raise EnvironmentContractError("expected an array within the item bound")
        return tuple(_decode(args[0], item) for item in value)
    if kind is str:
        return _text(value)
    if isinstance(kind, type) and issubclass(kind, Enum):
        return kind(value)
    if kind is InteroperabilityComponentDescriptor:
        result = kind.from_dict(value)
        if result.to_dict() != value:
            raise EnvironmentContractError("component descriptor must use its canonical current shape")
        return result
    if isinstance(kind, type) and issubclass(kind, EnvironmentRecord):
        return kind.from_dict(value)
    if kind is WorkloadIdentity:
        if not isinstance(value, Mapping) or set(value) != {f.name for f in fields(kind)}:
            raise EnvironmentContractError("workload must contain exactly its defined fields")
        # WorkloadIdentity intentionally permits empty optional strings.
        hints = get_type_hints(kind)
        for key, item in value.items():
            if hints[key] is str and not isinstance(item, str):
                raise EnvironmentContractError("workload fields must retain their declared types")
            if get_origin(hints[key]) is tuple and (
                not isinstance(item, (tuple, list)) or len(item) > MAX_ITEMS
                or not all(isinstance(part, str) for part in item)
            ):
                raise EnvironmentContractError("workload commitments must be a bounded string array")
        return kind(**{key: tuple(item) if isinstance(item, list) else item for key, item in value.items()})
    raise EnvironmentContractError(f"unsupported contract field type: {kind}")


def _unique(items: tuple[Any, ...], key: str | None = None) -> None:
    values = [getattr(item, key) if key else item for item in items]
    if len(set(values)) != len(values):
        raise EnvironmentContractError("duplicate record identifiers or declarations")


class EnvironmentRecord:
    """Strict immutable record serialization; ordering is part of identity."""

    SCHEMA: ClassVar[str] = ""

    def __post_init__(self) -> None:
        hints = get_type_hints(type(self))
        for field in fields(self):
            value = getattr(self, field.name)
            object.__setattr__(self, field.name, _decode(hints[field.name], _encode(value)))
        if len(self.canonical_json_bytes()) > MAX_RECORD_BYTES:
            raise EnvironmentContractError("environment record exceeds byte bound")

    def to_dict(self) -> dict[str, Any]:
        payload = {f.name: _encode(getattr(self, f.name)) for f in fields(self)}
        if self.SCHEMA:
            payload["schema_version"] = self.SCHEMA
        return payload

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()

    @classmethod
    def from_dict(cls: type[T], value: Mapping[str, Any]) -> T:
        expected = {f.name for f in fields(cls)} | ({"schema_version"} if cls.SCHEMA else set())
        if not isinstance(value, Mapping) or set(value) != expected:
            raise EnvironmentContractError(f"{cls.__name__} must contain exactly its defined fields")
        if cls.SCHEMA and value["schema_version"] != cls.SCHEMA:
            raise EnvironmentContractError("unsupported environment schema version")
        hints = get_type_hints(cls)
        try:
            return cls(**{f.name: _decode(hints[f.name], value[f.name]) for f in fields(cls)})
        except (TypeError, ValueError, KeyError, RecursionError) as exc:
            raise EnvironmentContractError(f"invalid {cls.__name__}: {exc}") from exc


class EnvironmentRole(str, Enum):
    SUBJECT = "SUBJECT"
    INSTRUMENT = "INSTRUMENT"
    CONTEXT = "CONTEXT"


class ComponentRole(str, Enum):
    TASK = "TASK"
    DYNAMICS = "DYNAMICS"
    WRAPPER = "WRAPPER"
    RUNTIME = "RUNTIME"
    EVALUATOR = "EVALUATOR"


class EnvironmentCapability(str, Enum):
    STEP = "STEP"
    STATE_RESTORE = "STATE_RESTORE"
    REPLAY = "REPLAY"


@dataclass(frozen=True)
class ArtifactBinding(EnvironmentRecord):
    path: str
    digest: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _digest(self.digest)
        PackageArtifact(self.path, "application/octet-stream", b"")


@dataclass(frozen=True)
class EnvironmentMechanism(EnvironmentRecord):
    mechanism_id: str
    implementation: ArtifactBinding


@dataclass(frozen=True)
class EnvironmentComponent(EnvironmentRecord):
    descriptor: InteroperabilityComponentDescriptor
    roles: tuple[ComponentRole, ...]
    artifacts: tuple[ArtifactBinding, ...]
    lineage: tuple[ArtifactBinding, ...] = ()
    mechanisms: tuple[EnvironmentMechanism, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.roles or not self.artifacts:
            raise EnvironmentContractError("components need roles and retained implementation bindings")
        _unique(self.roles)
        _unique(self.artifacts + self.lineage, "path")
        _unique(self.mechanisms, "mechanism_id")
        for mechanism in self.mechanisms:
            if (mechanism.mechanism_id not in self.descriptor.mechanism_ids
                    or mechanism.implementation not in self.artifacts):
                raise EnvironmentContractError("mechanism must bind a declared identifier and retained implementation")


@dataclass(frozen=True)
class EnvironmentConnection(EnvironmentRecord):
    source_component_id: str
    target_component_id: str
    contract: str


@dataclass(frozen=True)
class EnvironmentDefinition(EnvironmentRecord):
    SCHEMA: ClassVar[str] = "VSTD-ENVIRONMENT-DEFINITION-0.1"
    environment_id: str
    version: str
    statement: str
    roles: tuple[EnvironmentRole, ...]
    components: tuple[EnvironmentComponent, ...]
    interaction_mode: InteractionMode
    capabilities: tuple[EnvironmentCapability, ...] = ()
    connections: tuple[EnvironmentConnection, ...] = ()
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.roles or not self.components or not self.limitations:
            raise EnvironmentContractError("definition needs roles, components, and explicit limitations")
        _unique(self.roles)
        _unique(self.capabilities)
        _unique(tuple(item.descriptor.component_id for item in self.components))
        _unique(self.connections)


@dataclass(frozen=True)
class EnvironmentInstance(EnvironmentRecord):
    SCHEMA: ClassVar[str] = "VSTD-ENVIRONMENT-INSTANCE-0.1"
    instance_id: str
    definition_digest: str
    configuration: ArtifactBinding
    initialization: ArtifactBinding
    inputs: tuple[ArtifactBinding, ...] = ()
    model_visible_paths: tuple[str, ...] = ()
    evaluator_only_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        _digest(self.definition_digest)
        _unique(self.inputs, "path")
        _unique(self.model_visible_paths)
        _unique(self.evaluator_only_paths)


@dataclass(frozen=True)
class ModelInteractionBinding(EnvironmentRecord):
    """Optional model-test context; commitments do not authenticate inference."""

    model: ArtifactBinding
    tokenizer: ArtifactBinding
    parameters: ArtifactBinding
    request: ArtifactBinding
    response: ArtifactBinding


@dataclass(frozen=True)
class EnvironmentRunBinding(EnvironmentRecord):
    SCHEMA: ClassVar[str] = "VSTD-ENVIRONMENT-RUN-0.1"
    run_id: str
    instance_digest: str
    workload: WorkloadIdentity
    evaluator_component_id: str
    execution_evidence: tuple[ArtifactBinding, ...] = ()
    trace: ArtifactBinding | None = None
    evaluation: ArtifactBinding | None = None
    reward: ArtifactBinding | None = None
    measurements: ArtifactBinding | None = None
    model_interaction: ModelInteractionBinding | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _digest(self.instance_digest)
        _unique(self.execution_evidence, "path")


def load_environment_record(payload: bytes, *, expected_digest: str | None = None) -> EnvironmentRecord:
    """Decode inert bytes only; never resolve paths, import code, or fetch dependencies."""
    if not isinstance(payload, bytes) or len(payload) > MAX_RECORD_BYTES:
        raise EnvironmentContractError("expected bounded record bytes")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EnvironmentContractError("duplicate object field")
            result[key] = value
        return result

    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs)
        types = (EnvironmentDefinition, EnvironmentInstance, EnvironmentRunBinding)
        record_type = next((kind for kind in types if isinstance(data, dict) and data.get("schema_version") == kind.SCHEMA), None)
        if record_type is None:
            raise EnvironmentContractError("unsupported environment record")
        record = record_type.from_dict(data)
        if expected_digest is not None and record.canonical_digest() != _digest(expected_digest):
            raise EnvironmentContractError("environment record differs from expected digest")
        return record
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise EnvironmentContractError(str(exc)) from exc


def artifact_bindings(definition: EnvironmentDefinition, instance: EnvironmentInstance | None = None,
                      run: EnvironmentRunBinding | None = None) -> tuple[ArtifactBinding, ...]:
    """Preserve every reference, including collisions for assessment to diagnose."""
    refs = [ref for item in definition.components for ref in item.artifacts + item.lineage]
    if instance is not None:
        refs.extend((instance.configuration, instance.initialization, *instance.inputs))
    if run is not None:
        refs.extend(run.execution_evidence)
        refs.extend(ref for ref in (run.trace, run.evaluation, run.reward, run.measurements) if ref is not None)
        if run.model_interaction is not None:
            interaction = run.model_interaction
            refs.extend((interaction.model, interaction.tokenizer, interaction.parameters,
                         interaction.request, interaction.response))
    return tuple(refs)
