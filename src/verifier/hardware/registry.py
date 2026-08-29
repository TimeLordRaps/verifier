"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Data-driven accelerator profile registry; profiles do not define claim policy."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from .canonical import StrictDecodingError, strict_decode
from .models import AcceleratorProfile


class RegistryError(ValueError):
    pass


class AcceleratorRegistry:
    def __init__(self, profiles: tuple[AcceleratorProfile, ...], *, registry_version: str) -> None:
        self.registry_version = registry_version
        self._profiles: dict[str, AcceleratorProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: AcceleratorProfile) -> None:
        if profile.profile_id in self._profiles:
            raise RegistryError(f"duplicate accelerator profile {profile.profile_id}")
        self._profiles[profile.profile_id] = profile

    def get(self, profile_id: str) -> AcceleratorProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise RegistryError(f"unknown accelerator profile {profile_id}") from exc

    def list(self) -> tuple[AcceleratorProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "VSTD3-ACCELERATOR-REGISTRY-1.0",
            "registry_version": self.registry_version,
            "profiles": [profile.to_dict() for profile in self.list()],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AcceleratorRegistry":
        allowed = {"schema_version", "registry_version", "profiles"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise RegistryError(f"registry has unknown fields: {', '.join(unknown)}")
        if payload.get("schema_version") != "VSTD3-ACCELERATOR-REGISTRY-1.0":
            raise RegistryError("unsupported accelerator registry schema")
        version = payload.get("registry_version")
        profiles_payload = payload.get("profiles")
        if not isinstance(version, str) or not isinstance(profiles_payload, list):
            raise RegistryError("registry_version must be a string and profiles must be an array")
        try:
            profiles = tuple(strict_decode(AcceleratorProfile, item) for item in profiles_payload)
        except (StrictDecodingError, TypeError, ValueError) as exc:
            raise RegistryError(str(exc)) from exc
        return cls(profiles, registry_version=version)

    @classmethod
    def from_file(cls, path: Path) -> "AcceleratorRegistry":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(f"cannot load accelerator registry {path}: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise RegistryError("accelerator registry must be a JSON object")
        return cls.from_dict(payload)


def load_builtin_registry() -> AcceleratorRegistry:
    resource = files("verifier.hardware").joinpath("accelerator_registry.json")
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot load built-in accelerator registry: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise RegistryError("built-in accelerator registry must be a JSON object")
    return AcceleratorRegistry.from_dict(payload)
