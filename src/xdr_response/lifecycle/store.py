"""In-memory incident and package stores (architecture section 13.19).

Both stores are thread-safe and keep immutable models only. A package can be marked executed
exactly once (:meth:`InMemoryPackageStore.mark_executed` raises ``RuntimeError`` the second time),
which is one of the layers that prevents an approved package from running twice.
"""
from __future__ import annotations

import threading

from xdr_response.models import ActionPackage, ApprovalPurpose, Incident

__all__ = ["InMemoryIncidentStore", "InMemoryPackageStore"]


class InMemoryIncidentStore:
    """Implements :class:`~xdr_response.interfaces.IncidentStore`."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._incidents: dict[str, Incident] = {}

    def get(self, incident_id: str) -> Incident:
        with self._lock:
            return self._incidents[incident_id]

    def save(self, incident: Incident) -> None:
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident")
        with self._lock:
            self._incidents[incident.incident_id] = incident

    def list(self) -> list[Incident]:
        with self._lock:
            return list(self._incidents.values())

    def __contains__(self, incident_id: object) -> bool:
        with self._lock:
            return incident_id in self._incidents


class InMemoryPackageStore:
    """Implements :class:`~xdr_response.interfaces.PackageStore`. Packages are never deleted."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._packages: dict[str, ActionPackage] = {}
        self._order: list[str] = []
        self._executed: set[str] = set()

    def get(self, package_id: str) -> ActionPackage:
        with self._lock:
            return self._packages[package_id]

    def save(self, package: ActionPackage) -> None:
        if not isinstance(package, ActionPackage):
            raise TypeError("package must be an ActionPackage")
        with self._lock:
            existing = self._packages.get(package.package_id)
            if existing is not None and existing != package:
                raise ValueError(f"package {package.package_id} already stored with different content")
            if existing is None:
                self._order.append(package.package_id)
            self._packages[package.package_id] = package

    def mark_executed(self, package_id: str) -> None:
        with self._lock:
            if package_id not in self._packages:
                raise KeyError(package_id)
            if package_id in self._executed:
                raise RuntimeError(f"package {package_id} was already executed")
            self._executed.add(package_id)

    def is_executed(self, package_id: str) -> bool:
        with self._lock:
            return package_id in self._executed

    def latest_for_incident(self, incident_id: str, purpose: ApprovalPurpose) -> ActionPackage | None:
        with self._lock:
            for package_id in reversed(self._order):
                package = self._packages[package_id]
                if package.incident_id == incident_id and package.purpose is ApprovalPurpose(purpose):
                    return package
        return None

    def for_incident(self, incident_id: str) -> list[ActionPackage]:
        """Every package of ``incident_id`` in proposal order."""
        with self._lock:
            return [self._packages[p] for p in self._order if self._packages[p].incident_id == incident_id]
