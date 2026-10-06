"""Incident lifecycle transition table.

The table is defined in :mod:`xdr_response.models.states` (layer 0, created by core) so every
component can check transitions without importing the lifecycle package; this module re-exports it
under its contract name (architecture section 13.9).
"""
from __future__ import annotations

from xdr_response.models.enums import IncidentState
from xdr_response.models.states import ALLOWED_TRANSITIONS, TOKEN_REQUIRED, can_transition

__all__ = ["ALLOWED_TRANSITIONS", "TOKEN_REQUIRED", "IncidentState", "can_transition"]
