"""Shared pydantic base for every model: frozen, extra fields forbidden."""
from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

JsonDict = dict[str, Any]
Score = Annotated[int, Field(ge=0, le=100)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
