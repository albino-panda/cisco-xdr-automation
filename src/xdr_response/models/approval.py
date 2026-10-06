"""Approval models: credentials, principals, decisions and the approval token.

Signing and verification live in ``xdr_response.approval.tokens``; this module only defines the
data shapes and the wire encoding. It never imports ``xdr_response.errors`` at module level.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import TYPE_CHECKING, Literal

from pydantic import AwareDatetime, Field, SecretStr, ValidationError, field_validator, model_validator

from xdr_response.models._base import FrozenModel
from xdr_response.models.canonical import canonical_json
from xdr_response.models.catalog import ActionType
from xdr_response.models.enums import ApprovalLevel, ApprovalPurpose, DecisionType, PrincipalKind
from xdr_response.models.recommendation import CriticalAssetWarning

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.models.action import ActionRequest

__all__ = [
    "ApproverCredential",
    "AuthenticatedPrincipal",
    "DecisionRequest",
    "AnalystDecision",
    "TokenActionGrant",
    "ApproverClaim",
    "ApprovalTokenClaims",
    "ApprovalToken",
    "TOKEN_SIGNING_CONTEXT",
    "TOKEN_ISSUANCE_CONTEXT",
    "ActionBinding",
    "ApprovalOutcome",
]

TOKEN_SIGNING_CONTEXT = b"xdr-response/approval-token/v1\n"
#: Domain separator of the issuance proof (see ``ApprovalTokenClaims.issuance_proof``).
TOKEN_ISSUANCE_CONTEXT = b"xdr-response/approval-issuance/v1\n"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ApproverCredential(FrozenModel):
    principal_id: str = Field(min_length=1)
    scheme: str = Field(min_length=1)  # e.g. "static", "oidc"
    secret: SecretStr  # never logged; repr hidden


class AuthenticatedPrincipal(FrozenModel):
    principal_id: str = Field(min_length=1)
    display_name: str
    kind: PrincipalKind
    roles: frozenset[str] = frozenset()
    authenticator: str
    authenticated_at: AwareDatetime


class DecisionRequest(FrozenModel):
    package_id: str = Field(min_length=1)
    decision: DecisionType
    approved_keys: tuple[str, ...] = ()  # APPROVE_SELECTED only
    rejected_keys: tuple[str, ...] = ()  # optional; must equal the complement if given
    comment: str = ""


class AnalystDecision(FrozenModel):
    decision_id: str = Field(min_length=1)
    package_id: str
    incident_id: str
    purpose: ApprovalPurpose
    decision: DecisionType
    analyst_identity: str  # principal_id of the first approver
    approvers: tuple[AuthenticatedPrincipal, ...]
    decided_at: AwareDatetime
    approved_action_keys: tuple[str, ...]
    rejected_action_keys: tuple[str, ...]
    comment: str
    workflow_id: str
    workflow_version: str
    evidence_snapshot_hash: str
    token_id: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "AnalystDecision":
        if set(self.approved_action_keys) & set(self.rejected_action_keys):
            raise ValueError("a key cannot be both approved and rejected")
        if self.approvers and self.analyst_identity != self.approvers[0].principal_id:
            raise ValueError("analyst_identity must be the principal_id of the first approver")
        if self.decision in (DecisionType.REJECT, DecisionType.REQUEST_MORE_INVESTIGATION):
            if self.approved_action_keys:
                raise ValueError(f"{self.decision.value} cannot approve actions")
            if self.token_id is not None:
                raise ValueError(f"{self.decision.value} never carries a token")
        return self


class TokenActionGrant(FrozenModel):
    idempotency_key: str
    action_type: ActionType
    target: str
    params_hash: str
    approval_level: ApprovalLevel

    @field_validator("params_hash")
    @classmethod
    def _hex(cls, value: str) -> str:
        if not _HEX64.match(value):
            raise ValueError("params_hash must be 64 lowercase hex characters")
        return value


class ApproverClaim(FrozenModel):
    principal_id: str = Field(min_length=1)
    kind: PrincipalKind
    roles: tuple[str, ...]  # sorted

    @field_validator("roles")
    @classmethod
    def _sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class ApprovalTokenClaims(FrozenModel):
    version: Literal[1] = 1
    token_id: str = Field(min_length=1)
    purpose: ApprovalPurpose
    package_id: str
    incident_id: str
    evidence_snapshot_hash: str
    workflow_id: str
    workflow_version: str
    decision_id: str
    actions: tuple[TokenActionGrant, ...] = Field(min_length=1)
    approvers: tuple[ApproverClaim, ...] = Field(min_length=1)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    #: True when the decision was taken on a dry-run (simulated) package. Such a token can never
    #: authorize a live action: verification refuses it and the package binding must match.
    dry_run: bool = False
    #: HMAC proof, set only by ``ApprovalTokenService.issue`` after its policy checks (decision
    #: belongs to the package, authenticated HUMAN approvers, quorum). Verification refuses tokens
    #: without a valid proof, so claims signed through the low-level ``sign`` API (for example a
    #: fabricated HUMAN approver with no recorded decision) never authorize anything.
    issuance_proof: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "ApprovalTokenClaims":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        keys = [g.idempotency_key for g in self.actions]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate grants in token")
        return self

    def grant(self, idempotency_key: str) -> TokenActionGrant | None:
        for g in self.actions:
            if g.idempotency_key == idempotency_key:
                return g
        return None


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class ApprovalToken(FrozenModel):
    claims: ApprovalTokenClaims
    key_id: str
    alg: Literal["HMAC-SHA256"] = "HMAC-SHA256"
    signature: str = Field(repr=False)  # 64 lowercase hex

    @field_validator("signature")
    @classmethod
    def _sig(cls, value: str) -> str:
        if not _HEX64.match(value):
            raise ValueError("signature must be 64 lowercase hex characters")
        return value

    @field_validator("key_id")
    @classmethod
    def _kid(cls, value: str) -> str:
        if not _KEY_ID.match(value):
            raise ValueError("key_id must match [A-Za-z0-9_-]{1,64}")
        return value

    @property
    def token_id(self) -> str:
        return self.claims.token_id

    def encode(self) -> str:
        """``base64url(canonical_json(claims)) + "." + key_id + "." + signature``."""
        return f"{_b64e(canonical_json(self.claims))}.{self.key_id}.{self.signature}"

    @classmethod
    def decode(cls, value: str) -> "ApprovalToken":
        """Parse an encoded token. Malformed input raises TokenInvalidError (signature NOT checked)."""
        from xdr_response.errors import TokenInvalidError

        if not isinstance(value, str):
            raise TokenInvalidError("approval token must be a string")
        parts = value.strip().split(".")
        if len(parts) != 3:
            raise TokenInvalidError("malformed approval token")
        body, key_id, signature = parts
        try:
            raw = json.loads(_b64d(body).decode("utf-8"))
            claims = ApprovalTokenClaims.model_validate(raw)
            return cls(claims=claims, key_id=key_id, signature=signature)
        except (ValueError, binascii.Error, UnicodeDecodeError, ValidationError, TypeError) as exc:
            raise TokenInvalidError("malformed approval token") from exc

    def __str__(self) -> str:  # never print the signature
        return f"ApprovalToken(token_id={self.claims.token_id!r}, key_id={self.key_id!r})"


class ActionBinding(FrozenModel):
    incident_id: str
    idempotency_key: str
    action_type: ActionType
    target: str
    params_hash: str

    @classmethod
    def from_request(cls, request: "ActionRequest") -> "ActionBinding":
        return cls(
            incident_id=request.incident_id,
            idempotency_key=request.idempotency_key,
            action_type=request.action_type,
            target=request.target,
            params_hash=request.params_hash,
        )


class ApprovalOutcome(FrozenModel):
    decision: "AnalystDecision"
    token: ApprovalToken | None
    warnings: tuple[CriticalAssetWarning, ...] = ()
