"""Threat scoring (design-only in Phase 0).

Phase 0 ships no scoring engine. Risk and confidence are separate integers in 0..100 carried on
every ``RecommendedAction`` and ``ActionPackage``; ``xdr_response.models.risk_band`` maps a risk
score to LOW / MEDIUM / HIGH / CRITICAL using the bands in ``config/thresholds.yaml``. The Phase 1
engine design is described in ``README.md`` next to this file and in docs/architecture.md section 9.
"""
