# Scoring (design-only in Phase 0)

Phase 0 has no scoring code. This note fixes the rules the Phase 1 engine must follow.

## Two separate numbers

- **Risk score** (0-100): how bad the activity is if the evidence is right.
- **Confidence score** (0-100): how sure we are that the evidence is right and attributed to the correct target.

They are never merged into one number. A high-risk, low-confidence finding is shown as exactly that on the decision card.

## Bands

`risk_band(score)` in `xdr_response.models.recommendation`: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL. The same cut-offs are configured in `config/thresholds.yaml` under `scoring.bands`.

## Inputs (Phase 1)

- Normalized `EnrichmentResult` objects (verdict, risk, confidence, sources, health).
- Investigation findings with numbered, sourced evidence.
- A source that failed (health `UNAVAILABLE`, `AUTH_FAILED`, `RATE_LIMITED`) lowers confidence; it never blocks a recommendation that other evidence supports.

## Rules

- Scoring is deterministic: same inputs, same scores.
- AI-written narrative (`Incident.ai_narrative`) is never an input to scores and never evidence.
- Weights live in `config/thresholds.yaml` (`scoring.weights`) and are reviewed like code.
- Scores inform the analyst. They never approve, never skip approval and never change the approval level, which is decided by the critical-asset policy, the action catalog and blast-radius caps.

See `docs/architecture.md` section 9 for the data model.
