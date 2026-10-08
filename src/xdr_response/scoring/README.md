# Scoring

Binding rules: `docs/threat-scoring.md` (sections 1, 2, 4 to 8 and 10) as amended by `docs/architecture.md` section 14.2, which wins where they differ.

## Modules

| Module | Contents |
|---|---|
| `xdr_response.models.scoring` | `SignalCategory`, `DEFAULT_WEIGHTS`, `ScoringSignal`, `ScoringContext`, `Contribution`, `ScoreBreakdown` (layer 0, not re-exported from `xdr_response.models`) |
| `engine.py` | `ScoringEngine.score`, `ScoringEngine.package_scores`, `ScoringEngine.settings_hash` |
| `signals.py` | `signals_from_enrichment`, `signals_from_records`, the tables `ENRICHMENT_CATEGORY`, `SEVERITY_POINTS`, `LEVEL_POINTS`, `RECORD_CONFIDENCE` |
| `verdict.py` | `aggregate_verdict` |
| `xdr_response.config.schema` | `ScoringSettings` with `ScoringCaps`, `CorroborationSettings`, `ConfidenceSettings`, `ScoringContextSettings` (`config/thresholds.yaml` `scoring:`) |

## Two separate numbers

- **Risk score** (0-100): how bad the activity is if the evidence is right. Highest weighted category, reputation capped at 50, corroboration bonus (+5 per other category at 30 or more, at most +15), critical-asset bonus (+10, only when there is evidence).
- **Confidence score** (0-100): how sure we are that the evidence is right. Highest non-reputation confidence (reputation-only evidence capped at 50), +5 per additional independent integration (at most +20), -15 per integration rating the target `CLEAN`, -5 per failed expected source (at most -20).

They are never merged into one number. A high-risk, low-confidence finding is shown as exactly that on the decision card.

## Rules

- Deterministic: signals are sorted first, rounding happens once at the end (half up), scores are clamped to 0-100.
- Signals cite record ids (never evidence numbers, never AI text or analyst comments). `ScoringSignal.integration` must be an adapter name; a signal without a record id is refused.
- `UNKNOWN` signals are ignored. `CLEAN` signals only lower confidence; they never lower risk.
- A failed source lowers confidence and is listed; it never blocks a recommendation that other evidence supports. A source not queried on purpose (disclosure policy) costs nothing.
- No supporting signal: risk 0, confidence 0, LOW, "insufficient evidence".
- Workflows may override category weights only (`score(..., weights=...)`); caps, steps and penalties are not overridable.
- `aggregate_verdict`: one vendor's `MALICIOUS` alone is `SUSPICIOUS`. `MALICIOUS` needs a behavioural `MALICIOUS` signal at HIGH risk or two distinct reputation sources with no `CLEAN` vote.
- `user_profile` signals use `RECORD_CONFIDENCE["user_profile"]` = 70 (the anomaly value; added to the 14.2.3 table at Phase 1 integration).
- Scores inform the analyst. They never approve, never skip approval, never execute and never change the approval level, which comes only from the critical-asset policy, the action catalog and blast-radius caps. Dry run and live runs score identically.

Tests: `tests/unit/scoring/`.
