# Threat scoring

**Status: Phase 1 design.** Phase 0 ships no scoring engine. This document fixes what the Phase 1 engine (`xdr_response.scoring.engine`) must do, and describes what Phase 0 does today. The short rules are also in [src/xdr_response/scoring/README.md](../src/xdr_response/scoring/README.md). The data model is in [architecture.md](architecture.md) section 9.

## 1. Two numbers, never merged

| Score | Range | Question it answers |
|---|---|---|
| `risk_score` | 0-100 | How bad is this if the evidence is right? (impact) |
| `confidence_score` | 0-100, shown as a percentage | How sure are we that the evidence is right and points at the right target? (evidence strength) |

They stay separate everywhere: on every `RecommendedAction`, on the package, on the decision card and in the audit trail. A high-risk, low-confidence finding is shown as exactly that. It is never averaged into one "threat score".

## 2. Risk bands

| Risk score | Band |
|---|---|
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-79 | HIGH |
| 80-100 | CRITICAL |

`risk_band(score)` in `xdr_response.models.recommendation` implements these cut-offs. The same lower bounds are in [`config/thresholds.yaml`](../config/thresholds.yaml) under `scoring.bands`.

- **Phase 0:** `risk_band()` has the cut-offs built in. `scoring.bands` is loaded and type-checked as part of `thresholds.yaml`, but no code reads it yet.
- **Phase 1:** `risk_band()` reads the configured bands. The loader refuses a band table that does not start at 0, is not strictly increasing, or lacks one of the four bands. The defaults stay as above.

Confidence has no bands. It is shown as a percentage.

## 3. What Phase 0 does today

Phase 0 uses the deterministic `RuleBasedRecommender` (`src/xdr_response/lifecycle/recommendation.py`):

- Per observable, the worst verdict of all sources wins (`MALICIOUS` > `SUSPICIOUS` > `UNKNOWN` / `CLEAN`). A failed source contributes nothing.
- A playbook rule fires on `MALICIOUS`, or on `SUSPICIOUS` with risk at least 60.
- `risk_score` is the highest risk reported by a source with that verdict.
- `confidence_score` is the highest confidence of those sources, plus 10 per extra agreeing source, capped at 100.
- Package risk is the highest action risk. Package confidence is the rounded mean of the action confidences.

Known gap: in Phase 0 one source's `MALICIOUS` verdict is enough to fire a rule with that source's own risk. The Phase 1 engine closes this gap (section 5.4).

## 4. Inputs

The engine takes a list of `ScoringSignal` objects for one target. A signal is built from a normalized `EnrichmentResult` or an investigation finding. Each signal must point at numbered, sourced evidence. A signal without evidence is dropped.

```python
# Phase 1 design (xdr_response/scoring/engine.py)
class ScoringSignal(FrozenModel):
    category: SignalCategory          # see the table below
    integration: str                  # the source adapter, for example "secure_endpoint"
    observable: Observable            # the target the signal is about
    verdict: Verdict                  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    severity: Score                   # 0-100: impact if true, as normalized by the adapter
    confidence: Score                 # 0-100: the source's own confidence, or the configured default
    evidence_numbers: tuple[int, ...] # numbers on the decision card, at least one
    health: HealthStatus              # health of the source when it answered

class ScoringEngine:
    def __init__(self, settings: ScoringSettings) -> None: ...
    def score(self, signals: Sequence[ScoringSignal], *, context: ScoringContext) -> ScoreBreakdown: ...
```

| Category | Typical sources |
|---|---|
| `endpoint_detection` | Secure Endpoint, Defender for Endpoint detections |
| `sandbox_verdict` | Secure Malware Analytics |
| `reputation` | VirusTotal, AlienVault OTX, Umbrella categorization, Cisco XDR enrich verdicts |
| `network_behaviour` | Secure Cloud Analytics alerts (read as XDR incidents), Umbrella and Meraki activity |
| `authentication_anomaly` | Entra sign-in logs (impossible travel, MFA fatigue, risky sign-ins) |
| `email_verdict` | Secure Email Threat Defense, Defender for Office 365 |
| `persistence` | Investigation findings on autoruns, services, scheduled tasks |
| `lateral_movement` | Investigation findings on remote execution, new admin logons |
| `campaign_association` | Threat-intel pulses or XDR incidents that link the observable to a known campaign |

`ScoringContext` carries facts that are not signals: whether the target matches a critical asset class, which sources were expected for this observable type, and which sources failed or were not queried.

**Never an input:** AI-written text (`Incident.ai_narrative`), analyst comments, or anything without a numbered evidence item.

## 5. Calculation

The calculation is deterministic: the same signals, context and settings always give the same scores. All arithmetic uses integers or rounds once at the end.

### 5.1 Risk

1. Per category, take the highest `severity` among its signals. A `CLEAN` signal has severity 0 here. It never cancels another category's severity.
2. Multiply by the category weight `w` (0.0-1.0) from `scoring.weights`.
3. Cap the `reputation` category at `reputation_max_contribution` (default 50).
4. Base risk is the highest weighted category value.
5. Corroboration: add `corroboration_step` (default 5) for each other category whose weighted value is at least `corroboration_min` (default 30). The total bonus is capped at `corroboration_max` (default 15).
6. Context: add `critical_asset_bonus` (default 10) when the target matches a critical asset class.
7. Round and clamp to 0-100.

### 5.2 Confidence

1. Base confidence is the highest `confidence` among non-reputation signals that are not `CLEAN`.
2. If every supporting signal is a reputation signal, base confidence is the highest reputation confidence, capped at `reputation_only_confidence_cap` (default 50).
3. Independent corroboration: add `independent_source_step` (default 5) for each additional distinct integration that supports the finding. The total bonus is capped at `independent_source_max` (default 20).
4. Contradiction: subtract `contradiction_penalty` (default 15) for each integration that rates the same observable `CLEAN`.
5. Failed sources: subtract `failed_source_penalty` (default 5) for each expected source whose health is `UNAVAILABLE`, `AUTH_FAILED` or `RATE_LIMITED`. The total penalty is capped at `failed_source_max_penalty` (default 20).
6. Round and clamp to 0-100.

A source that was **not queried** on purpose is not a failure. For example, `DisclosurePolicy` never sends internal hostnames or private IPs to VirusTotal. It is listed as `not queried` in the breakdown and costs no confidence.

### 5.3 Package and action scores

- Each `RecommendedAction` takes the risk and confidence of its target.
- The package risk is the highest action risk. The package confidence is the rounded mean of the action confidences, as in Phase 0.

### 5.4 No vendor verdict is absolute truth

- A reputation verdict is one signal with a capped weight. With the defaults, reputation alone gives at most risk 50 (MEDIUM) and confidence 50%.
- A single source can never reach CRITICAL on its own unless it is a behavioural detection with high severity (for example an EDR ransomware detection on the host).
- A `CLEAN` verdict lowers confidence. It never zeroes a behavioural detection from another source.
- Whether a MEDIUM, reputation-only target is proposed at all is the workflow's playbook decision (its minimum risk). The scores only inform it.

### 5.5 Failed sources never block

A failed enrichment source lowers confidence and is listed in the breakdown. It never blocks a recommendation that other evidence supports. If no source answered at all, the engine returns risk 0, confidence 0 and the list of failed sources. The decision card then shows "insufficient evidence" instead of an empty card.

## 6. Output and explanation

```python
class ScoreBreakdown(FrozenModel):
    risk_score: Score
    confidence_score: Score
    risk_band: RiskBand
    contributions: tuple[Contribution, ...]   # category, integration, points, evidence_numbers, note
    caps_applied: tuple[str, ...]             # for example "reputation capped at 50"
    failed_sources: tuple[str, ...]           # with health status
    not_queried: tuple[str, ...]              # with the disclosure-policy reason
    settings_hash: str                        # sha256 of the scoring settings used
```

- Every contribution names its evidence numbers, so the decision card can explain each point.
- The decision card shows risk, band, confidence, the top contributions, caps applied, and failed and not-queried sources.
- The breakdown and `settings_hash` go into the audit record of the recommendation. A score can then be reproduced later with the same settings.

## 7. Configuration

Phase 0 accepts only `scoring.bands` and `scoring.weights` (a flat map of name to number). Phase 1 extends `ScoringSettings` in `xdr_response/config/schema.py`. The config schema forbids unknown keys, so the new fields below are refused until that schema change lands. Proposed shape:

```yaml
scoring:
  bands: {LOW: 0, MEDIUM: 30, HIGH: 60, CRITICAL: 80}
  weights:                        # category weight, 0.0-1.0
    endpoint_detection: 1.0
    sandbox_verdict: 0.9
    network_behaviour: 0.9
    authentication_anomaly: 0.9
    email_verdict: 0.8
    persistence: 0.8
    lateral_movement: 1.0
    campaign_association: 0.7
    reputation: 0.6
  caps:
    reputation_max_contribution: 50
    reputation_only_confidence_cap: 50
  corroboration: {min: 30, step: 5, max: 15}
  confidence: {independent_source_step: 5, independent_source_max: 20,
               contradiction_penalty: 15, failed_source_penalty: 5, failed_source_max_penalty: 20}
  context: {critical_asset_bonus: 10}
```

Rules for these settings:

- They are reviewed like code. A change goes through a pull request with updated scoring tests.
- Weights are between 0.0 and 1.0. Caps, steps and penalties are between 0 and 100.
- Workflows may override weights in their own spec (Phase 2 onward). They can never override the reputation caps or the rules in section 8.

## 8. What scores can never do

- Scores never approve, never skip approval and never execute anything.
- Scores never change the approval level. ELEVATED comes from the critical-asset policy, the action catalog and the blast-radius caps, not from risk or confidence.
- A low score never hides an action an analyst should see, and a high score never adds an action the playbook does not allow.
- Dry run and live runs score the same way.

## 9. Worked example (fake data)

Target: host `TH-LT-1047`. Default settings, not a critical asset.

| Signal | Category | Integration | Severity | Confidence | Evidence |
|---|---|---|---|---|---|
| Ransomware behaviour, 1,204 files renamed | `endpoint_detection` | secure_endpoint | 80 | 80 | [2] |
| C2 domain `c2.ransom-ops.example` contacted | `network_behaviour` | umbrella | 85 | 85 | [5] |
| Encryptor hash rated malicious | `reputation` | virustotal | 90 | 80 | [8] |
| (no answer) | `reputation` | alienvault_otx | | | RATE_LIMITED |

Risk:

- Weighted values: endpoint 80 × 1.0 = 80. Network 85 × 0.9 = 76.5. Reputation 90 × 0.6 = 54, capped at 50.
- Base 80. Two other categories are at least 30: +10 (below the cap of 15).
- Risk = 90, **CRITICAL**.

Confidence:

- Base 85 (the highest non-reputation confidence, from umbrella).
- Two additional supporting integrations (secure_endpoint, virustotal): +10.
- One failed expected source (alienvault_otx): -5.
- Confidence = 90%.

Counter-example: domain `login-update.example` rated `MALICIOUS` by VirusTotal only (severity 90, confidence 80), no other signal. Risk = min(54, 50) = 50, **MEDIUM**. Confidence = min(80, 50) = 50%. If Umbrella rates the same domain `CLEAN`, confidence drops to 35%. The card shows "reputation only" and the playbook decides whether to propose a block.

## 10. Tests the Phase 1 engine must ship with

- Band boundaries: 29, 30, 59, 60, 79 and 80 map to the right band.
- Determinism: the same input in a different order gives the same breakdown and `settings_hash`.
- Reputation-only input never exceeds the reputation caps, whatever the weights.
- A `CLEAN` verdict never lowers risk below the strongest behavioural signal.
- A failed source lowers confidence, is listed, and never empties a recommendation that other evidence supports.
- A not-queried source (disclosure policy) costs no confidence.
- AI narrative and analyst comments have no effect on any score.
- No score changes `approval_level` (property test across the critical-asset fixtures).
- Golden breakdowns for the bundled scenarios in `tests/fixtures/incidents/`.
