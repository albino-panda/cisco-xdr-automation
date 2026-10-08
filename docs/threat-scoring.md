# Threat scoring

**Status: binding (Phase 1, implemented).** Sections 1, 2, 4 to 8 and 10 are binding as amended by [architecture.md](architecture.md) section 14.2, which is authoritative where the two differ. The engine is `xdr_response.scoring` (`engine.py`, `signals.py`, `verdict.py`); the models are in `xdr_response.models.scoring`; the settings are `ScoringSettings` in `xdr_response.config.schema`. The short rules are also in [src/xdr_response/scoring/README.md](../src/xdr_response/scoring/README.md).

The one deliberate change from the original design: signals and contributions cite **record ids** (the deterministic ids of investigation and enrichment records, architecture 14.1.2), not evidence numbers, because numbers are assigned later by `PackageBuilder`.

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

- `risk_band(score, bands=None)` takes the configured bands; `None` uses the built-in cut-offs above (Phase 0 callers are unchanged). The scoring engine always passes `scoring.bands`.
- The loader refuses a band table that does not name exactly the four bands, does not start with `LOW: 0`, is not strictly increasing in band order, or has a bound above 100. The defaults stay as above.

Confidence has no bands. It is shown as a percentage.

## 3. What Phase 0 did (historical, not binding)

Phase 0 uses the deterministic `RuleBasedRecommender` (`src/xdr_response/lifecycle/recommendation.py`):

- Per observable, the worst verdict of all sources wins (`MALICIOUS` > `SUSPICIOUS` > `UNKNOWN` / `CLEAN`). A failed source contributes nothing.
- A playbook rule fires on `MALICIOUS`, or on `SUSPICIOUS` with risk at least 60.
- `risk_score` is the highest risk reported by a source with that verdict.
- `confidence_score` is the highest confidence of those sources, plus 10 per extra agreeing source, capped at 100.
- Package risk is the highest action risk. Package confidence is the rounded mean of the action confidences.

Known gap: in Phase 0 one source's `MALICIOUS` verdict is enough to fire a rule with that source's own risk. The Phase 1 engine closes this gap (section 5.4) for everything built on it; the Phase 0 recommender remains only until the workflow framework replaces it.

## 4. Inputs

The engine takes a list of `ScoringSignal` objects for one target. A signal is built from normalized records (`signals_from_enrichment`, `signals_from_records`, architecture 14.2.3) or by a workflow hook from the records it computed a pattern over. Each signal cites at least one record id; a signal without one is refused by the model.

```python
# xdr_response/models/scoring.py (exact contract: architecture 14.2.1)
class ScoringSignal(FrozenModel):
    category: SignalCategory          # see the table below
    integration: str                  # the source adapter (INTEGRATION_NAMES), for example "secure_endpoint"
    observable: Observable            # the target the signal is about
    verdict: Verdict                  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    severity: Score                   # 0-100: impact if true
    confidence: Score                 # 0-100: the source's own confidence, or the record-kind default
    record_ids: tuple[str, ...]       # at least one; the records the signal was built from
    health: HealthStatus = CONNECTED  # health of the source when it answered
    origin: str = "framework"         # or "workflow:<id>" for hook-derived signals
    note: str = ""                    # display only; never changes a score
    vendor_verdict: bool = False      # True for an enrichment answer: a vendor's verdict, never a behavioural detection

# xdr_response/scoring/engine.py
class ScoringEngine:
    def __init__(self, settings: ScoringSettings) -> None: ...
    def score(self, signals: Sequence[ScoringSignal], *, context: ScoringContext,
              weights: Mapping[SignalCategory, float] | None = None) -> ScoreBreakdown: ...
    def package_scores(self, breakdowns: Sequence[ScoreBreakdown]) -> tuple[int, int]: ...
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

**Never an input:** AI-written text (`Incident.ai_narrative`), analyst comments, or anything without a record id. There is no parameter or field that could carry them.

## 5. Calculation

The calculation is deterministic: the same signals, context and settings always give the same scores. Signals are sorted by `(category, integration, observable type, observable value, record_ids)` first, so input order never matters. Weighted values are kept unrounded; rounding happens once at the end, half up (`math.floor(x + 0.5)`), then the score is clamped to 0-100.

General rules (architecture 14.2.2):

- Signals with verdict `UNKNOWN` are ignored. `MALICIOUS` and `SUSPICIOUS` signals are the **supporting** signals. `CLEAN` signals count only for the contradiction penalty and never lower risk.
- No supporting signal at all: risk 0, confidence 0, band LOW, no contributions, failed and not-queried sources listed; the decision card shows "insufficient evidence". The critical-asset bonus never invents risk without evidence.

### 5.1 Risk

1. Per category, take the highest `severity` among its signals. A `CLEAN` signal has severity 0 here. It never cancels another category's severity.
2. Multiply by the category weight `w` (0.0-1.0) from `scoring.weights`.
3. Cap the `reputation` category at `reputation_max_contribution` (default 50).
4. Base risk is the highest weighted category value.
5. Corroboration: add `corroboration_step` (default 5) for each other category whose weighted value **from an integration other than the base signal's** is at least `corroboration_min` (default 30). A source never corroborates itself: three categories from the same EDR add nothing. The total bonus is capped at `corroboration_max` (default 15).
6. Single-source cap (section 5.4): when every supporting signal that carries weight comes from one integration (another integration counts only when one of its supporting signals is weighted at least `corroboration.min`) and none of them is a `MALICIOUS` behavioural detection (not an enrichment vendor verdict, not `reputation` or `campaign_association`) with severity at least the CRITICAL band lower bound, the risk so far is capped at that bound minus one (79 with the default bands; `caps_applied` says "single source capped at 79").
7. Context: add `critical_asset_bonus` (default 10) once when the target matches one or more critical asset classes (`ScoringContext.critical_asset_classes`). This raises impact only; it never changes confidence and never changes the approval level.
8. Round and clamp to 0-100.

### 5.2 Confidence

1. Base confidence is the highest `confidence` among non-reputation signals that are not `CLEAN`.
2. If every supporting signal is a reputation signal, base confidence is the highest reputation confidence, capped at `reputation_only_confidence_cap` (default 50).
3. Independent corroboration: add `independent_source_step` (default 5) for each additional distinct integration that supports the finding (the base signal's integration is not additional; one integration in two categories counts once). The total bonus is capped at `independent_source_max` (default 20). For reputation-only evidence the bonus is limited so that confidence never exceeds `reputation_only_confidence_cap`.
4. Contradiction: subtract `contradiction_penalty` (default 15) for each distinct integration that rates a supported observable `CLEAN` (observables compared by type and case-insensitive value).
5. Failed sources: subtract `failed_source_penalty` (default 5) for each expected source whose health is `UNAVAILABLE`, `AUTH_FAILED` or `RATE_LIMITED` (once per source, even when it failed with several of these in one run). The total penalty is capped at `failed_source_max_penalty` (default 20). When the caller names no expected sources, every failed source counts as expected. Other health values (`DEGRADED`, `UNKNOWN`) are listed but cost nothing.
6. Round and clamp to 0-100.

A source that was **not queried** on purpose is not a failure. For example, `DisclosurePolicy` never sends internal hostnames or private IPs to VirusTotal. It is listed as `not queried` in the breakdown and costs no confidence.

### 5.3 Package and action scores

- Each `RecommendedAction` takes the risk and confidence of its target.
- The package risk is the highest action risk. The package confidence is the round-half-up mean of the action confidences (`ScoringEngine.package_scores`; `(0, 0)` for none).

### 5.4 No vendor verdict is absolute truth

- A reputation verdict is one signal with a capped weight. With the defaults, reputation alone gives at most risk 50 (MEDIUM) and confidence 50%.
- A single source can never reach CRITICAL on its own unless it is a behavioural detection with high severity (for example an EDR ransomware detection on the host). An enrichment answer (`ScoringSignal.vendor_verdict`) is a vendor's verdict, never a behavioural detection, whatever its category: a sandbox, email-gateway or identity verdict alone stays below CRITICAL (5.1 step 6), and `aggregate_verdict` gives `SUSPICIOUS` unless a second integration agrees.
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
    contributions: tuple[Contribution, ...]   # category, integration, signed points, applies_to, record_ids, note
    caps_applied: tuple[str, ...]             # for example "reputation capped at 50"
    failed_sources: tuple[str, ...]           # "<integration> (<HEALTH>)"
    not_queried: tuple[str, ...]              # "<integration> (<reason>)"
    reputation_only: bool
    settings_hash: str                        # sha256 of the canonical scoring settings used
    def explain(self) -> str: ...             # one deterministic line
```

- Every contribution cites the record ids it was computed from (the critical-asset and failed-source contributions cite none), so the decision card can explain each point. Category contributions carry the note `base`, `corroborates` or `below corroboration minimum <n>`; the base confidence contribution carries `base`.
- `explain()` is one deterministic line, for example `risk 90 CRITICAL (endpoint_detection secure_endpoint 80; corroboration +10), confidence 90 (base 85; independent sources +10; failed alienvault_otx -5), settings <hash[:12]>`.
- `settings_hash` is `sha256_hex(canonical_json(settings, allow_floats=True))`; with workflow weight overrides it is computed over the settings with those weights merged in.
- The decision card shows risk, band, confidence, the top contributions, caps applied, and failed and not-queried sources.
- The breakdown and `settings_hash` go into the audit record of the recommendation. A score can then be reproduced later with the same settings.

## 7. Configuration

`ScoringSettings` in `xdr_response/config/schema.py` (with `ScoringCaps`, `CorroborationSettings`, `ConfidenceSettings` and `ScoringContextSettings`) reads this shape from `config/thresholds.yaml`. Unknown keys are refused; a Phase 0 file with only `bands` and `weights: {}` still loads (missing categories use the defaults below).

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
- Weights are between 0.0 and 1.0 and keyed by a known category (an unknown key is refused). Caps, steps, penalties and bonuses are integers between 0 and 100.
- Workflows may override category weights in their own spec (`ScoringEngine.score(..., weights=...)`). They can never override caps, steps, penalties or the rules in section 8.

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

Counter-example: domain `login-update.example` rated `MALICIOUS` by VirusTotal only (severity 90, confidence 80), no other signal. Risk = min(54, 50) = 50, **MEDIUM**. Confidence = min(80, 50) = 50%. If Umbrella rates the same domain `CLEAN`, confidence drops to 35%. The card shows "reputation only" and the playbook decides whether to propose a block. `aggregate_verdict` gives `SUSPICIOUS`: one vendor's `MALICIOUS` alone is never the final verdict.

Both examples are unit tests (`tests/unit/scoring/test_engine.py`).

## 10. Tests the Phase 1 engine must ship with

All of these live in `tests/unit/scoring/`, together with the additions of architecture 14.2.5 (weight overrides cannot change caps, `explain()` is stable, every contribution's record ids exist in the input signals).

- Band boundaries: 29, 30, 59, 60, 79 and 80 map to the right band.
- Determinism: the same input in a different order gives the same breakdown and `settings_hash`.
- Reputation-only input never exceeds the reputation caps, whatever the weights.
- A `CLEAN` verdict never lowers risk below the strongest behavioural signal.
- A failed source lowers confidence, is listed, and never empties a recommendation that other evidence supports.
- A not-queried source (disclosure policy) costs no confidence.
- AI narrative and analyst comments have no effect on any score.
- No score changes `approval_level` (property test across the critical-asset fixtures).
- Golden breakdowns for the bundled scenarios in `tests/fixtures/incidents/`.
