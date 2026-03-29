# CADE Threat Scoring Model

## Overview

CADE produces a single **normalized risk score** in the range **0–100** for each detected attack path or threat event. The score is designed to be:

- **Interpretable** — each dimension is independently viewable
- **Comparable** — scores are normalized so a 75 always means the same relative risk
- **Auditable** — every score is traceable back to its input dimensions
- **CVSS-aligned** — dimensions map to CVSS v3.1 concepts where applicable

---

## Scoring Dimensions

CADE decomposes risk into four primary dimensions:

### 1. Severity (S)
Measures the potential harm if the attack succeeds. Influenced by:
- CVSS Base Score of the exploited vulnerability (if present)
- Data classification of affected assets (public / internal / confidential / restricted)
- System criticality rating of the target asset

**Range:** 0.0 – 1.0

### 2. Likelihood (L)
Estimates the probability the attack will succeed, given current conditions. Influenced by:
- Attack complexity (maps to CVSS Attack Complexity)
- Presence of known public exploits (e.g., weaponized PoCs)
- Threat actor capability profile
- Environmental controls (e.g., WAF present, network segmentation)

**Range:** 0.0 – 1.0

### 3. Impact (I)
Quantifies the business impact if the attack completes. Influenced by:
- Confidentiality, Integrity, and Availability impact (maps to CVSS CIA triad)
- Downstream blast radius (number of assets reachable via propagation)
- Regulatory or compliance implications

**Range:** 0.0 – 1.0

### 4. Confidence (C)
Reflects how certain CADE is in the detection and its associated metadata. Influenced by:
- Number of independent corroborating signals
- Age and reliability of threat intelligence sources
- Completeness of the event record

**Range:** 0.0 – 1.0

---

## Score Aggregation

The raw composite score is computed as a weighted sum:

```
raw_score = w_S * S + w_L * L + w_I * I + w_C * C
```

Default weights (tunable per deployment):

| Dimension | Default Weight |
|---|---|
| Severity (S) | 0.35 |
| Likelihood (L) | 0.25 |
| Impact (I) | 0.30 |
| Confidence (C) | 0.10 |

The weights always sum to 1.0.

---

## Score Normalization

After aggregation, the raw composite (0.0–1.0) is normalized to 0–100:

```
normalized_score = round(raw_score * 100, 2)
```

**Score bands:**

| Band | Range | Meaning |
|---|---|---|
| Critical | 90 – 100 | Immediate response required |
| High | 70 – 89 | Urgent investigation needed |
| Medium | 40 – 69 | Scheduled remediation |
| Low | 10 – 39 | Monitor and review |
| Informational | 0 – 9 | Context only, no action required |

---

## Temporal Decay

Scores decay over time if no new corroborating signals arrive. This prevents stale detections from dominating the risk view.

The decay function is exponential:

```
decayed_score(t) = normalized_score * exp(-λ * t)
```

Where:
- `t` is time elapsed since last signal (in hours)
- `λ` (lambda) is the decay constant (default: `0.02` per hour, i.e., ~50% decay at ~35 hours)

Decay is disabled for scores in the **Critical** band until explicitly acknowledged by an analyst.

---

## CVSS Alignment

CADE maps CVSS v3.1 metrics as follows:

| CVSS Metric | CADE Dimension |
|---|---|
| Base Score | Severity (partial) |
| Attack Complexity (AC) | Likelihood (partial) |
| Privileges Required (PR) | Likelihood (partial) |
| Confidentiality Impact | Impact |
| Integrity Impact | Impact |
| Availability Impact | Impact |
| Temporal Score | Confidence |

When a CVSS score is available for a vulnerability, it anchors the Severity dimension. When absent, CADE uses its own heuristics.

---

## Output Format

The `Scorer` returns a `ScoreResult` object:

```python
@dataclass
class ScoreResult:
    score: float                  # 0.0 – 100.0, normalized
    severity: float               # 0.0 – 1.0
    likelihood: float             # 0.0 – 1.0
    impact: float                 # 0.0 – 1.0
    confidence: float             # 0.0 – 1.0
    band: str                     # "critical" | "high" | "medium" | "low" | "info"
    attack_path_id: str           # reference to the scored AttackPath
    timestamp: str                # ISO 8601
    decayed: bool                 # whether temporal decay has been applied
```

The `Explainer` consumes a `ScoreResult` and produces a plain-English summary of why the score is what it is.
