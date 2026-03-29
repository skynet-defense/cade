# CADE Threat Model

## Purpose

This document describes the threat model for the **CADE system itself** — not the threats CADE detects, but the threats posed *to* CADE as a piece of security infrastructure. Compromising a detection engine is a high-value target for sophisticated adversaries.

---

## Assets at Risk

| Asset | Description | Sensitivity |
|---|---|---|
| Normalized event stream | Continuous flow of security events | High |
| Attack graph | Structural knowledge of the monitored environment | Critical |
| Threat intelligence | IoCs, actor profiles, scoring results | Critical |
| API endpoints | REST surface for querying and submitting events | High |
| Integration credentials | Keys/tokens for FSSA, Zbal, SmokeSignal | Critical |
| Score history | Historical risk scores and trends | Medium |
| Configuration | Weights, thresholds, decay constants | Medium |

---

## Trust Boundaries

```
┌────────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE                                                │
│  External data sources, threat feeds, raw log forwarders      │
└────────────────────────┬───────────────────────────────────────┘
                         │  (TLS + authentication required)
┌────────────────────────▼───────────────────────────────────────┐
│  SEMI-TRUSTED ZONE                                             │
│  API Layer, Integration clients                                │
│  (authenticated callers, rate-limited, schema-validated)       │
└────────────────────────┬───────────────────────────────────────┘
                         │  (internal service mesh, mTLS)
┌────────────────────────▼───────────────────────────────────────┐
│  TRUSTED ZONE                                                  │
│  Core Engine (ingestion → explainability pipeline)             │
│  Attack graph, scoring, configuration                          │
└────────────────────────────────────────────────────────────────┘
```

---

## Threat Actors

| Actor | Capability | Motivation |
|---|---|---|
| External attacker | Medium–High | Blind CADE to enable attack; exfiltrate threat intelligence |
| Malicious insider | Low–High | Tamper with scores; exfiltrate graph structure |
| Compromised integration | Medium | Inject false events; manipulate graph |
| Automated scanner | Low | DoS the API; enumerate endpoints |

---

## Attack Scenarios

1. **Event injection** — Attacker submits crafted events via `POST /events` to inflate or suppress scores for specific assets.
2. **Graph poisoning** — Malicious topology data from a compromised Zbal integration inserts false edges into the attack graph.
3. **Credential theft** — Integration credentials stolen from the CADE config, allowing the attacker to impersonate CADE in FSSA/SmokeSignal.
4. **API enumeration** — Unauthenticated scanning of the API to discover the organization's asset topology.
5. **Explainability manipulation** — Tamper with scoring weights to consistently produce low scores, masking real threats.
6. **Replay attack** — Replay previously captured events to create false positives or exhaust analyst capacity.

---

## STRIDE Analysis

### Ingestion (`engine/ingestion/`)

| Threat | STRIDE Category | Notes |
|---|---|---|
| Injected malformed events crash the ingestor | **D**enial of Service | Input validation and size limits required |
| Events forged to attribute attacks to innocent assets | **S**poofing | Source authentication on all input channels |
| Event payload modified in transit | **T**ampering | TLS in transit; integrity hash on receipt |

### Normalization (`engine/normalization/`)

| Threat | STRIDE Category | Notes |
|---|---|---|
| Parser vulnerability exploited via crafted payload | **E**levation of Privilege | Strict schema validation; no `eval`/`exec` on input |
| Normalized events leak sensitive raw data | **I**nformation Disclosure | Strip PII fields during normalization |

### Graph (`engine/graph/`)

| Threat | STRIDE Category | Notes |
|---|---|---|
| Graph structure exfiltrated | **I**nformation Disclosure | Restrict read access; no unauthenticated graph export |
| False edges injected to hide attack paths | **T**ampering | Write access requires elevated privilege |
| Graph grows unbounded (DoS) | **D**enial of Service | Node/edge count limits; eviction policy |

### API Layer (`api/`)

| Threat | STRIDE Category | Notes |
|---|---|---|
| Unauthenticated access to `/threats` or `/attack-paths` | **I**nformation Disclosure | All endpoints require authentication |
| Spoofed `POST /events` from unauthorized source | **S**poofing | mTLS or signed JWT required |
| Attacker replays captured requests | **R**epudiation | Nonce or timestamp validation on all mutations |
| Rate limit bypass enables DoS | **D**enial of Service | Per-client rate limiting enforced at API gateway |

### Integrations (`integrations/`)

| Threat | STRIDE Category | Notes |
|---|---|---|
| Compromised FSSA pushes false signals | **T**ampering | Validate signal schema and source signature |
| Zbal topology report reflects attacker-controlled data | **T**ampering | Cross-validate topology against known baselines |
| SmokeSignal feed used as C2 channel | **E**levation of Privilege | Treat feed data as untrusted; no exec from feed content |
| Integration credentials in plaintext config | **I**nformation Disclosure | Use secrets manager; never commit credentials |

---

## Mitigations

| Mitigation | Applies To |
|---|---|
| TLS on all external connections | Ingestion, API, Integrations |
| mTLS between internal services | API ↔ Engine, API ↔ Integrations |
| Input schema validation at every trust boundary | Ingestion, API |
| Authentication and authorization on all API endpoints | API |
| Secrets management (vault / env injection) | Integrations, Config |
| Audit logging of all graph mutations | Graph |
| Rate limiting on `POST /events` | API |
| Signed event receipts (HMAC) | Ingestion |
| Regular dependency audit (stdlib-only core reduces surface) | Engine |
| Immutable normalized events (no post-creation mutation) | Normalization, Graph |
