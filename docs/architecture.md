# CADE Architecture

## High-Level Overview

CADE is organized as a layered pipeline. Raw security events enter through the **Ingestion** layer and are progressively enriched, structured, and analyzed until actionable, explainable threat intelligence is produced at the output.

```
┌──────────────────────────────────────────────────────────────────────┐
│                            Data Sources                              │
│         (SIEM, IDS/IPS, FSSA feeds, SmokeSignal, raw logs)          │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │       Ingestion         │  engine/ingestion/
                    │  (parse & validate raw  │
                    │   events from sources)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Normalization       │  engine/normalization/
                    │  (map to canonical      │
                    │   Event schema)         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Graph Construction   │  engine/graph/
                    │  (build/update directed │
                    │   attack graph)         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Attack Pathing       │  engine/pathing/
                    │  (BFS/DFS to enumerate  │
                    │   attack paths)         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      Simulation         │  engine/simulation/
                    │  (model threat actor    │
                    │   movement/scenarios)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │        Scoring          │  engine/scoring/
                    │  (compute normalized    │
                    │   0-100 risk score)     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Explainability       │  engine/explainability/
                    │  (generate human-       │
                    │   readable explanation) │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────▼───────────────────┐
             │              API Layer                 │  api/
             │   REST endpoints serving threats,      │
             │   attack paths, scores, and events     │
             └──────────┬──────────────┬──────────────┘
                        │              │
          ┌─────────────▼───┐    ┌─────▼──────────────┐
          │  Integrations   │    │     UI Layer        │
          │  fssa/zbal/     │    │  React/TypeScript   │
          │  smokesignal    │    │  dashboard          │
          └─────────────────┘    └────────────────────┘
```

---

## Engine Pipeline

### 1. Ingestion (`engine/ingestion/`)
Accepts raw data from any source (log lines, JSON payloads, binary streams via integrations). The `Ingestor` abstract base class defines the contract; concrete implementations handle specific source formats.

### 2. Normalization (`engine/normalization/`)
Transforms ingested raw data into canonical `Event` objects (see `docs/data-model.md`). Normalization ensures all downstream components work with a consistent data shape regardless of source format.

### 3. Graph Construction (`engine/graph/`)
Maintains a directed `AttackGraph` where nodes represent Assets, Vulnerabilities, and ThreatActors, and edges represent relationships such as `Exploits`, `Targets`, and `Propagates`. The graph is updated incrementally as new events arrive.

### 4. Attack Pathing (`engine/pathing/`)
The `PathFinder` traverses the `AttackGraph` using Breadth-First Search to enumerate all viable attack paths between a source node and a target node. Results feed directly into simulation and scoring.

### 5. Simulation (`engine/simulation/`)
The `Simulator` models how a threat actor might traverse an attack path under a given scenario (e.g., opportunistic attacker vs. targeted APT). Simulation output includes reachability probabilities and step sequences.

### 6. Scoring (`engine/scoring/`)
The `Scorer` computes a normalized 0-100 risk score for each attack path based on severity, likelihood, impact, and confidence dimensions. See `docs/scoring-model.md` for full detail.

### 7. Explainability (`engine/explainability/`)
The `Explainer` converts numeric score results into natural-language explanations, citing the top contributing factors, affected assets, and recommended mitigations.

---

## API Layer (`api/`)

The API layer exposes CADE's capabilities over HTTP REST. Route stubs are defined in `api/routes.py`; request/response schemas use Python dataclasses in `api/schemas.py`.

Key endpoints:
- `GET  /health` — liveness and readiness check
- `GET  /threats` — list current active threats
- `POST /events` — submit a new security event for analysis
- `GET  /attack-paths` — retrieve enumerated attack paths

---

## Integrations Layer (`integrations/`)

| Package | Purpose |
|---|---|
| `integrations/fssa/` | **Fast Security Signal Aggregator** — high-throughput pub/sub ingestion of security signals |
| `integrations/zbal/` | **Zero-trust Balancer** — retrieves live network topology and enforces zero-trust policy |
| `integrations/smokesignal/` | **SmokeSignal** — subscribes to external threat intelligence feeds for IoC correlation |

Each integration exposes a `connect()` method and source-specific methods (e.g., `subscribe`, `get_topology`, `send_alert`).

---

## UI Layer (`ui/`)

A React/TypeScript single-page application providing:
- Live threat dashboard
- Attack graph visualization
- Score history and trend charts
- Explanation cards for each detected threat

The UI consumes the API layer exclusively and has no direct dependency on the engine internals.

---

## Design Principles

- **Dependency-light core** — the engine uses only the Python standard library
- **Pluggable integrations** — all external systems are isolated behind interface-defined clients
- **Immutable events** — normalized events are never mutated after creation
- **Explainability first** — every score output is accompanied by a human-readable justification
