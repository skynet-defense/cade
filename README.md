# CADE — Cyber Attack Detection Engine

![Status: Scaffold](https://img.shields.io/badge/status-scaffold-yellow) ![License: MIT](https://img.shields.io/badge/license-MIT-blue) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

---

## Overview

**CADE** (Cyber Attack Detection Engine) is an open-source framework for:

- **Real-time cyber attack detection** — ingest and normalize security events from diverse sources
- **Graph-based attack path analysis** — model assets, vulnerabilities, and threat actors as a directed graph
- **Risk scoring** — produce normalized 0-100 threat scores aligned to CVSS
- **Explainable threat intelligence** — generate human-readable explanations for every detection and score

CADE is designed to be modular, dependency-light, and integration-friendly. It ships a clean Python engine core, a REST API layer, pluggable integrations, and a React/TypeScript UI (in progress).

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                        CADE Core Engine                │
│  Ingestion → Normalization → Graph → Pathing →         │
│  Simulation → Scoring → Explainability                 │
└───────────────────────┬────────────────────────────────┘
                        │
          ┌─────────────▼─────────────┐
          │         API Layer         │
          │   (routes + schemas)      │
          └──────┬──────────┬─────────┘
                 │          │
     ┌───────────▼──┐  ┌────▼──────────────┐
     │  Integrations │  │     UI Layer      │
     │  fssa / zbal  │  │  React/TypeScript │
     │  smokesignal  │  │  (placeholder)    │
     └───────────────┘  └───────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for the full architecture description.

---

## Quickstart

> **Note:** The engine is currently at v0.1 (scaffold). Full quickstart instructions will be added in v0.2.

```bash
# Clone the repository
git clone https://github.com/skynet-defense/cade.git
cd cade

# (Coming in v0.2) Install dependencies and run
pip install -e .
python -m engine
```

---

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System architecture and component overview |
| [`docs/scoring-model.md`](docs/scoring-model.md) | Threat scoring model, dimensions, and normalization |
| [`docs/data-model.md`](docs/data-model.md) | Core data entities, graph model, and schemas |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE threat model for CADE itself |
| [`docs/roadmap.md`](docs/roadmap.md) | Development roadmap from v0.1 to v1.0 |

---

## Repository Structure

```
cade/
├── engine/               # Core detection engine (Python, stdlib only)
│   ├── ingestion/        # Raw event ingestion
│   ├── normalization/    # Event normalization
│   ├── graph/            # Attack graph construction
│   ├── pathing/          # Attack path finding (BFS)
│   ├── simulation/       # Attack scenario simulation
│   ├── scoring/          # Risk scoring
│   └── explainability/   # Human-readable explanations
├── api/                  # REST API layer (routes + schemas)
├── integrations/         # Third-party integrations
│   ├── fssa/             # Fast Security Signal Aggregator
│   ├── zbal/             # Zero-trust balancer / network topology
│   └── smokesignal/      # Threat intelligence feed
├── ui/                   # Web UI (React/TypeScript, placeholder)
├── tests/                # Unit tests
├── examples/             # Example scripts
├── papers/               # Research papers and references
└── docs/                 # Documentation
```

---

## Integrations

| Integration | Description |
|---|---|
| **fssa** | Fast Security Signal Aggregator — high-throughput security event ingestion |
| **zbal** | Zero-trust balancer — network topology awareness and policy enforcement |
| **smokesignal** | Threat intelligence feed — subscribe to and correlate external threat data |

---

## Contributing

Contributions are welcome! Please open an issue or pull request. See the roadmap in [`docs/roadmap.md`](docs/roadmap.md) for areas where help is most needed.

---

## License

MIT — see [`LICENSE`](LICENSE).
