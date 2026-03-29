# CADE Development Roadmap

## Current State — v0.1 (Scaffold)

**Status:** ✅ In progress

The v0.1 milestone establishes the repository structure, documentation, and code scaffolding. No functional detection logic is implemented yet — this version exists to define interfaces, conventions, and architecture before implementation begins.

Deliverables:
- [x] Repository structure (`engine/`, `api/`, `integrations/`, `ui/`, `tests/`, `docs/`)
- [x] Architecture documentation
- [x] Scoring model specification
- [x] Data model specification
- [x] Threat model
- [x] Abstract base classes for all engine components
- [x] Stub implementations with docstrings
- [x] Unit test structure

---

## Near-Term — v0.2 (Core Engine Pipeline)

**Target:** Core detection pipeline operational end-to-end with synthetic data.

Goals:
- [ ] Implement `Ingestor` concrete class for JSON log ingestion
- [ ] Implement `Normalizer` concrete class mapping raw JSON to `Event` dataclass
- [ ] Implement `AttackGraph` with full add/remove/query operations
- [ ] Implement `PathFinder` BFS with cycle detection
- [ ] Implement basic `Scorer` using the weighted-sum model from `docs/scoring-model.md`
- [ ] Implement `Explainer` producing structured plain-text output
- [ ] Complete unit test suite (>80% coverage of engine/)
- [ ] `examples/basic_detection.py` fully functional
- [ ] `pyproject.toml` / `setup.py` with package metadata

---

## Mid-Term — v0.3–v0.5 (Graph Analysis, Scoring, Integrations)

### v0.3 — Graph Analysis
- [ ] Depth-limited DFS in `PathFinder`
- [ ] Cycle detection and loop-free path enumeration
- [ ] Graph persistence (JSON serialization/deserialization)
- [ ] Graph diff: detect newly added paths since last analysis run
- [ ] `Simulator` first implementation: deterministic scenario replay

### v0.4 — Scoring and Explainability
- [ ] Full scoring dimensions implementation (severity, likelihood, impact, confidence)
- [ ] Temporal decay with configurable lambda
- [ ] CVSS v3.1 mapping layer
- [ ] `Explainer` producing structured JSON explanation objects
- [ ] Score history store (in-memory, with persistence export)

### v0.5 — Integrations
- [ ] `FSSAClient` — working pub/sub event ingestion
- [ ] `ZbalClient` — live topology query and graph update
- [ ] `SmokeSignalClient` — IoC feed subscription and indicator correlation
- [ ] Integration configuration via environment variables
- [ ] Integration health monitoring

---

## Long-Term — v1.0 (Production-Ready)

**Target:** Full-featured, deployable production system.

Goals:
- [ ] REST API fully implemented (FastAPI or Flask, TBD)
- [ ] Authentication and authorization (JWT + RBAC)
- [ ] Rate limiting and input validation on all endpoints
- [ ] Graph database backend (Neo4j adapter)
- [ ] Event stream backend (Kafka consumer adapter)
- [ ] React/TypeScript UI: threat dashboard, graph visualization, score trends
- [ ] Docker Compose deployment configuration
- [ ] Kubernetes Helm chart
- [ ] End-to-end integration tests
- [ ] Performance benchmarks (events/second throughput)
- [ ] Full documentation site (MkDocs or Sphinx)
- [ ] Security audit and penetration test
- [ ] v1.0 release and changelog

---

## Stretch Goals (Post v1.0)

### ML-Based Anomaly Detection
- Unsupervised baseline modeling of normal event patterns
- Statistical anomaly flagging without labeled training data
- Lightweight model (no heavy framework dependency in core)

### Federated Learning
- Privacy-preserving model updates across multiple CADE deployments
- Organizations contribute to a shared threat model without exposing raw events
- Federated gradient aggregation for IoC and TTP pattern models

### MITRE ATT&CK Integration
- Automatic TTP tagging of normalized events
- Attack path annotation with ATT&CK technique IDs
- Coverage gap analysis (which techniques are not currently detected)

### Automated Response
- Playbook engine: trigger automated mitigations based on score thresholds
- Integration with SOAR platforms
- Human-in-the-loop approval workflow for high-impact actions
