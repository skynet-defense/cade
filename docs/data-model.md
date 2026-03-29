# CADE Data Model

## Overview

CADE's data model is built around a small set of core entities that represent the key concepts in cyber attack detection and analysis. All entities are expressed as Python dataclasses (stdlib `dataclasses` module) and are designed to be serializable to JSON.

---

## Core Entities

### Event
An atomic security observation from any data source.

```python
@dataclass
class Event:
    event_id: str           # UUID
    source: str             # e.g., "fssa", "syslog", "zeek"
    event_type: str         # e.g., "network.connection", "auth.failure", "process.exec"
    timestamp: str          # ISO 8601
    asset_id: str           # ID of the asset that generated the event
    raw: dict               # original, unmodified source payload
    tags: list[str]         # free-form classification tags
    severity_hint: float    # 0.0–1.0 hint from source (if available)
```

### Asset
A network-connected system, service, or resource that can be targeted.

```python
@dataclass
class Asset:
    asset_id: str           # UUID
    hostname: str
    ip_address: str
    asset_type: str         # e.g., "server", "workstation", "container", "iot"
    criticality: str        # "low" | "medium" | "high" | "critical"
    owner: str              # team or person responsible
    tags: list[str]
    vulnerabilities: list[str]   # list of Vulnerability IDs
```

### Vulnerability
A known weakness in an asset that can be exploited.

```python
@dataclass
class Vulnerability:
    vuln_id: str            # UUID or CVE ID
    cve: str | None         # e.g., "CVE-2024-1234" (optional)
    cvss_score: float | None    # 0.0–10.0 (optional)
    description: str
    affected_asset_ids: list[str]
    exploitable_remotely: bool
    has_public_exploit: bool
    patch_available: bool
```

### AttackPath
A sequence of graph edges representing a viable route from a threat actor to a target.

```python
@dataclass
class AttackPath:
    path_id: str            # UUID
    source_node_id: str     # starting node (e.g., ThreatActor or external Asset)
    target_node_id: str     # destination node (high-value Asset)
    steps: list[str]        # ordered list of node IDs traversed
    edges: list[str]        # ordered list of edge IDs traversed
    discovered_at: str      # ISO 8601
    score: float | None     # populated after Scorer runs
```

### ThreatActor
A known or suspected adversary profile.

```python
@dataclass
class ThreatActor:
    actor_id: str           # UUID
    name: str               # e.g., "APT29", "unknown-ransomware-group"
    motivation: str         # e.g., "espionage", "financial", "disruption"
    capability: str         # "low" | "medium" | "high" | "nation-state"
    known_ttps: list[str]   # MITRE ATT&CK technique IDs, e.g., ["T1059", "T1190"]
    ioc_ids: list[str]      # associated Indicator IDs
```

### Indicator
An Indicator of Compromise (IoC) associated with a threat actor or attack campaign.

```python
@dataclass
class Indicator:
    ioc_id: str             # UUID
    ioc_type: str           # "ip", "domain", "hash", "url", "email"
    value: str              # the indicator value
    confidence: float       # 0.0–1.0
    source: str             # e.g., "smokesignal", "analyst", "open-source-feed"
    first_seen: str         # ISO 8601
    last_seen: str          # ISO 8601
    actor_ids: list[str]    # associated ThreatActor IDs
```

---

## Graph Data Model

The attack graph is a **directed graph** where:

### Node Types

| Node Type | Description |
|---|---|
| `Asset` | A system or service within the target environment |
| `Vulnerability` | A weakness attached to an asset |
| `ThreatActor` | An adversary (source node for attack paths) |

### Edge Types

| Edge Type | From | To | Description |
|---|---|---|---|
| `Exploits` | ThreatActor / Asset | Vulnerability | The actor or a compromised asset can exploit this vulnerability |
| `Targets` | ThreatActor | Asset | The actor is known to target this asset type |
| `Propagates` | Asset | Asset | Compromise of the source asset can propagate to the target |
| `Has` | Asset | Vulnerability | The asset has this vulnerability |

### Graph Representation

```
ThreatActor ──[Targets]──► Asset_A ──[Has]──► Vulnerability_V
                                │
                          [Propagates]
                                │
                                ▼
                           Asset_B ──[Has]──► Vulnerability_W
```

---

## Edge Schema

```python
@dataclass
class GraphEdge:
    edge_id: str
    edge_type: str          # "Exploits" | "Targets" | "Propagates" | "Has"
    source_node_id: str
    target_node_id: str
    weight: float           # 0.0–1.0, represents traversal ease/likelihood
    metadata: dict          # arbitrary edge attributes
```

---

## Storage Considerations

- **In-memory (v0.1–v0.2):** The `AttackGraph` uses an adjacency-list dict for fast neighbor lookup. Suitable for development and small datasets.
- **Persistent store (v0.3+):** A graph database (e.g., Neo4j or ArangoDB) is recommended for production deployments with large, evolving graphs.
- **Event store (v0.3+):** Normalized `Event` objects should be written to an append-only log (e.g., Kafka topic or PostgreSQL WAL) to enable replay and audit.
- **Serialization:** All dataclass instances can be converted to/from JSON via `dataclasses.asdict()` and a custom decoder for type restoration.
