"""
api.schemas — CADE API request and response dataclass schemas.

All schemas use the stdlib ``dataclasses`` module to remain
framework-agnostic.  They can be serialized with ``dataclasses.asdict()``
and deserialized with a simple custom factory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EventRequest:
    """Schema for submitting a new security event via POST /events.

    Attributes:
        source: Identifier of the system that generated the event,
            e.g. ``"fssa"``, ``"syslog"``, ``"zeek"``.
        event_type: Dot-namespaced event category,
            e.g. ``"auth.failure"``, ``"network.scan"``.
        timestamp: ISO 8601 timestamp of when the event occurred.
        asset_id: ID of the asset that generated or is the subject of
            the event.
        payload: Arbitrary event-specific fields as a JSON-serializable dict.
        tags: Optional list of free-form labels for pre-classification.
        severity_hint: Optional 0.0–1.0 severity hint from the source.
    """

    source: str
    event_type: str
    timestamp: str
    asset_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    severity_hint: float = 0.0


@dataclass
class ThreatResponse:
    """Schema for a single active threat detection in GET /threats.

    Attributes:
        threat_id: Unique identifier for this threat detection.
        attack_path_id: ID of the underlying attack path.
        score: Normalized risk score in the range 0.0–100.0.
        band: Risk band: ``"critical"``, ``"high"``, ``"medium"``,
            ``"low"``, or ``"informational"``.
        summary: One-sentence human-readable summary from the Explainer.
        top_factors: Top contributing risk factors.
        detected_at: ISO 8601 timestamp of initial detection.
        acknowledged: Whether an analyst has acknowledged this threat.
    """

    threat_id: str
    attack_path_id: str
    score: float
    band: str
    summary: str
    top_factors: list[str]
    detected_at: str
    acknowledged: bool = False


@dataclass
class AttackPathResponse:
    """Schema for a single attack path in GET /attack-paths.

    Attributes:
        path_id: Unique identifier for this attack path.
        source_node_id: Starting node ID (e.g., a ThreatActor).
        target_node_id: Destination node ID (e.g., a high-value Asset).
        steps: Ordered list of node IDs comprising the path.
        score: Normalized risk score, or ``None`` if not yet scored.
        band: Risk band label, or ``None`` if not yet scored.
        discovered_at: ISO 8601 timestamp of when the path was first
            enumerated.
    """

    path_id: str
    source_node_id: str
    target_node_id: str
    steps: list[str]
    score: float | None = None
    band: str | None = None
    discovered_at: str = ""


@dataclass
class HealthResponse:
    """Schema for the GET /health liveness and readiness endpoint.

    Attributes:
        status: Overall status: ``"ok"`` or ``"degraded"``.
        version: CADE engine version string.
        engine_ready: Whether the core engine pipeline is ready.
        integrations: Per-integration readiness flags keyed by name.
        uptime_seconds: Seconds since the service started.
    """

    status: str
    version: str
    engine_ready: bool
    integrations: dict[str, bool] = field(default_factory=dict)
    uptime_seconds: float = 0.0
