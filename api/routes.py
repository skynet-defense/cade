"""
api.routes — CADE REST API route stubs.

Route functions are defined here without a framework dependency.
A concrete web framework (e.g., FastAPI or Flask) will import these
stubs and bind them to HTTP endpoints in a later milestone.

Intended endpoint mapping:
    GET  /health        → health_check()
    GET  /threats       → get_threats()
    POST /events        → submit_event(request)
    GET  /attack-paths  → get_attack_paths()
"""

from __future__ import annotations

from api.schemas import (
    AttackPathResponse,
    EventRequest,
    HealthResponse,
    ThreatResponse,
)


def health_check() -> HealthResponse:
    """Return the liveness and readiness status of the CADE service.

    Returns:
        A :class:`~api.schemas.HealthResponse` indicating whether the
        service is alive and all sub-systems are ready.
    """
    raise NotImplementedError("health_check is not yet implemented.")


def get_threats() -> list[ThreatResponse]:
    """Return the list of currently active threat detections.

    Results are ordered by descending risk score.  Only threats that
    have not been acknowledged or resolved are returned.

    Returns:
        A list of :class:`~api.schemas.ThreatResponse` objects.
    """
    raise NotImplementedError("get_threats is not yet implemented.")


def submit_event(request: EventRequest) -> dict:
    """Accept a new security event for ingestion and analysis.

    The event is validated against the :class:`~api.schemas.EventRequest`
    schema, passed through the CADE engine pipeline (ingestion →
    normalization → graph update → pathing → scoring), and any resulting
    threats are persisted.

    Args:
        request: An :class:`~api.schemas.EventRequest` containing the
            event source, type, timestamp, and payload.

    Returns:
        A dict with ``{"accepted": True, "event_id": "<uuid>"}`` on
        success, or an error dict on validation failure.
    """
    raise NotImplementedError("submit_event is not yet implemented.")


def get_attack_paths() -> list[AttackPathResponse]:
    """Return the list of currently enumerated attack paths.

    Paths are ordered by descending risk score.  Paths with no score
    (not yet processed by the Scorer) are returned last.

    Returns:
        A list of :class:`~api.schemas.AttackPathResponse` objects.
    """
    raise NotImplementedError("get_attack_paths is not yet implemented.")
