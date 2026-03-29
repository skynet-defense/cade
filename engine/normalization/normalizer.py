"""
engine.normalization.normalizer — Abstract base class for CADE normalizers.

A Normalizer transforms a raw event dict (as produced by an Ingestor)
into a canonical Event dataclass instance.  All downstream engine
components operate exclusively on normalized Event objects.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """Canonical representation of a security event within CADE.

    Attributes:
        event_id: Unique identifier (UUID string).
        source: Identifier of the originating data source, e.g. ``"fssa"``.
        event_type: Dot-namespaced event category, e.g. ``"auth.failure"``.
        timestamp: ISO 8601 timestamp of when the event occurred.
        asset_id: ID of the asset that generated or is the subject of
            the event.
        raw: The original, unmodified source payload preserved for
            audit purposes.
        tags: Free-form classification labels applied during normalization.
        severity_hint: Optional 0.0–1.0 severity hint provided by the
            source system.  Defaults to ``0.0`` when unavailable.
    """

    event_id: str
    source: str
    event_type: str
    timestamp: str
    asset_id: str
    raw: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    severity_hint: float = 0.0


class Normalizer(abc.ABC):
    """Abstract base class for CADE normalizers.

    Concrete implementations translate source-specific raw event dicts
    into canonical :class:`Event` instances.  The contract is intentionally
    narrow: one raw dict in, one ``Event`` out.
    """

    @abc.abstractmethod
    def normalize(self, raw_event: dict[str, Any]) -> Event:
        """Normalize a raw event dict into a canonical Event.

        Args:
            raw_event: A raw event dict as returned by an :class:`Ingestor`.
                Must contain at minimum ``source``, ``timestamp``, and
                ``payload`` keys.

        Returns:
            A fully populated :class:`Event` instance.

        Raises:
            ValueError: If required fields are missing or malformed.
        """
