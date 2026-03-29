"""
engine.ingestion.ingestor — Abstract base class for all CADE ingestors.

An Ingestor accepts raw data from a specific source format and returns
a list of parsed, unvalidated event dicts ready for normalization.
"""

from __future__ import annotations

import abc
from typing import Any


class Ingestor(abc.ABC):
    """Abstract base class for CADE ingestors.

    Concrete implementations must accept a raw data payload in their
    source-specific format and return a list of raw event dicts.
    The output of ``ingest`` is passed directly to a ``Normalizer``.
    """

    @abc.abstractmethod
    def ingest(self, raw_data: Any) -> list[dict]:
        """Parse raw source data and return a list of raw event dicts.

        Each returned dict must contain at minimum:
        - ``source`` (str): identifier of the originating data source
        - ``timestamp`` (str): ISO 8601 timestamp of the event
        - ``payload`` (dict): the event-specific data fields

        Args:
            raw_data: Raw input in the format expected by this ingestor
                (e.g., a JSON string, bytes, file-like object).

        Returns:
            A list of raw event dicts. May be empty if the input
            contains no parseable events.

        Raises:
            ValueError: If ``raw_data`` is structurally invalid and
                cannot produce any events.
        """
