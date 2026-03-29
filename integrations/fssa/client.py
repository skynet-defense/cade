"""
integrations.fssa.client — FSSA integration client for CADE.

FSSA (Fast Security Signal Aggregator) is a high-throughput pub/sub
platform for distributing security signals across detection systems.
CADE uses FSSA as a primary event ingestion source: the FSSAClient
connects to an FSSA broker, subscribes to one or more security signal
channels, and forwards received signals to the CADE ingestion pipeline.

FSSA uses a channel-based model where each channel corresponds to a
signal category (e.g., ``"network.alerts"``, ``"auth.events"``).
"""

from __future__ import annotations

from typing import Any


class FSSAClient:
    """Client for the Fast Security Signal Aggregator (FSSA) integration.

    FSSA is a high-throughput pub/sub platform for distributing security
    signals.  This client handles connection management, channel
    subscription, and event publishing on behalf of CADE.

    Example::

        client = FSSAClient(broker_url="fssa://broker.example.com:9000")
        client.connect()
        client.subscribe("network.alerts")
        client.push_event({"type": "port_scan", "src_ip": "10.0.0.1"})
    """

    def __init__(self, broker_url: str = "", api_key: str = "") -> None:
        """Initialize the FSSA client.

        Args:
            broker_url: URL of the FSSA broker, e.g.
                ``"fssa://broker.example.com:9000"``.
            api_key: API key for authenticating with the FSSA broker.
                Should be injected via an environment variable or secrets
                manager; never hard-coded.
        """
        self.broker_url = broker_url
        self._api_key = api_key
        self._connected = False
        self._subscriptions: list[str] = []

    def connect(self) -> None:
        """Establish a connection to the FSSA broker.

        Authenticates using the configured API key and opens a persistent
        connection for pub/sub operations.

        Raises:
            ConnectionError: If the broker is unreachable or authentication
                fails.

        Note:
            This is a stub.  Network implementation will be added in v0.5.
        """
        raise NotImplementedError("FSSAClient.connect is not yet implemented.")

    def subscribe(self, channel: str) -> None:
        """Subscribe to a FSSA signal channel.

        Once subscribed, incoming signals on ``channel`` will be
        forwarded to the CADE ingestion pipeline.

        Args:
            channel: The channel identifier to subscribe to, e.g.
                ``"network.alerts"`` or ``"auth.events"``.

        Raises:
            RuntimeError: If the client is not connected.

        Note:
            This is a stub.  Channel subscription implementation will be
            added in v0.5.
        """
        raise NotImplementedError("FSSAClient.subscribe is not yet implemented.")

    def push_event(self, event: dict[str, Any]) -> None:
        """Publish a security event to the FSSA broker.

        Used when CADE needs to emit a detection back into the FSSA
        signal stream (e.g., for downstream consumers).

        Args:
            event: A JSON-serializable dict representing the security
                event to publish.

        Raises:
            RuntimeError: If the client is not connected.
            ValueError: If ``event`` is empty or missing required fields.

        Note:
            This is a stub.  Publishing implementation will be added in v0.5.
        """
        raise NotImplementedError("FSSAClient.push_event is not yet implemented.")

    def disconnect(self) -> None:
        """Close the connection to the FSSA broker gracefully.

        Note:
            This is a stub.  Teardown implementation will be added in v0.5.
        """
        raise NotImplementedError("FSSAClient.disconnect is not yet implemented.")
