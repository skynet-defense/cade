"""
engine.graph.graph — Directed attack graph for CADE.

The AttackGraph models assets, vulnerabilities, and threat actors as
nodes in a directed graph.  Edges represent relationships such as
Exploits, Targets, Propagates, and Has.

No external graph library is required; the implementation uses a plain
adjacency-list backed by Python dicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    """A node in the attack graph.

    Attributes:
        node_id: Unique identifier for this node.
        node_type: Category of node: ``"Asset"``, ``"Vulnerability"``,
            or ``"ThreatActor"``.
        attributes: Arbitrary metadata associated with this node.
    """

    node_id: str
    node_type: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed edge in the attack graph.

    Attributes:
        edge_id: Unique identifier for this edge.
        edge_type: Relationship type: ``"Exploits"``, ``"Targets"``,
            ``"Propagates"``, or ``"Has"``.
        source_node_id: ID of the originating node.
        target_node_id: ID of the destination node.
        weight: Traversal ease or likelihood in the range 0.0–1.0.
            A higher weight indicates the edge is easier to traverse.
        metadata: Arbitrary metadata associated with this edge.
    """

    edge_id: str
    edge_type: str
    source_node_id: str
    target_node_id: str
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class AttackGraph:
    """Directed attack graph representing the target environment.

    Nodes represent :class:`GraphNode` instances (assets, vulnerabilities,
    threat actors).  Edges represent directed relationships between nodes.

    The graph is stored as an adjacency list mapping each node ID to the
    list of outgoing :class:`GraphEdge` instances.  A separate node
    registry provides O(1) node lookup by ID.

    Example::

        g = AttackGraph()
        g.add_node(GraphNode("actor-1", "ThreatActor"))
        g.add_node(GraphNode("asset-1", "Asset"))
        g.add_edge(GraphEdge("e-1", "Targets", "actor-1", "asset-1"))
        neighbors = g.get_neighbors("actor-1")
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._adjacency: dict[str, list[GraphEdge]] = {}

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph.

        If a node with the same ``node_id`` already exists it is
        silently replaced.

        Args:
            node: The :class:`GraphNode` to add.
        """
        self._nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return the node with the given ID, or ``None`` if absent.

        Args:
            node_id: The ID of the node to retrieve.

        Returns:
            The :class:`GraphNode` instance, or ``None``.
        """
        return self._nodes.get(node_id)

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all edges incident to it.

        Args:
            node_id: The ID of the node to remove.
        """
        self._nodes.pop(node_id, None)
        self._adjacency.pop(node_id, None)
        for edges in self._adjacency.values():
            edges[:] = [e for e in edges if e.target_node_id != node_id]

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge to the graph.

        Both the source and target nodes must already exist in the graph.

        Args:
            edge: The :class:`GraphEdge` to add.

        Raises:
            KeyError: If either the source or target node is not present
                in the graph.
        """
        if edge.source_node_id not in self._nodes:
            raise KeyError(f"Source node '{edge.source_node_id}' not found in graph.")
        if edge.target_node_id not in self._nodes:
            raise KeyError(f"Target node '{edge.target_node_id}' not found in graph.")
        self._adjacency[edge.source_node_id].append(edge)

    # ------------------------------------------------------------------
    # Query operations
    # ------------------------------------------------------------------

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        """Return the list of nodes directly reachable from ``node_id``.

        Args:
            node_id: The ID of the source node.

        Returns:
            A list of :class:`GraphNode` instances reachable via outgoing
            edges.  Returns an empty list if the node has no outgoing
            edges or does not exist.
        """
        edges = self._adjacency.get(node_id, [])
        return [
            self._nodes[e.target_node_id]
            for e in edges
            if e.target_node_id in self._nodes
        ]

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        """Return all outgoing edges from ``node_id``.

        Args:
            node_id: The ID of the source node.

        Returns:
            A list of :class:`GraphEdge` instances.  Empty if the node
            has no outgoing edges or does not exist.
        """
        return list(self._adjacency.get(node_id, []))

    def node_count(self) -> int:
        """Return the total number of nodes in the graph."""
        return len(self._nodes)

    def edge_count(self) -> int:
        """Return the total number of edges in the graph."""
        return sum(len(edges) for edges in self._adjacency.values())

    def __contains__(self, node_id: str) -> bool:
        """Return ``True`` if a node with ``node_id`` is in the graph."""
        return node_id in self._nodes
