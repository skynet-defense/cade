"""
engine.pathing.path_finder — BFS-based attack path enumeration for CADE.

PathFinder traverses an AttackGraph to discover all viable paths from a
source node to a target node.  Breadth-First Search is used so that the
shortest paths are returned first.  Cycles are prevented by tracking
visited nodes within each path.
"""

from __future__ import annotations

from collections import deque

from engine.graph.graph import AttackGraph


class PathFinder:
    """Enumerates attack paths within an :class:`AttackGraph`.

    Uses Breadth-First Search (BFS) to find all simple (cycle-free)
    paths from a source node to a target node.  Paths are returned in
    order of increasing length (shortest first).

    Example::

        graph = AttackGraph()
        # ... populate graph ...
        finder = PathFinder()
        paths = finder.find_paths(graph, "actor-1", "crown-jewel-db")
        for path in paths:
            print(" -> ".join(path))
    """

    def find_paths(
        self,
        graph: AttackGraph,
        source: str,
        target: str,
        max_depth: int = 20,
    ) -> list[list[str]]:
        """Find all simple paths from ``source`` to ``target`` in ``graph``.

        Each returned path is a list of node IDs starting with ``source``
        and ending with ``target``.  No node appears more than once in a
        single path (cycle-free).

        Args:
            graph: The :class:`AttackGraph` to traverse.
            source: Node ID of the starting point (e.g., a ThreatActor).
            target: Node ID of the goal (e.g., a high-value Asset).
            max_depth: Maximum path length (number of hops) to explore.
                Prevents unbounded traversal on dense graphs.  Defaults
                to ``20``.

        Returns:
            A list of paths, where each path is a list of node ID strings.
            Returns an empty list if no paths exist, or if either
            ``source`` or ``target`` is not present in the graph.
        """
        if source not in graph or target not in graph:
            return []

        if source == target:
            return [[source]]

        found_paths: list[list[str]] = []

        # Each queue entry is the current path explored so far.
        queue: deque[list[str]] = deque()
        queue.append([source])

        while queue:
            current_path = queue.popleft()
            current_node = current_path[-1]

            if len(current_path) > max_depth:
                continue

            for neighbor in graph.get_neighbors(current_node):
                neighbor_id = neighbor.node_id

                # Skip already-visited nodes to keep paths cycle-free.
                if neighbor_id in current_path:
                    continue

                new_path = current_path + [neighbor_id]

                if neighbor_id == target:
                    found_paths.append(new_path)
                else:
                    queue.append(new_path)

        return found_paths
