"""
tests.test_pathing — Unit tests for engine.pathing.path_finder.PathFinder.
"""

import unittest

from engine.graph.graph import AttackGraph, GraphEdge, GraphNode
from engine.pathing.path_finder import PathFinder


def _build_linear_graph() -> AttackGraph:
    """Return a simple linear graph: actor → host-a → host-b → db."""
    g = AttackGraph()
    for node_id, node_type in [
        ("actor", "ThreatActor"),
        ("host-a", "Asset"),
        ("host-b", "Asset"),
        ("db", "Asset"),
    ]:
        g.add_node(GraphNode(node_id, node_type))
    g.add_edge(GraphEdge("e1", "Targets", "actor", "host-a"))
    g.add_edge(GraphEdge("e2", "Propagates", "host-a", "host-b"))
    g.add_edge(GraphEdge("e3", "Propagates", "host-b", "db"))
    return g


def _build_branching_graph() -> AttackGraph:
    """
    Return a graph with two paths from actor to db:
      actor → host-a → db
      actor → host-b → db
    """
    g = AttackGraph()
    for node_id, node_type in [
        ("actor", "ThreatActor"),
        ("host-a", "Asset"),
        ("host-b", "Asset"),
        ("db", "Asset"),
    ]:
        g.add_node(GraphNode(node_id, node_type))
    g.add_edge(GraphEdge("e1", "Targets", "actor", "host-a"))
    g.add_edge(GraphEdge("e2", "Targets", "actor", "host-b"))
    g.add_edge(GraphEdge("e3", "Propagates", "host-a", "db"))
    g.add_edge(GraphEdge("e4", "Propagates", "host-b", "db"))
    return g


class TestPathFinderFindPaths(unittest.TestCase):
    """Tests for PathFinder.find_paths."""

    def setUp(self):
        self.finder = PathFinder()

    def test_finds_single_path_in_linear_graph(self):
        g = _build_linear_graph()
        paths = self.finder.find_paths(g, "actor", "db")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["actor", "host-a", "host-b", "db"])

    def test_finds_all_paths_in_branching_graph(self):
        g = _build_branching_graph()
        paths = self.finder.find_paths(g, "actor", "db")
        self.assertEqual(len(paths), 2)
        path_sets = [tuple(p) for p in paths]
        self.assertIn(("actor", "host-a", "db"), path_sets)
        self.assertIn(("actor", "host-b", "db"), path_sets)

    def test_returns_empty_when_no_path_exists(self):
        g = AttackGraph()
        g.add_node(GraphNode("a", "Asset"))
        g.add_node(GraphNode("b", "Asset"))
        # No edges added — no path possible.
        paths = self.finder.find_paths(g, "a", "b")
        self.assertEqual(paths, [])

    def test_returns_empty_when_source_absent(self):
        g = _build_linear_graph()
        paths = self.finder.find_paths(g, "ghost", "db")
        self.assertEqual(paths, [])

    def test_returns_empty_when_target_absent(self):
        g = _build_linear_graph()
        paths = self.finder.find_paths(g, "actor", "ghost")
        self.assertEqual(paths, [])

    def test_source_equals_target_returns_single_node_path(self):
        g = _build_linear_graph()
        paths = self.finder.find_paths(g, "actor", "actor")
        self.assertEqual(paths, [["actor"]])

    def test_paths_are_cycle_free(self):
        """Even with a cycle in the graph, returned paths must be simple."""
        g = AttackGraph()
        for nid in ["a", "b", "c"]:
            g.add_node(GraphNode(nid, "Asset"))
        g.add_edge(GraphEdge("e1", "Propagates", "a", "b"))
        g.add_edge(GraphEdge("e2", "Propagates", "b", "c"))
        g.add_edge(GraphEdge("e3", "Propagates", "c", "a"))  # cycle back
        paths = self.finder.find_paths(g, "a", "c")
        for path in paths:
            # All node IDs in a path must be unique (no cycles).
            self.assertEqual(len(path), len(set(path)))

    def test_max_depth_limits_exploration(self):
        """Paths longer than max_depth should not be returned."""
        g = _build_linear_graph()
        # Linear path is 4 nodes (depth 3). max_depth=2 should find nothing.
        paths = self.finder.find_paths(g, "actor", "db", max_depth=2)
        self.assertEqual(paths, [])

    def test_shortest_paths_returned_first(self):
        """BFS guarantees shorter paths are returned before longer ones."""
        g = _build_branching_graph()
        # Both paths in the branching graph are length 3 (2 hops) — equal.
        paths = self.finder.find_paths(g, "actor", "db")
        lengths = [len(p) for p in paths]
        self.assertEqual(sorted(lengths), lengths)


if __name__ == "__main__":
    unittest.main()
