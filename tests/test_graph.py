"""
tests.test_graph — Unit tests for engine.graph.graph.AttackGraph.
"""

import unittest

from engine.graph.graph import AttackGraph, GraphEdge, GraphNode


class TestAttackGraphAddNode(unittest.TestCase):
    """Tests for AttackGraph.add_node."""

    def test_add_single_node_increases_count(self):
        g = AttackGraph()
        g.add_node(GraphNode("n1", "Asset"))
        self.assertEqual(g.node_count(), 1)

    def test_add_multiple_nodes(self):
        g = AttackGraph()
        g.add_node(GraphNode("n1", "Asset"))
        g.add_node(GraphNode("n2", "ThreatActor"))
        g.add_node(GraphNode("n3", "Vulnerability"))
        self.assertEqual(g.node_count(), 3)

    def test_add_duplicate_node_replaces_existing(self):
        g = AttackGraph()
        g.add_node(GraphNode("n1", "Asset", {"hostname": "host-a"}))
        g.add_node(GraphNode("n1", "Asset", {"hostname": "host-b"}))
        self.assertEqual(g.node_count(), 1)
        self.assertEqual(g.get_node("n1").attributes["hostname"], "host-b")

    def test_node_is_retrievable_after_add(self):
        g = AttackGraph()
        node = GraphNode("n1", "Asset", {"ip": "10.0.0.1"})
        g.add_node(node)
        retrieved = g.get_node("n1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.node_id, "n1")
        self.assertEqual(retrieved.node_type, "Asset")

    def test_contains_returns_true_for_added_node(self):
        g = AttackGraph()
        g.add_node(GraphNode("actor-1", "ThreatActor"))
        self.assertIn("actor-1", g)

    def test_contains_returns_false_for_absent_node(self):
        g = AttackGraph()
        self.assertNotIn("ghost", g)

    def test_get_node_returns_none_for_absent(self):
        g = AttackGraph()
        self.assertIsNone(g.get_node("does-not-exist"))


class TestAttackGraphAddEdge(unittest.TestCase):
    """Tests for AttackGraph.add_edge."""

    def _graph_with_two_nodes(self):
        g = AttackGraph()
        g.add_node(GraphNode("src", "ThreatActor"))
        g.add_node(GraphNode("dst", "Asset"))
        return g

    def test_add_edge_increases_edge_count(self):
        g = self._graph_with_two_nodes()
        g.add_edge(GraphEdge("e1", "Targets", "src", "dst"))
        self.assertEqual(g.edge_count(), 1)

    def test_add_multiple_edges(self):
        g = AttackGraph()
        g.add_node(GraphNode("a", "Asset"))
        g.add_node(GraphNode("b", "Asset"))
        g.add_node(GraphNode("c", "Asset"))
        g.add_edge(GraphEdge("e1", "Propagates", "a", "b"))
        g.add_edge(GraphEdge("e2", "Propagates", "b", "c"))
        self.assertEqual(g.edge_count(), 2)

    def test_add_edge_missing_source_raises_key_error(self):
        g = AttackGraph()
        g.add_node(GraphNode("dst", "Asset"))
        with self.assertRaises(KeyError):
            g.add_edge(GraphEdge("e1", "Targets", "missing-src", "dst"))

    def test_add_edge_missing_target_raises_key_error(self):
        g = AttackGraph()
        g.add_node(GraphNode("src", "ThreatActor"))
        with self.assertRaises(KeyError):
            g.add_edge(GraphEdge("e1", "Targets", "src", "missing-dst"))

    def test_get_edges_from_returns_correct_edges(self):
        g = self._graph_with_two_nodes()
        edge = GraphEdge("e1", "Targets", "src", "dst", weight=0.8)
        g.add_edge(edge)
        edges = g.get_edges_from("src")
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].edge_id, "e1")
        self.assertAlmostEqual(edges[0].weight, 0.8)

    def test_get_edges_from_absent_node_returns_empty(self):
        g = AttackGraph()
        self.assertEqual(g.get_edges_from("no-such-node"), [])


class TestAttackGraphGetNeighbors(unittest.TestCase):
    """Tests for AttackGraph.get_neighbors."""

    def test_get_neighbors_returns_directly_reachable_nodes(self):
        g = AttackGraph()
        g.add_node(GraphNode("actor", "ThreatActor"))
        g.add_node(GraphNode("host-a", "Asset"))
        g.add_node(GraphNode("host-b", "Asset"))
        g.add_edge(GraphEdge("e1", "Targets", "actor", "host-a"))
        g.add_edge(GraphEdge("e2", "Targets", "actor", "host-b"))

        neighbors = g.get_neighbors("actor")
        neighbor_ids = {n.node_id for n in neighbors}
        self.assertEqual(neighbor_ids, {"host-a", "host-b"})

    def test_get_neighbors_empty_for_isolated_node(self):
        g = AttackGraph()
        g.add_node(GraphNode("isolated", "Asset"))
        self.assertEqual(g.get_neighbors("isolated"), [])

    def test_get_neighbors_empty_for_absent_node(self):
        g = AttackGraph()
        self.assertEqual(g.get_neighbors("ghost"), [])

    def test_get_neighbors_does_not_include_reverse_direction(self):
        g = AttackGraph()
        g.add_node(GraphNode("a", "Asset"))
        g.add_node(GraphNode("b", "Asset"))
        g.add_edge(GraphEdge("e1", "Propagates", "a", "b"))
        # 'b' has no outgoing edges — directed graph
        self.assertEqual(g.get_neighbors("b"), [])

    def test_remove_node_cleans_up_edges(self):
        g = AttackGraph()
        g.add_node(GraphNode("src", "ThreatActor"))
        g.add_node(GraphNode("dst", "Asset"))
        g.add_edge(GraphEdge("e1", "Targets", "src", "dst"))
        g.remove_node("dst")
        # After removing the target, the neighbor list should be empty.
        self.assertEqual(g.get_neighbors("src"), [])


if __name__ == "__main__":
    unittest.main()
