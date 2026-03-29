"""
examples/basic_detection.py — End-to-end CADE engine pipeline walkthrough.

This script demonstrates how to use the CADE engine components together to:
  1. Build an attack graph with assets, a vulnerability, and a threat actor
  2. Enumerate attack paths using PathFinder
  3. Score each path using Scorer
  4. Generate human-readable explanations using Explainer

No external dependencies are required.  Run from the repository root:

    python examples/basic_detection.py
"""

from engine.explainability.explainer import Explainer
from engine.graph.graph import AttackGraph, GraphEdge, GraphNode
from engine.pathing.path_finder import PathFinder
from engine.scoring.scorer import AttackPathInput, Scorer


# ---------------------------------------------------------------------------
# Step 1: Build the attack graph
# ---------------------------------------------------------------------------
# The graph models a simple environment:
#
#   threat-actor-apt99
#       |-- [Targets] --> dmz-web-server
#                             |-- [Propagates] --> internal-app-server
#                                                       |-- [Propagates] --> crown-jewel-db

def build_mock_graph() -> AttackGraph:
    """Construct a small mock attack graph representing a three-tier environment."""
    g = AttackGraph()

    # Nodes
    g.add_node(GraphNode("threat-actor-apt99", "ThreatActor", {
        "name": "APT99",
        "capability": "high",
        "motivation": "espionage",
    }))
    g.add_node(GraphNode("dmz-web-server", "Asset", {
        "hostname": "web-01.dmz.example.com",
        "ip": "203.0.113.10",
        "criticality": "medium",
    }))
    g.add_node(GraphNode("internal-app-server", "Asset", {
        "hostname": "app-01.internal.example.com",
        "ip": "10.10.1.5",
        "criticality": "high",
    }))
    g.add_node(GraphNode("crown-jewel-db", "Asset", {
        "hostname": "db-01.internal.example.com",
        "ip": "10.10.2.10",
        "criticality": "critical",
    }))
    g.add_node(GraphNode("vuln-cve-2024-9999", "Vulnerability", {
        "cve": "CVE-2024-9999",
        "cvss_score": 9.1,
        "description": "Remote code execution in ExampleCMS 3.x",
        "has_public_exploit": True,
    }))

    # Edges
    g.add_edge(GraphEdge("e1", "Targets", "threat-actor-apt99", "dmz-web-server", weight=0.9))
    g.add_edge(GraphEdge("e2", "Has", "dmz-web-server", "vuln-cve-2024-9999", weight=1.0))
    g.add_edge(GraphEdge("e3", "Exploits", "threat-actor-apt99", "vuln-cve-2024-9999", weight=0.85))
    g.add_edge(GraphEdge("e4", "Propagates", "dmz-web-server", "internal-app-server", weight=0.7))
    g.add_edge(GraphEdge("e5", "Propagates", "internal-app-server", "crown-jewel-db", weight=0.6))

    return g


# ---------------------------------------------------------------------------
# Step 2: Enumerate attack paths
# ---------------------------------------------------------------------------

def enumerate_paths(graph: AttackGraph) -> list[list[str]]:
    """Find all paths from the threat actor to the crown-jewel database."""
    finder = PathFinder()
    paths = finder.find_paths(
        graph,
        source="threat-actor-apt99",
        target="crown-jewel-db",
    )
    return paths


# ---------------------------------------------------------------------------
# Step 3: Score each path
# ---------------------------------------------------------------------------

def score_paths(paths: list[list[str]]) -> list:
    """Assign a risk score to each discovered attack path."""
    scorer = Scorer()
    results = []
    for i, path in enumerate(paths):
        path_input = AttackPathInput(
            path_id=f"ap-{i+1:03d}",
            # Mock dimension values derived from the graph metadata
            severity=0.88,      # CVE-2024-9999 has CVSS 9.1
            likelihood=0.75,    # Public exploit available
            impact=0.92,        # Crown jewel database is critical
            confidence=0.80,    # Two independent signals corroborate
            hours_since_last_signal=0.0,
        )
        score_result = scorer.score(path_input)
        results.append((path, score_result))
    return results


# ---------------------------------------------------------------------------
# Step 4: Explain each score
# ---------------------------------------------------------------------------

def explain_scores(scored_paths: list) -> None:
    """Print a human-readable explanation for each scored path."""
    explainer = Explainer()
    for path, score_result in scored_paths:
        explanation = explainer.explain(score_result)

        print("=" * 70)
        print(f"Attack Path : {' → '.join(path)}")
        print(f"Path ID     : {score_result.path_id}")
        print(f"Score       : {score_result.score:.1f}/100  [{score_result.band.upper()}]")
        print()
        print(f"Summary     : {explanation.summary}")
        print()
        print("Top Factors :")
        for factor in explanation.top_factors:
            print(f"  • {factor}")
        print()
        print("Recommended Actions :")
        for action in explanation.recommended_actions:
            print(f"  → {action}")
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("CADE — Cyber Attack Detection Engine")
    print("Basic Detection Pipeline Example")
    print()

    # 1. Build graph
    print("[1/4] Building attack graph ...")
    graph = build_mock_graph()
    print(f"      Nodes: {graph.node_count()}  |  Edges: {graph.edge_count()}")
    print()

    # 2. Find paths
    print("[2/4] Enumerating attack paths (actor → crown-jewel-db) ...")
    paths = enumerate_paths(graph)
    if not paths:
        print("      No attack paths found.")
        return
    print(f"      Found {len(paths)} path(s).")
    print()

    # 3. Score paths
    print("[3/4] Scoring attack paths ...")
    scored = score_paths(paths)
    print(f"      Scored {len(scored)} path(s).")
    print()

    # 4. Explain
    print("[4/4] Generating explanations ...")
    print()
    explain_scores(scored)


if __name__ == "__main__":
    main()
