"""
engine.simulation.simulator — Attack scenario simulation for CADE.

The Simulator models how a threat actor might traverse an attack graph
under a specified scenario (e.g., opportunistic vs. targeted APT).
Simulation results feed into the Scorer and Explainer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.graph.graph import AttackGraph


@dataclass
class SimulationScenario:
    """Describes the parameters of an attack simulation run.

    Attributes:
        scenario_id: Unique identifier for this scenario.
        actor_id: Node ID of the threat actor initiating the simulation.
        target_id: Node ID of the intended target asset.
        actor_capability: Capability level: ``"low"``, ``"medium"``,
            ``"high"``, or ``"nation-state"``.
        max_steps: Maximum number of lateral movement steps to simulate.
        metadata: Arbitrary scenario-specific configuration.
    """

    scenario_id: str
    actor_id: str
    target_id: str
    actor_capability: str = "medium"
    max_steps: int = 10
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SimulationResult:
    """Output of a single simulation run.

    Attributes:
        scenario_id: ID of the scenario that produced this result.
        paths_explored: Number of attack paths evaluated.
        reachable: Whether the target is reachable from the actor node.
        most_likely_path: Node ID sequence of the highest-weight path,
            or an empty list if the target is unreachable.
        step_probabilities: Per-step reachability probabilities along
            the most likely path.
        metadata: Additional simulation output metadata.
    """

    scenario_id: str
    paths_explored: int
    reachable: bool
    most_likely_path: list[str] = field(default_factory=list)
    step_probabilities: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Simulator:
    """Simulates threat actor movement across an :class:`AttackGraph`.

    The Simulator evaluates a :class:`SimulationScenario` against an
    :class:`AttackGraph` to determine whether a target is reachable and
    to identify the most probable attack path.

    The current implementation is a stub that returns a placeholder
    result.  Full probabilistic simulation will be implemented in v0.3.

    Example::

        sim = Simulator()
        scenario = SimulationScenario(
            scenario_id="s-1",
            actor_id="actor-1",
            target_id="db-server",
        )
        result = sim.run(attack_graph, scenario)
        print(result.reachable, result.most_likely_path)
    """

    def run(
        self,
        attack_graph: AttackGraph,
        scenario: SimulationScenario,
    ) -> SimulationResult:
        """Run a simulation scenario against the given attack graph.

        Args:
            attack_graph: The :class:`AttackGraph` representing the
                target environment.
            scenario: The :class:`SimulationScenario` defining the
                actor, target, and simulation parameters.

        Returns:
            A :class:`SimulationResult` describing the outcome of the
            simulation.

        Note:
            This is a stub implementation.  Full probabilistic path
            weighting based on edge weights and actor capability will
            be added in v0.3.
        """
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            paths_explored=0,
            reachable=False,
            most_likely_path=[],
            step_probabilities=[],
            metadata={"status": "stub — not yet implemented"},
        )
