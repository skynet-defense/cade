"""
engine.scoring.scorer — Threat risk scoring for CADE.

The Scorer computes a normalized 0-100 risk score for an attack path
based on four dimensions: severity, likelihood, impact, and confidence.
See docs/scoring-model.md for the full specification.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackPathInput:
    """Input data required by the Scorer to compute a risk score.

    Attributes:
        path_id: Unique identifier of the attack path being scored.
        severity: 0.0–1.0 measure of potential harm if the attack succeeds.
        likelihood: 0.0–1.0 estimate of the probability of success.
        impact: 0.0–1.0 measure of business impact upon compromise.
        confidence: 0.0–1.0 confidence in the detection and its metadata.
        hours_since_last_signal: Hours elapsed since the most recent
            corroborating signal.  Used for temporal decay.  Set to
            ``0.0`` to skip decay.
        metadata: Additional context forwarded to the score result.
    """

    path_id: str
    severity: float
    likelihood: float
    impact: float
    confidence: float
    hours_since_last_signal: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    """Output of the Scorer for a single attack path.

    Attributes:
        path_id: ID of the scored attack path.
        score: Normalized risk score in the range 0.0–100.0.
        severity: Input severity dimension value.
        likelihood: Input likelihood dimension value.
        impact: Input impact dimension value.
        confidence: Input confidence dimension value.
        band: Risk band label derived from ``score``:
            ``"critical"`` (≥90), ``"high"`` (≥70), ``"medium"`` (≥40),
            ``"low"`` (≥10), or ``"informational"`` (<10).
        decayed: ``True`` if temporal decay was applied to this score.
        metadata: Forwarded metadata from the input.
    """

    path_id: str
    score: float
    severity: float
    likelihood: float
    impact: float
    confidence: float
    band: str
    decayed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


# Default dimension weights — must sum to 1.0.
_DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": 0.35,
    "likelihood": 0.25,
    "impact": 0.30,
    "confidence": 0.10,
}

# Temporal decay constant (per hour).  ~50% decay at ~35 hours.
_DECAY_LAMBDA: float = 0.02


def _band_for_score(score: float) -> str:
    """Return the risk band label for a normalized score."""
    if score >= 90.0:
        return "critical"
    if score >= 70.0:
        return "high"
    if score >= 40.0:
        return "medium"
    if score >= 10.0:
        return "low"
    return "informational"


class Scorer:
    """Computes normalized 0-100 risk scores for CADE attack paths.

    Scores are computed as a weighted sum of four dimensions (severity,
    likelihood, impact, confidence) and then normalized to 0-100.
    Temporal decay is applied when ``hours_since_last_signal`` is
    non-zero, *unless* the resulting score would fall in the
    ``"critical"`` band.

    Custom dimension weights may be supplied at construction time.

    Example::

        scorer = Scorer()
        result = scorer.score(AttackPathInput(
            path_id="ap-001",
            severity=0.8,
            likelihood=0.6,
            impact=0.9,
            confidence=0.7,
        ))
        print(result.score, result.band)
    """

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        """Initialize the Scorer with optional custom dimension weights.

        Args:
            weights: A dict with keys ``severity``, ``likelihood``,
                ``impact``, and ``confidence`` whose values sum to 1.0.
                Defaults to :data:`_DEFAULT_WEIGHTS` when ``None``.

        Raises:
            ValueError: If provided weights do not sum to approximately 1.0.
        """
        self._weights = weights or dict(_DEFAULT_WEIGHTS)
        total = sum(self._weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Scorer weights must sum to 1.0, got {total:.6f}."
            )

    def score(self, attack_path: AttackPathInput) -> ScoreResult:
        """Compute a risk score for the given attack path.

        Args:
            attack_path: An :class:`AttackPathInput` populated with the
                four scoring dimensions and optional decay metadata.

        Returns:
            A :class:`ScoreResult` containing the normalized score,
            band label, and input dimension values.

        Raises:
            ValueError: If any dimension value is outside [0.0, 1.0].
        """
        for dim_name in ("severity", "likelihood", "impact", "confidence"):
            value = getattr(attack_path, dim_name)
            if not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"Dimension '{dim_name}' must be in [0.0, 1.0], got {value}."
                )

        raw = (
            self._weights["severity"] * attack_path.severity
            + self._weights["likelihood"] * attack_path.likelihood
            + self._weights["impact"] * attack_path.impact
            + self._weights["confidence"] * attack_path.confidence
        )
        normalized = round(raw * 100.0, 2)

        decayed = False
        if attack_path.hours_since_last_signal > 0.0:
            pre_decay_band = _band_for_score(normalized)
            if pre_decay_band != "critical":
                normalized = round(
                    normalized * math.exp(-_DECAY_LAMBDA * attack_path.hours_since_last_signal),
                    2,
                )
                decayed = True

        normalized = max(0.0, min(100.0, normalized))

        return ScoreResult(
            path_id=attack_path.path_id,
            score=normalized,
            severity=attack_path.severity,
            likelihood=attack_path.likelihood,
            impact=attack_path.impact,
            confidence=attack_path.confidence,
            band=_band_for_score(normalized),
            decayed=decayed,
            metadata=dict(attack_path.metadata),
        )
