"""
engine.explainability.explainer — Human-readable threat explanations for CADE.

The Explainer converts a ScoreResult into a structured, plain-English
explanation that analysts can read without consulting raw score data.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.scoring.scorer import ScoreResult


@dataclass
class Explanation:
    """A human-readable explanation of a CADE threat score.

    Attributes:
        path_id: ID of the attack path this explanation refers to.
        summary: One-sentence summary of the overall risk.
        score_narrative: Explanation of the numeric score and band.
        top_factors: Ordered list of the top contributing factors,
            most significant first.
        recommended_actions: Suggested analyst or remediation actions.
        raw_score: The underlying numeric score for reference.
        band: The risk band label.
    """

    path_id: str
    summary: str
    score_narrative: str
    top_factors: list[str]
    recommended_actions: list[str]
    raw_score: float
    band: str


# Thresholds that trigger a factor being highlighted in the explanation.
_HIGH_DIMENSION_THRESHOLD = 0.7
_MEDIUM_DIMENSION_THRESHOLD = 0.4


class Explainer:
    """Generates human-readable explanations for CADE score results.

    The Explainer analyses the four scoring dimensions and the band label
    from a :class:`~engine.scoring.scorer.ScoreResult` to produce an
    :class:`Explanation` containing a summary, narrative, contributing
    factors, and recommended actions.

    Example::

        from engine.scoring.scorer import Scorer, AttackPathInput
        from engine.explainability.explainer import Explainer

        scorer = Scorer()
        result = scorer.score(AttackPathInput(
            path_id="ap-001",
            severity=0.85,
            likelihood=0.6,
            impact=0.9,
            confidence=0.75,
        ))
        explainer = Explainer()
        explanation = explainer.explain(result)
        print(explanation.summary)
        print(explanation.top_factors)
    """

    def explain(self, score_result: ScoreResult) -> Explanation:
        """Produce a human-readable explanation for a score result.

        Args:
            score_result: A :class:`~engine.scoring.scorer.ScoreResult`
                as returned by :meth:`~engine.scoring.scorer.Scorer.score`.

        Returns:
            An :class:`Explanation` instance with a summary, narrative,
            top contributing factors, and recommended actions.
        """
        band = score_result.band
        score = score_result.score

        summary = self._build_summary(score_result)
        narrative = self._build_narrative(score, band, score_result.decayed)
        factors = self._identify_factors(score_result)
        actions = self._recommend_actions(band, score_result)

        return Explanation(
            path_id=score_result.path_id,
            summary=summary,
            score_narrative=narrative,
            top_factors=factors,
            recommended_actions=actions,
            raw_score=score,
            band=band,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: ScoreResult) -> str:
        band_descriptions = {
            "critical": "critically high",
            "high": "high",
            "medium": "moderate",
            "low": "low",
            "informational": "informational",
        }
        level = band_descriptions.get(result.band, result.band)
        decay_note = " (score has been adjusted for signal age)" if result.decayed else ""
        return (
            f"Attack path '{result.path_id}' presents a {level} risk "
            f"with a normalized score of {result.score:.1f}/100{decay_note}."
        )

    def _build_narrative(self, score: float, band: str, decayed: bool) -> str:
        decay_clause = (
            " Temporal decay has been applied because no new corroborating "
            "signals have arrived recently."
            if decayed
            else ""
        )
        return (
            f"The overall risk score is {score:.1f} out of 100, placing this "
            f"path in the '{band}' band.{decay_clause}"
        )

    def _identify_factors(self, result: ScoreResult) -> list[str]:
        dimensions = [
            ("severity", result.severity, "High severity indicates significant potential harm if exploited."),
            ("impact", result.impact, "High impact indicates broad business consequences upon compromise."),
            ("likelihood", result.likelihood, "High likelihood suggests the attack is readily achievable."),
            ("confidence", result.confidence, "High confidence reflects strong corroboration from multiple signals."),
        ]

        factors: list[str] = []
        for name, value, description in sorted(dimensions, key=lambda x: x[1], reverse=True):
            if value >= _HIGH_DIMENSION_THRESHOLD:
                factors.append(f"{name.capitalize()} is elevated ({value:.2f}): {description}")
            elif value >= _MEDIUM_DIMENSION_THRESHOLD:
                factors.append(f"{name.capitalize()} is moderate ({value:.2f}).")

        if not factors:
            factors.append("No individual dimension is elevated; the cumulative combination drives the score.")

        return factors

    def _recommend_actions(self, band: str, result: ScoreResult) -> list[str]:
        actions: list[str] = []

        if band == "critical":
            actions.append("Initiate incident response immediately.")
            actions.append("Isolate affected assets from the network.")
        elif band == "high":
            actions.append("Escalate to the security operations team for urgent investigation.")
            actions.append("Apply available patches or workarounds within 24 hours.")
        elif band == "medium":
            actions.append("Schedule remediation within the next sprint cycle.")
            actions.append("Increase monitoring on affected assets.")
        elif band == "low":
            actions.append("Review during the next regular security review cycle.")
        else:
            actions.append("No immediate action required; retain for context.")

        if result.likelihood >= _HIGH_DIMENSION_THRESHOLD:
            actions.append("Validate that exploit mitigations (e.g., WAF rules, network segmentation) are in place.")
        if result.severity >= _HIGH_DIMENSION_THRESHOLD:
            actions.append("Review data classification for assets on this path; consider additional access controls.")

        return actions
