"""
tests.test_scoring — Unit tests for engine.scoring.scorer.Scorer.
"""

import unittest

from engine.scoring.scorer import AttackPathInput, Scorer, ScoreResult


class TestScorerScore(unittest.TestCase):
    """Tests for Scorer.score."""

    def setUp(self):
        self.scorer = Scorer()

    def _make_input(self, **kwargs) -> AttackPathInput:
        defaults = dict(
            path_id="ap-test",
            severity=0.5,
            likelihood=0.5,
            impact=0.5,
            confidence=0.5,
        )
        defaults.update(kwargs)
        return AttackPathInput(**defaults)

    # ------------------------------------------------------------------
    # Return type and range
    # ------------------------------------------------------------------

    def test_score_returns_score_result(self):
        result = self.scorer.score(self._make_input())
        self.assertIsInstance(result, ScoreResult)

    def test_score_is_float(self):
        result = self.scorer.score(self._make_input())
        self.assertIsInstance(result.score, float)

    def test_score_is_within_0_to_100(self):
        result = self.scorer.score(self._make_input())
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 100.0)

    def test_score_zero_for_all_zero_dimensions(self):
        result = self.scorer.score(self._make_input(
            severity=0.0, likelihood=0.0, impact=0.0, confidence=0.0
        ))
        self.assertAlmostEqual(result.score, 0.0)

    def test_score_100_for_all_one_dimensions(self):
        result = self.scorer.score(self._make_input(
            severity=1.0, likelihood=1.0, impact=1.0, confidence=1.0
        ))
        self.assertAlmostEqual(result.score, 100.0)

    # ------------------------------------------------------------------
    # Band labels
    # ------------------------------------------------------------------

    def test_band_critical_for_high_score(self):
        result = self.scorer.score(self._make_input(
            severity=1.0, likelihood=1.0, impact=1.0, confidence=1.0
        ))
        self.assertEqual(result.band, "critical")

    def test_band_informational_for_zero_score(self):
        result = self.scorer.score(self._make_input(
            severity=0.0, likelihood=0.0, impact=0.0, confidence=0.0
        ))
        self.assertEqual(result.band, "informational")

    def test_band_medium_for_midrange_score(self):
        # With default weights, score ≈ 50 → "medium"
        result = self.scorer.score(self._make_input(
            severity=0.5, likelihood=0.5, impact=0.5, confidence=0.5
        ))
        self.assertEqual(result.band, "medium")

    # ------------------------------------------------------------------
    # Dimension values preserved in result
    # ------------------------------------------------------------------

    def test_dimensions_preserved_in_result(self):
        inp = self._make_input(severity=0.3, likelihood=0.7, impact=0.6, confidence=0.9)
        result = self.scorer.score(inp)
        self.assertAlmostEqual(result.severity, 0.3)
        self.assertAlmostEqual(result.likelihood, 0.7)
        self.assertAlmostEqual(result.impact, 0.6)
        self.assertAlmostEqual(result.confidence, 0.9)

    def test_path_id_preserved_in_result(self):
        result = self.scorer.score(self._make_input(path_id="my-path-123"))
        self.assertEqual(result.path_id, "my-path-123")

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def test_raises_value_error_for_severity_above_1(self):
        with self.assertRaises(ValueError):
            self.scorer.score(self._make_input(severity=1.1))

    def test_raises_value_error_for_likelihood_below_0(self):
        with self.assertRaises(ValueError):
            self.scorer.score(self._make_input(likelihood=-0.1))

    def test_raises_value_error_for_impact_above_1(self):
        with self.assertRaises(ValueError):
            self.scorer.score(self._make_input(impact=2.0))

    # ------------------------------------------------------------------
    # Temporal decay
    # ------------------------------------------------------------------

    def test_no_decay_when_hours_zero(self):
        inp = self._make_input(
            severity=0.5, likelihood=0.5, impact=0.5, confidence=0.5,
            hours_since_last_signal=0.0,
        )
        result = self.scorer.score(inp)
        self.assertFalse(result.decayed)

    def test_decay_applied_for_nonzero_hours(self):
        inp = self._make_input(
            severity=0.5, likelihood=0.5, impact=0.5, confidence=0.5,
            hours_since_last_signal=35.0,
        )
        no_decay_result = self.scorer.score(self._make_input(
            severity=0.5, likelihood=0.5, impact=0.5, confidence=0.5,
        ))
        decay_result = self.scorer.score(inp)
        self.assertTrue(decay_result.decayed)
        self.assertLess(decay_result.score, no_decay_result.score)

    def test_critical_band_not_decayed(self):
        """Critical scores must not be decayed regardless of signal age."""
        inp = self._make_input(
            severity=1.0, likelihood=1.0, impact=1.0, confidence=1.0,
            hours_since_last_signal=100.0,
        )
        result = self.scorer.score(inp)
        self.assertFalse(result.decayed)
        self.assertEqual(result.band, "critical")

    # ------------------------------------------------------------------
    # Custom weights
    # ------------------------------------------------------------------

    def test_custom_weights_accepted(self):
        scorer = Scorer(weights={
            "severity": 0.4,
            "likelihood": 0.3,
            "impact": 0.2,
            "confidence": 0.1,
        })
        result = scorer.score(self._make_input(
            severity=1.0, likelihood=0.0, impact=0.0, confidence=0.0
        ))
        self.assertAlmostEqual(result.score, 40.0)

    def test_invalid_weights_raise_value_error(self):
        with self.assertRaises(ValueError):
            Scorer(weights={
                "severity": 0.5,
                "likelihood": 0.5,
                "impact": 0.5,
                "confidence": 0.5,
            })


if __name__ == "__main__":
    unittest.main()
