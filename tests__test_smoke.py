import unittest

from backend.app.ml import assess_risk


class SmokeTest(unittest.TestCase):
    def test_risk_scoring_is_bounded_and_explainable(self):
        assessment = assess_risk('high', 'medium')
        self.assertEqual(assessment.severity, 'high')
        self.assertEqual(assessment.confidence, 'medium')
        self.assertTrue(0 < assessment.score <= 100)
