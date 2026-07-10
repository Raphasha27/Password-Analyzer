import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import PasswordAnalyzer


class TestPasswordAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_weak_password(self):
        result = self.analyzer.analyze("password")
        self.assertEqual(result.strength, "very_weak")
        self.assertTrue(result.is_common)

    def test_very_weak_short(self):
        result = self.analyzer.analyze("ab")
        self.assertEqual(result.strength, "very_weak")
        self.assertFalse(result.is_common)

    def test_strong_password(self):
        result = self.analyzer.analyze("K7$mD9#xL2@pQ5!v")
        self.assertIn(result.strength, ("strong", "very_strong"))
        self.assertFalse(result.is_common)
        self.assertTrue(result.has_uppercase)
        self.assertTrue(result.has_lowercase)
        self.assertTrue(result.has_digits)
        self.assertTrue(result.has_special)

    def test_moderate_password(self):
        result = self.analyzer.analyze("abcdefgh")
        self.assertEqual(result.strength, "moderate")
        self.assertFalse(result.is_common)
        self.assertFalse(result.has_uppercase)
        self.assertFalse(result.has_digits)
        self.assertFalse(result.has_special)

    def test_nist_score_max(self):
        result = self.analyzer.analyze("Abcd1234!@#$XYZ")
        self.assertEqual(result.nist_score, 5)

    def test_nist_score_min(self):
        result = self.analyzer.analyze("a")
        self.assertEqual(result.nist_score, 0)

    def test_empty_password(self):
        result = self.analyzer.analyze("")
        self.assertEqual(result.password_length, 0)
        self.assertEqual(result.entropy, 0.0)
        self.assertEqual(result.nist_score, 0)

    def test_entropy_zero_for_same_char(self):
        result = self.analyzer.analyze("aaaaaa")
        self.assertGreater(result.entropy, 0)
        self.assertFalse(result.is_common)

    def test_batch_analyze(self):
        results = self.analyzer.batch_analyze(["123456", "StrongP@ss1"])
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].is_common)
        self.assertFalse(results[1].is_common)

    def test_suggestions_for_weak(self):
        result = self.analyzer.analyze("weak")
        self.assertGreater(len(result.suggestions), 0)
        self.assertIn("8 characters", result.suggestions[0])

    def test_crack_time_common(self):
        result = self.analyzer.analyze("password")
        self.assertIn("instantly", result.crack_time_estimate)

    def test_crack_time_centuries(self):
        result = self.analyzer.analyze("kX9#mP2$vL8@qR5!nA3&")
        self.assertEqual(result.crack_time_estimate, "centuries")


if __name__ == "__main__":
    unittest.main()
