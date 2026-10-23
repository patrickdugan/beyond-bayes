"""Guard the project's intended Lean proof boundary from silent erosion."""
import unittest
from pathlib import Path


class FormalContracts(unittest.TestCase):
    def test_v06_lean_has_premises_and_no_placeholders(self):
        text=Path('lean/ACE/Conditional.lean').read_text()
        self.assertIn('eventMassMonotone', text)
        self.assertIn('villePremise', text)
        self.assertIn('actual_clean_score_dominates_infimum', text)
        self.assertNotIn('sorry', text)


if __name__=='__main__':
    unittest.main()
