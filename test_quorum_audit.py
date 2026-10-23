import unittest

from quorum_audit import exact_audit


class QuorumArithmeticTests(unittest.TestCase):
    def test_arithmetic_conditions_match_exhaustive_honest_intersections(self):
        for n in range(2,8):
            for f in range(n):
                for q in range(1,n+1):
                    for r in range(1,n+1):
                        x=exact_audit(n,f,q,r)
                        self.assertEqual(x['receipt_omission_excluded'],
                                         x['arithmetic_receipt_bound'],(n,f,q,r))
                        self.assertEqual(x['split_view_excluded'],
                                         x['arithmetic_split_bound'],(n,f,q,r))


if __name__=='__main__':unittest.main()
