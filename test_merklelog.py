import hashlib
from itertools import product
import unittest

from merklelog import merkle_root, inclusion_proof, verify_inclusion, consistency_proof, verify_consistency


class MerkleProofTests(unittest.TestCase):
    def setUp(self):
        self.leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(35)]

    def test_empty_and_singleton(self):
        self.assertEqual(merkle_root([]), hashlib.sha256(b'').digest())
        root = merkle_root([b'x']).hex()
        self.assertTrue(verify_inclusion(b'x', 0, 1, root, []))
        self.assertFalse(verify_inclusion(b'x', 1, 1, root, []))

    def test_inclusion_every_position_and_malformed_paths(self):
        for n in range(1, 36):
            items = self.leaves[:n]
            root = merkle_root(items).hex()
            for i, item in enumerate(items):
                path = inclusion_proof(items, i)
                self.assertTrue(verify_inclusion(item, i, n, root, path), (n,i,path))
                self.assertFalse(verify_inclusion(item + b'!',i,n,root,path))
                self.assertFalse(verify_inclusion(item,i,n,'00'*32,path))
                self.assertFalse(verify_inclusion(item,i,n,root,path + ['00'*32]))
                if path:
                    self.assertFalse(verify_inclusion(item,i,n,root,path[:-1]))

    def test_consistency_all_pairs(self):
        for n in range(0, 36):
            newer = self.leaves[:n]
            h_new = merkle_root(newer).hex()
            for m in range(n+1):
                h_old = merkle_root(newer[:m]).hex()
                proof = consistency_proof(newer, m)
                self.assertTrue(verify_consistency(m,n,h_old,h_new,proof), (m,n,proof))
                if m and m < n:
                    self.assertFalse(verify_consistency(m,n,'00'*32,h_new,proof))
                    self.assertFalse(verify_consistency(m,n,h_old,'00'*32,proof))
                    self.assertFalse(verify_consistency(m,n,h_old,h_new,proof+['00'*32]))

    def test_prefix_swap_breaks_consistency(self):
        for n in range(2, 30):
            old = self.leaves[:n-1]
            swapped = self.leaves[:n]
            swapped[0] = b'evil'
            self.assertFalse(verify_consistency(n-1,n,merkle_root(old).hex(),
                                                merkle_root(swapped).hex(),
                                                consistency_proof(swapped,n-1)))


if __name__ == '__main__':
    unittest.main()
