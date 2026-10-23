"""RFC 9162-style SHA-256 Merkle tree for ACE's signed observation intake.

Prefix separated leaves (0x00) and interior nodes (0x01), unbalanced RFC
Merkle tree, inclusion and consistency paths. Serialized report bytes are
canonical ASCII JSON as defined in provenance._encoding.

This is a research implementation, not an audited CT implementation.
"""
from __future__ import annotations

import hashlib
import hmac


def _h(blob: bytes) -> bytes:
    return hashlib.sha256(blob).digest()


def leaf_hash(blob: bytes) -> bytes:
    return _h(b'\x00' + blob)


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError('SHA-256 subtree digest must be 32 bytes')
    return _h(b'\x01' + left + right)


def _left_size(n: int) -> int:
    if n < 2:
        raise ValueError('tree needs at least two entries')
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves: list[bytes] | tuple[bytes, ...]) -> bytes:
    n = len(leaves)
    if not n:
        return _h(b'')
    if n == 1:
        return leaf_hash(leaves[0])
    k = _left_size(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes] | tuple[bytes, ...], index: int) -> list[str]:
    if type(index) is not int or index < 0 or index >= len(leaves):
        raise ValueError('invalid leaf index')
    if len(leaves) == 1:
        return []
    k = _left_size(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:]).hex()]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k]).hex()]


def verify_inclusion(leaf: bytes, index: int, size: int,
                     root_hex: str, path: list[str]) -> bool:
    if type(size) is not int or type(index) is not int or size < 1 or not 0 <= index < size:
        return False
    try:
        root = bytes.fromhex(root_hex)
        nodes = [bytes.fromhex(h) for h in path]
        if len(root) != 32 or any(len(h) != 32 for h in nodes):
            return False
        cursor = iter(nodes)
        def walk(i: int, n: int) -> bytes:
            if n == 1:
                return leaf_hash(leaf)
            k = _left_size(n)
            if i < k:
                left = walk(i, k)
                return node_hash(left, next(cursor))
            right = walk(i - k, n - k)
            return node_hash(next(cursor), right)
        calculated = walk(index, size)
        try:
            next(cursor)
            return False
        except StopIteration:
            return hmac.compare_digest(calculated, root)
    except (ValueError, TypeError, StopIteration, RecursionError):
        return False


def consistency_proof(leaves: list[bytes] | tuple[bytes, ...], old_size: int) -> list[str]:
    n = len(leaves)
    if type(old_size) is not int or not 0 <= old_size <= n:
        raise ValueError('invalid historical tree size')
    if old_size in (0, n):
        return []
    def subproof(items, m: int, complete: bool) -> list[bytes]:
        if m == len(items):
            return [] if complete else [merkle_root(items)]
        k = _left_size(len(items))
        if m <= k:
            return subproof(items[:k], m, complete) + [merkle_root(items[k:])]
        return subproof(items[k:], m - k, False) + [merkle_root(items[:k])]
    return [v.hex() for v in subproof(leaves, old_size, True)]


def verify_consistency(old_size: int, new_size: int,
                       old_root_hex: str, new_root_hex: str,
                       path: list[str]) -> bool:
    """Verify the short consistency proof from RFC 9162 section 2.1.4.2."""
    if (type(old_size) is not int or type(new_size) is not int or
        old_size < 0 or new_size < old_size):
        return False
    try:
        old = bytes.fromhex(old_root_hex)
        new = bytes.fromhex(new_root_hex)
        proof = [bytes.fromhex(v) for v in path]
        if len(old) != 32 or len(new) != 32 or any(len(v) != 32 for v in proof):
            return False
        if old_size == 0:
            return hmac.compare_digest(old, _h(b'')) and path == []
        if old_size == new_size:
            return hmac.compare_digest(old, new) and path == []
        if not proof:
            return False
        if old_size & (old_size - 1) == 0:
            proof.insert(0, old)
        fn, sn = old_size - 1, new_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = proof[0]
        for c in proof[1:]:
            if sn == 0:
                return False
            if (fn & 1) or (fn == sn):
                fr = node_hash(c, fr)
                sr = node_hash(c, sr)
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = node_hash(sr, c)
            fn >>= 1
            sn >>= 1
        return sn == 0 and hmac.compare_digest(fr, old) and hmac.compare_digest(sr, new)
    except (ValueError, TypeError, IndexError):
        return False
