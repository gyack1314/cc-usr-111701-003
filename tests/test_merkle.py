"""穷举验证 Merkle 包含证明与追加一致性证明的生成/验证配对。"""
import hashlib
import unittest

from capture_data import merkle

MAX_LEAVES = 64
ZERO = b"\x00" * 32


def build_leaves(n):
    return [bytes([i]) * (i + 1) for i in range(n)]


class RootTest(unittest.TestCase):
    def test_empty_tree_root_is_sha256_of_empty(self):
        self.assertEqual(merkle.tree_root([]),
                         hashlib.sha256(b"").digest())

    def test_leaf_and_node_domain_separation(self):
        data = b"abc"
        self.assertEqual(merkle.leaf_hash(data),
                         hashlib.sha256(b"\x00" + data).digest())
        self.assertEqual(merkle.node_hash(ZERO, ZERO),
                         hashlib.sha256(b"\x01" + ZERO + ZERO).digest())

    def test_incremental_append_changes_root_deterministically(self):
        leaves = build_leaves(8)
        roots = [merkle.tree_root(leaves[:n]) for n in range(9)]
        self.assertEqual(len(set(roots[1:])), 8)
        # 全量重建与逐叶子序列结果一致。
        self.assertEqual(
            merkle.root_from_hashes(merkle.leaf_hash(x) for x in leaves),
            roots[8])


class InclusionTest(unittest.TestCase):
    def test_all_indices_all_sizes(self):
        for n in range(1, MAX_LEAVES + 1):
            leaves = build_leaves(n)
            hashes = [merkle.leaf_hash(x) for x in leaves]
            root = merkle.root_from_hashes(hashes)
            for index in range(n):
                path = merkle.inclusion_path(hashes, index)
                self.assertTrue(
                    merkle.verify_inclusion(index, n, hashes[index], root, path),
                    f"包含证明自验失败 n={n} index={index}")

    def test_rfc_style_rebuilt_root_matches(self):
        # 手工核验一个已知结构：3 叶子时索引 2 的证明只有 [F01]。
        leaves = build_leaves(3)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        f01 = merkle.node_hash(hashes[0], hashes[1])
        root = merkle.node_hash(f01, hashes[2])
        path = merkle.inclusion_path(hashes, 2)
        self.assertEqual(path, [f01])
        self.assertTrue(merkle.verify_inclusion(2, 3, hashes[2], root, path))

    def test_tampered_proof_or_root_rejected(self):
        leaves = build_leaves(10)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        root = merkle.root_from_hashes(hashes)
        path = merkle.inclusion_path(hashes, 4)
        self.assertFalse(merkle.verify_inclusion(
            4, 10, hashes[4], merkle.node_hash(root, ZERO)[:32], path))
        tampered = list(path)
        tampered[0] = bytes(32 - len(tampered[0])) + b"\xff" + tampered[0][1:]
        tampered[0] = bytes([tampered[0][0] ^ 0xFF]) + tampered[0][1:]
        self.assertFalse(merkle.verify_inclusion(
            4, 10, hashes[4], root, tampered))
        self.assertFalse(merkle.verify_inclusion(
            4, 10, hashes[4], root, path[:-1]))
        self.assertFalse(merkle.verify_inclusion(
            4, 10, hashes[4], root, path + [ZERO]))
        self.assertFalse(merkle.verify_inclusion(
            5, 10, hashes[4], root, path))
        # 对另一棵树的根必须失败。
        other_root = merkle.root_from_hashes(hashes[:9])
        self.assertFalse(merkle.verify_inclusion(
            4, 9, hashes[4], other_root if other_root != root else ZERO, path))

    def test_index_bounds_rejected(self):
        leaves = build_leaves(4)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        root = merkle.root_from_hashes(hashes)
        path = merkle.inclusion_path(hashes, 0)
        self.assertFalse(merkle.verify_inclusion(-1, 4, hashes[0], root, path))
        self.assertFalse(merkle.verify_inclusion(4, 4, hashes[0], root, path))
        self.assertFalse(merkle.verify_inclusion(0, 0, hashes[0], root, path))


class ConsistencyTest(unittest.TestCase):
    def test_all_pairs(self):
        for n in range(1, MAX_LEAVES + 1):
            leaves = build_leaves(n)
            hashes = [merkle.leaf_hash(x) for x in leaves]
            for first in range(0, n + 1):
                for second in range(first, n + 1):
                    old_root = merkle.root_from_hashes(hashes[:first])
                    new_root = merkle.root_from_hashes(hashes[:second])
                    proof = merkle.consistency_path(first, second, hashes)
                    self.assertTrue(
                        merkle.verify_consistency(
                            first, second, old_root, new_root, proof),
                        f"一致性证明自验失败 {first}->{second}")

    def test_empty_old_tree_needs_no_proof(self):
        leaves = build_leaves(5)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        root = merkle.root_from_hashes(hashes)
        self.assertTrue(merkle.verify_consistency(0, 5, b"", root, []))
        self.assertEqual(merkle.consistency_path(0, 5, hashes), [])

    def test_equal_sizes_need_empty_proof_and_equal_roots(self):
        leaves = build_leaves(5)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        root = merkle.root_from_hashes(hashes)
        self.assertTrue(merkle.verify_consistency(5, 5, root, root, []))
        self.assertFalse(merkle.verify_consistency(5, 5, root, ZERO, []))

    def test_tampered_consistency_rejected(self):
        leaves = build_leaves(12)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        old_root = merkle.root_from_hashes(hashes[:5])
        new_root = merkle.root_from_hashes(hashes)
        proof = merkle.consistency_path(5, 12, hashes)
        tampered = list(proof)
        tampered[0] = bytes([tampered[0][0] ^ 0x01]) + tampered[0][1:]
        self.assertFalse(merkle.verify_consistency(
            5, 12, old_root, new_root, tampered))
        self.assertFalse(merkle.verify_consistency(
            5, 12, old_root, new_root, proof[:-1]))
        # 旧根不匹配也必须失败（证明无法桥接另一条历史）。
        self.assertFalse(merkle.verify_consistency(
            5, 12, ZERO, new_root, proof))
        # 分叉新树：替换最后一片叶子后根变化，旧证明不再成立。
        forked = list(leaves)
        forked[-1] = b"different-leaf-bytes"
        forked_hashes = [merkle.leaf_hash(x) for x in forked]
        forked_root = merkle.root_from_hashes(forked_hashes)
        self.assertFalse(merkle.verify_consistency(
            5, 12, old_root, forked_root, proof))

    def test_invalid_ranges(self):
        leaves = build_leaves(6)
        hashes = [merkle.leaf_hash(x) for x in leaves]
        with self.assertRaises(ValueError):
            merkle.consistency_path(4, 2, hashes)
        with self.assertRaises(ValueError):
            merkle.consistency_path(-1, 2, hashes)


if __name__ == "__main__":
    unittest.main()
