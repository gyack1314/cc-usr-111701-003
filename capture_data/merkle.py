"""RFC 6962 Merkle 树原语：叶子/节点哈希、包含证明、追加一致性证明。

仅依赖标准库。哈希域分隔与 RFC 6962 第 2.1 节一致：

* 叶子哈希 = SHA256(0x00 || leaf_bytes)
* 内部节点哈希 = SHA256(0x01 || left || right)
* 空树根 = SHA256("")

一致性证明采用等价于 RFC 6962 第 2.1.3 节的子树分解布局：按旧树在
新树中的完整幂次子树边界逐段提供兄弟子树根，验证者同时重建旧根与
新根。生成与验证在本模块成对实现，并由 tests/test_merkle.py 对所有
小规模 (first, second) 组合穷举交叉检验，任何哈希被替换都会失败。
"""
import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
EMPTY_TREE_ROOT = hashlib.sha256(b"").digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """对叶子原文计算 RFC 6962 叶子哈希。"""
    if not isinstance(leaf_bytes, (bytes, bytearray)):
        raise TypeError("叶子原文必须是字节")
    return _sha256(_LEAF_PREFIX + bytes(leaf_bytes))


def node_hash(left: bytes, right: bytes) -> bytes:
    """合并两个子树根哈希。"""
    return _sha256(_NODE_PREFIX + left + right)


def root_from_hashes(hashes):
    """从叶子哈希序列自底向上计算树根，奇数节点上浮。"""
    level = list(hashes)
    if not level:
        return EMPTY_TREE_ROOT
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def tree_root(leaf_bytes_list):
    """从叶子原文序列计算树根。"""
    return root_from_hashes(leaf_hash(item) for item in leaf_bytes_list)


def inclusion_path(leaf_hashes, index: int):
    """生成 index 处叶子在给定叶子哈希序列中的包含证明路径。"""
    if index < 0 or index >= len(leaf_hashes):
        raise ValueError("叶子索引越界")
    level = list(leaf_hashes)
    idx = index
    path = []
    while len(level) > 1:
        if idx % 2:
            path.append(level[idx - 1])
        elif idx + 1 < len(level):
            path.append(level[idx + 1])
        # 奇数尾部节点上浮，该层没有兄弟可提供。
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
        idx //= 2
    return path


def verify_inclusion(index: int, tree_size: int, leaf_hash_value: bytes,
                     root_hash: bytes, proof_hashes) -> bool:
    """RFC 6962 条目包含证明验证。

    沿 fn/sn 两个游标向上合并；遇到奇数尾部上浮节点时只移动游标、
    不消费证明哈希。证明过长、过短或重建结果不等于树根均判失败。
    """
    if tree_size <= 0 or index < 0 or index >= tree_size:
        return False
    if len(leaf_hash_value) != 32 or len(root_hash) != 32:
        return False
    proof = list(proof_hashes)
    if any(not isinstance(h, (bytes, bytearray)) or len(h) != 32 for h in proof):
        return False
    fn, sn = index, tree_size - 1
    current = bytes(leaf_hash_value)
    pi = 0
    while sn > 0:
        if fn % 2 or fn != sn:
            if pi >= len(proof):
                return False
            sibling = proof[pi]
            pi += 1
            if fn % 2:
                current = node_hash(sibling, current)
            else:
                current = node_hash(current, sibling)
        fn //= 2
        sn //= 2
    return pi == len(proof) and current == root_hash


def _split_size(total: int) -> int:
    """小于 total 的最大二次幂（total >= 2）。"""
    return 1 << ((total - 1).bit_length() - 1)


def consistency_path(first: int, second: int, leaf_hashes):
    """生成 first -> second 的追加一致性证明哈希列表。"""
    if first < 0 or second < first or second > len(leaf_hashes):
        raise ValueError("一致性证明区间非法")
    if first == 0 or first == second:
        return []
    proof = []

    def build(old_size, new_size, offset):
        if old_size == new_size:
            # 旧树的完整子树根（边缘节点），直接作为证明哈希。
            proof.append(root_from_hashes(leaf_hashes[offset:offset + new_size]))
            return
        split = _split_size(new_size)
        if old_size <= split:
            build(old_size, split, offset)
            proof.append(root_from_hashes(leaf_hashes[offset + split:offset + new_size]))
        else:
            build(old_size - split, new_size - split, offset + split)
            proof.append(root_from_hashes(leaf_hashes[offset:offset + split]))

    build(first, second, 0)
    return proof


def verify_consistency(first: int, second: int, first_root: bytes,
                       second_root: bytes, proof_hashes) -> bool:
    """验证两个树头之间仅发生追加（append-only）。

    与 consistency_path 的子树分解同构：递归同时重建旧子树根与新子树
    树根，最后分别比对已确认的旧根与候选新根。first=0 表示旧树为空，
    无需证明；first==second 时证明必须为空且两根相同。
    """
    if first < 0 or second < first:
        return False
    if first == 0:
        return len(proof_hashes) == 0
    if first == second:
        return len(proof_hashes) == 0 and first_root == second_root
    if not proof_hashes or len(first_root) != 32 or len(second_root) != 32:
        return False
    proof = list(proof_hashes)
    if any(not isinstance(h, (bytes, bytearray)) or len(h) != 32 for h in proof):
        return False
    cursor = 0

    def rebuild(old_size, new_size):
        nonlocal cursor
        if old_size == new_size:
            if cursor >= len(proof):
                return None
            fringe = proof[cursor]
            cursor += 1
            return fringe, fringe
        split = _split_size(new_size)
        if old_size <= split:
            left = rebuild(old_size, split)
            if left is None or cursor >= len(proof):
                return None
            right = proof[cursor]
            cursor += 1
            old_left, new_left = left
            return old_left, node_hash(new_left, right)
        right = rebuild(old_size - split, new_size - split)
        if right is None or cursor >= len(proof):
            return None
        left = proof[cursor]
        cursor += 1
        old_right, new_right = right
        return node_hash(left, old_right), node_hash(left, new_right)

    rebuilt = rebuild(first, second)
    if rebuilt is None or cursor != len(proof):
        return False
    got_old, got_new = rebuilt
    return got_old == first_root and got_new == second_root
