"""合成 CT 日志引擎：确定性地维护叶子序列、签名树头与 Merkle 证明。

仅测试与演示使用。日志随 append 增长，每个树大小有确定时间戳，树头
用与采集器相同的 HMAC 方案签名；证明由 capture_data.merkle 的生成器
产出，采集器用独立的验证器核验。
"""
import base64
import hashlib
import json

from capture_data import merkle
from capture_data.verifier import log_identity, sign_tree_head

_BASE_TS = 1_700_000_000_000


def make_leaf_bytes(index: int, domain: str = "example.test") -> bytes:
    """构造合成叶子原文（JSON 文档，模拟 RFC 6962 MerkleTreeLeaf 载荷）。"""
    doc = {
        "certificate": f"CN={domain}:{index}",
        "subject": domain,
        "san": [f"leaf{index}.{domain}", domain],
        "serial": index,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SyntheticLog:
    """内存中的可追加合成日志。"""

    def __init__(self, verification_key: bytes, leaves=None):
        self.key = bytes(verification_key)
        self.log_id = log_identity(self.key)
        self._leaves = list(leaves or [])

    def append(self, leaf_bytes: bytes):
        self._leaves.append(bytes(leaf_bytes))
        return len(self._leaves) - 1

    def size(self):
        return len(self._leaves)

    def leaf_bytes(self, index):
        return self._leaves[index]

    def leaf_hashes(self, up_to=None):
        leaves = self._leaves if up_to is None else self._leaves[:up_to]
        return [merkle.leaf_hash(item) for item in leaves]

    def root_hash(self, size=None):
        if size is None:
            size = self.size()
        return merkle.root_from_hashes(self.leaf_hashes(size))

    def timestamp(self, size):
        return _BASE_TS + size * 1000

    def sth_payload(self, size=None):
        size = self.size() if size is None else size
        root = self.root_hash(size)
        signature = sign_tree_head(
            self.key, self.log_id, size, self.timestamp(size), root)
        return {
            "tree_size": size,
            "timestamp": self.timestamp(size),
            "sha256_root_hash": root.hex(),
            "tree_head_signature": signature,
        }

    def entries_payload(self, start, end, view_size=None):
        size = self.size() if view_size is None else view_size
        end = min(end, size - 1)
        entries = []
        for idx in range(start, end + 1):
            entries.append({
                "index": idx,
                "leaf_input": base64.b64encode(self._leaves[idx]).decode("ascii"),
            })
        return {"entries": entries}

    def consistency_payload(self, first, second):
        hashes = merkle.consistency_path(
            first, second, self.leaf_hashes(second))
        return {"hashes": [h.hex() for h in hashes]}

    def inclusion_payload(self, index, size=None):
        size = self.size() if size is None else size
        hashes = merkle.inclusion_path(self.leaf_hashes(size), index)
        return {
            "leaf_hash": merkle.leaf_hash(self._leaves[index]).hex(),
            "hashes": [h.hex() for h in hashes],
        }

    def digest_chain(self):
        """便于测试断言的根哈希链。"""
        return {size: self.root_hash(size).hex() for size in
                range(0, self.size() + 1)}


def http_200(payload: dict):
    return {"status": 200, "body": json.dumps(payload, sort_keys=True)}


def http_error(status: int, message: str = "error"):
    return {"status": status, "body": json.dumps({"error": message})}
