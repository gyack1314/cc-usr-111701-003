"""日志身份与树头签名核验、叶子原文解析。

本项目的样例日志是合成的，没有 RFC 6962 第 2.1.4 节规定的 X.509 日志
证书；为保持"核对签名身份"这一密码学语义，合成日志对规范化树头字节
做 HMAC-SHA256。log_id 从验证密钥派生（SHA256(b'ct-log-id'||key)），
核验侧只持有验证密钥，因此不同身份的日志无法互签树头。接入真实日志
时只需把 verify_signed_tree_head 替换为 ECDSA/RSA 签名核验，采集主
流程不变。

线上 JSON 均使用 hex 表示哈希/签名、base64 表示叶子原文，与本项目
既有的冻结资产编码风格一致。
"""
import base64
import hashlib
import hmac
import json

_STH_DOMAIN = b"ct-log-sth-v1\x00"
_ID_DOMAIN = b"ct-log-id"


class VerificationError(ValueError):
    """结构或密码学核验失败（调用方归入不可采信）。"""


def log_identity(verification_key: bytes) -> str:
    """由验证密钥派生稳定的日志身份标识（hex）。"""
    if not isinstance(verification_key, (bytes, bytearray)) or not verification_key:
        raise VerificationError("验证密钥非法")
    return hashlib.sha256(_ID_DOMAIN + bytes(verification_key)).hexdigest()


def canonical_sth(log_id: str, tree_size: int, timestamp: int, root_hash: bytes) -> bytes:
    """树头签名的规范化字节：长度前缀字段，杜绝跨字段歧义。"""
    if not isinstance(log_id, str) or not log_id:
        raise VerificationError("日志身份非法")
    if type(tree_size) is not int or tree_size < 0:
        raise VerificationError("树大小非法")
    if type(timestamp) is not int or timestamp < 0:
        raise VerificationError("时间戳非法")
    if not isinstance(root_hash, (bytes, bytearray)) or len(root_hash) != 32:
        raise VerificationError("树根哈希非法")
    log_bytes = log_id.encode("ascii")
    return (
        _STH_DOMAIN
        + len(log_bytes).to_bytes(2, "big") + log_bytes
        + tree_size.to_bytes(8, "big")
        + timestamp.to_bytes(8, "big")
        + bytes(root_hash)
    )


def sign_tree_head(verification_key: bytes, log_id: str, tree_size: int,
                   timestamp: int, root_hash: bytes) -> str:
    """对规范化树头计算 HMAC-SHA256，hex 输出（仅合成日志侧使用）。"""
    message = canonical_sth(log_id, tree_size, timestamp, root_hash)
    return hmac.new(bytes(verification_key), message, hashlib.sha256).hexdigest()


def verify_signed_tree_head(verification_key: bytes, expected_log_id: str,
                            tree_size: int, timestamp: int,
                            root_hash: bytes, signature_hex: str) -> dict:
    """核对树头签名身份。

    成功返回带 signature_verified=True 的核验记录；任何不符都抛出
    VerificationError，调用方必须把对应树头归入不可采信。
    """
    actual_id = log_identity(verification_key)
    if not hmac.compare_digest(actual_id, expected_log_id or ""):
        raise VerificationError("树头日志身份与配置不符")
    if not isinstance(signature_hex, str):
        raise VerificationError("签名编码非法")
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        raise VerificationError("签名不是合法 hex")
    message = canonical_sth(expected_log_id, tree_size, timestamp, root_hash)
    expected = hmac.new(bytes(verification_key), message, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise VerificationError("树头签名核验失败")
    return {
        "signature_verified": True,
        "log_id": expected_log_id,
        "tree_size": tree_size,
        "timestamp": timestamp,
        "root_hash": root_hash.hex(),
    }


def decode_hash(value, label="哈希") -> bytes:
    """解码线上 hex 哈希字段。"""
    if not isinstance(value, str):
        raise VerificationError(f"{label}不是字符串")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise VerificationError(f"{label}不是合法 hex")
    if len(raw) != 32:
        raise VerificationError(f"{label}长度必须为 32 字节")
    return raw


def decode_leaf(value) -> bytes:
    """解码 base64 叶子原文。"""
    if not isinstance(value, str):
        raise VerificationError("叶子原文编码非法")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise VerificationError("叶子原文不是合法 base64")
    if not raw:
        raise VerificationError("叶子原文为空")
    return raw


def parse_leaf(leaf_bytes: bytes) -> dict:
    """解析叶子原文中的证书字段。

    合成叶子是 JSON 文档（真实 CT 叶子应按 RFC 6962 的 MerkleTreeLeaf
    TLS 结构解析）。解析失败不伪造证书：返回 raw_base64，certificate
    留空，检索侧仍可追溯叶子原文，但不会得到证书条目。
    """
    result = {"raw_length": len(leaf_bytes), "certificate": None,
              "subject": None, "san": None}
    try:
        doc = json.loads(leaf_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        result["raw_base64"] = base64.b64encode(leaf_bytes).decode("ascii")
        return result
    if not isinstance(doc, dict):
        result["raw_base64"] = base64.b64encode(leaf_bytes).decode("ascii")
        return result
    result["certificate"] = doc.get("certificate")
    result["subject"] = doc.get("subject")
    san = doc.get("san")
    result["san"] = sorted(san) if isinstance(san, list) else san
    return result


def response_digest(payload: dict) -> str:
    """对线上响应 JSON 计算稳定摘要，用于候选来源追溯。"""
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
