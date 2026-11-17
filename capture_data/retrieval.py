"""面向检索使用者的可追溯视图。

正式结果只暴露已确认水位之下、包含证明核验通过的证书，每条都带：

* 被核验时的树版本（tree_size + root_hash + 树头签名）；
* 包含证明响应摘要与来源镜像，可回放到原始冻结响应；
* 叶子哈希与原文 base64，可重新计算 RFC 6962 叶子哈希复核。

未完成证明的候选只存在于 backlog/quarantine，绝不进入本视图。
"""
from . import checkpoint as cp


def checkpoint_view(conn, log_id):
    """返回检查点全貌：已确认树版本链、当前水位、待补与隔离区。"""
    heads = cp.list_confirmed_heads(conn, log_id)
    watermark = cp.current_watermark(conn, log_id)
    return {
        "log_id": log_id,
        "watermark": watermark,
        "confirmed_heads": heads,
        "backlog": cp.list_backlog(conn, log_id),
        "quarantine": cp.list_quarantine(conn, log_id),
        "append_only_heads": len(heads),
    }


def traceable_certificates(conn, log_id):
    """正式证书结果，逐条附树版本追溯信息。"""
    published = cp.published_certificates(conn, log_id)
    heads = {h["tree_size"]: h for h in cp.list_confirmed_heads(conn, log_id)}
    certificates = []
    for row in published["certificates"]:
        # 只发布真正带有证书字段的叶子；无法解析的叶子留作原始条目追溯，
        # 不伪造证书记录。
        if not row.get("certificate"):
            continue
        head = heads.get(row["verified_tree_size"])
        certificates.append({
            "leaf_index": row["leaf_index"],
            "certificate": row["certificate"],
            "subject": row["subject"],
            "san": row["san"],
            "leaf_hash": row["leaf_hash"],
            "provenance": {
                "tree_size": row["verified_tree_size"],
                "tree_root_hash": row["verified_root_hash"],
                "tree_head_signature": head["signature"] if head else None,
                "tree_head_timestamp": head["timestamp"] if head else None,
                "inclusion_proof_digest": row["inclusion_proof_digest"],
                "entries_response_digest": row["response_digest"],
                "source_mirror": row["source_mirror"],
            },
        })
    return {
        "log_id": log_id,
        "watermark": published["watermark"],
        "count": len(certificates),
        "certificates": certificates,
        "candidates_excluded": len(cp.list_backlog(conn, log_id))
        + len(cp.list_quarantine(conn, log_id)),
    }


def raw_leaf_trace(conn, log_id, leaf_index):
    """单条叶子的完整追溯链（含未解析为证书的原始叶子）。"""
    leaf = cp.get_verified_leaf(conn, log_id, leaf_index)
    if leaf is None:
        return None
    heads = {h["tree_size"]: h for h in cp.list_confirmed_heads(conn, log_id)}
    head = heads.get(leaf["included_tree_size"])
    return {
        "leaf_index": leaf["leaf_index"],
        "leaf_hash": leaf["leaf_hash"],
        "raw_b64": leaf["raw_b64"],
        "parsed": {"certificate": leaf["certificate"], "subject": leaf["subject"],
                   "san": leaf["san"]},
        "verified_against": {
            "tree_size": leaf["included_tree_size"],
            "root_hash": leaf["root_hash"],
            "signed_head": head,
        },
        "inclusion_proof_digest": leaf["inclusion_proof_digest"],
        "source_mirror": leaf["source_mirror"],
        "entries_response_digest": leaf["response_digest"],
    }
