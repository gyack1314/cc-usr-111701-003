"""检查点驱动的 CT 增量采集器。

每轮 run_once 的闸门顺序：

1. 向每个镜像取 get-sth，核对日志身份与树头 HMAC 签名；取不到=待补，
   签名/结构失败=不可采信；
2. 交叉比对各镜像已签名树头：同树大小不同根=冲突，小于已确认水位=
   回退冲突，落后镜像必须给出到领头树头的追加一致性证明（取不到=待补，
   证明缺失/核验失败=不可采信）；
3. 领头树头相对上一确认树头做一致性证明（首启 bootstrap 除外，空树到
   首树按 RFC 6962 无需证明，改由全部叶子包含证明建立根）；
4. 增量拉取条目，逐条核对叶子原文哈希与包含证明；某段暂时取不到=待补，
   证明缺失/哈希不符=不可采信，同索引不同叶子=伪造重复索引冲突；
5. 全部通过后在单个事务里写入整段叶子、追加 confirmed_heads 并前移
   可发布水位（commit_segment）。任何一步失败整体回滚，不写确认树头、
   不动水位，重启后从旧检查点重放。
"""
import base64

from . import checkpoint as cp
from . import merkle
from . import transport as tx
from .verifier import (
    VerificationError,
    decode_hash,
    decode_leaf,
    log_identity,
    parse_leaf,
    response_digest,
    verify_signed_tree_head,
)

# quarantine/backlog 的条目类型前缀，保证同一项跨重启稳定定位。
K_STH = "sth"
K_STH_PENDING = "sth-pending"
K_DIVERGENCE = "divergent-head"
K_ROLLBACK = "rollback"
K_LAGGARD = "laggard"
K_CONSISTENCY = "consistency"
K_ENTRIES = "entries"
K_INCLUSION = "inclusion"
K_LEAF = "leaf"
K_DUPLICATE = "duplicate-index"


class Collector:
    """绑定单一日志身份与持久化检查点的采集器。"""

    def __init__(self, conn, verification_key, mirrors, log_id=None):
        self.conn = conn
        self.key = bytes(verification_key)
        self.log_id = log_id or log_identity(self.key)
        if log_identity(self.key) != self.log_id:
            raise VerificationError("验证密钥与日志身份不匹配")
        if not mirrors:
            raise ValueError("至少配置一个镜像")
        self.mirrors = list(mirrors)
        self.names = {m.name for m in self.mirrors}
        if len(self.names) != len(self.mirrors):
            raise ValueError("镜像名称必须唯一")
        self._seen_issues = set()

    # -- 工具 ----------------------------------------------------------------

    def _quorum(self):
        """多数派门槛：单镜像部署为 1，否则严格过半。"""
        return len(self.mirrors) // 2 + 1

    def _mirror_by_name(self, name):
        for mirror in self.mirrors:
            if mirror.name == name:
                return mirror
        raise KeyError(f"未知镜像 {name}")

    def _pending(self, kind, key, detail):
        issue = (cp.PENDING, kind, key)
        if issue in self._seen_issues:
            return {"kind": kind, "item_key": key, "detail": detail,
                    "classification": cp.PENDING, "deduped": True}
        self._seen_issues.add(issue)
        cp.upsert_backlog(self.conn, self.log_id, kind, key, detail)
        return {"kind": kind, "item_key": key, "detail": detail,
                "classification": cp.PENDING}

    def _quarantine(self, kind, key, classification, detail):
        issue = (classification, kind, key)
        if issue in self._seen_issues:
            return {"kind": kind, "item_key": key, "detail": detail,
                    "classification": classification, "deduped": True}
        self._seen_issues.add(issue)
        cp.upsert_quarantine(self.conn, self.log_id, kind, key,
                             classification, detail)
        return {"kind": kind, "item_key": key, "detail": detail,
                "classification": classification}

    def _conflict(self, kind, key, detail):
        return self._quarantine(kind, key, cp.CONFLICT, detail)

    def _inadmissible(self, kind, key, detail):
        return self._quarantine(kind, key, cp.INADMISSIBLE, detail)

    # -- 主流程 --------------------------------------------------------------

    def run_once(self):
        report = {"log_id": self.log_id,
                  "watermark_before": cp.current_watermark(self.conn, self.log_id),
                  "watermark_after": None, "advanced": False,
                  "confirmed_head": None, "verified_leaves": [],
                  "mirrors": {}, "pending": [], "conflicts": [],
                  "inadmissible": []}
        valid_sths = self._collect_sths(report)
        if not valid_sths:
            report["watermark_after"] = report["watermark_before"]
            return report
        # 单一有效镜像不足以确认树头（无交叉见证）：登记待补，等其他
        # 镜像恢复。已确认水位的存在性不受影响，检索仍基于旧检查点。
        if len(valid_sths) < self._quorum():
            report["pending"].append(self._pending(
                K_STH_PENDING, "quorum",
                {"reason": "有效签名树头未达多数派",
                 "valid_mirrors": sorted(s["mirror"] for s in valid_sths),
                 "quorum": self._quorum(),
                 "total_mirrors": len(self.mirrors)}))
            report["watermark_after"] = report["watermark_before"]
            return report
        cp.resolve_backlog(self.conn, self.log_id, K_STH_PENDING, "quorum")
        if self._cross_check_heads(valid_sths, report):
            report["watermark_after"] = report["watermark_before"]
            return report

        chosen = max(valid_sths, key=lambda s: s["tree_size"])
        chosen_size = chosen["tree_size"]
        wm = cp.current_watermark(self.conn, self.log_id)

        # 幂等：领头树头就是当前已确认水位时不产生新版本。
        if wm is not None and chosen_size == wm["tree_size"]:
            if chosen["root_hash_hex"] != wm["root_hash"]:
                report["conflicts"].append(self._conflict(
                    K_DIVERGENCE, f"head-{chosen_size}",
                    {"reason": "同水位树大小的签名树根与已确认根不一致",
                     "tree_size": chosen_size}))
            report["watermark_after"] = wm
            return report

        previous = self._previous_head(chosen_size)

        # 回退防护：领头树头不得小于已确认水位。
        if previous is not None and chosen_size < previous["tree_size"]:
            report["conflicts"].append(self._conflict(
                K_ROLLBACK, f"head-{chosen_size}",
                {"reason": "领头树头小于已确认水位",
                 "chosen_size": chosen_size,
                 "confirmed_size": previous["tree_size"]}))
            report["watermark_after"] = report["watermark_before"]
            return report

        if not self._check_continuity(chosen, previous, valid_sths, report):
            report["watermark_after"] = report["watermark_before"]
            return report
        staged = self._verify_segment(chosen, previous, report)
        if staged is None:
            report["watermark_after"] = report["watermark_before"]
            return report

        inserted = self._advance(chosen, staged, report)
        report["verified_leaves"] = inserted
        report["watermark_after"] = cp.current_watermark(self.conn, self.log_id)
        return report

    def _previous_head(self, chosen_size):
        """取不超过候选树大小的最大已确认树头。"""
        heads = cp.list_confirmed_heads(self.conn, self.log_id)
        prior = [h for h in heads if h["tree_size"] <= chosen_size]
        return prior[-1] if prior else None

    # -- 第 1 步：树头签名身份 ------------------------------------------------

    def _collect_sths(self, report):
        valid = []
        for mirror in self.mirrors:
            name = mirror.name
            try:
                sth, raw_payload = mirror.get_sth()
            except tx.FetchError as exc:
                report["pending"].append(self._pending(
                    K_STH_PENDING, name, {"mirror": name, "reason": str(exc)}))
                report["mirrors"][name] = {"status": cp.PENDING}
                continue
            except tx.ProtocolError as exc:
                report["inadmissible"].append(self._inadmissible(
                    K_STH, name, {"mirror": name, "reason": str(exc)}))
                report["mirrors"][name] = {"status": cp.INADMISSIBLE}
                continue
            try:
                root = decode_hash(sth["sha256_root_hash"], "树根哈希")
                verify_signed_tree_head(
                    self.key, self.log_id, sth["tree_size"], sth["timestamp"],
                    root, sth["tree_head_signature"])
            except VerificationError as exc:
                report["inadmissible"].append(self._inadmissible(
                    K_STH, name, {"mirror": name, "reason": str(exc),
                                  "raw": sth}))
                report["mirrors"][name] = {"status": cp.INADMISSIBLE}
                continue
            cp.resolve_backlog(self.conn, self.log_id, K_STH_PENDING, name)
            entry = {"mirror": name, "tree_size": sth["tree_size"],
                     "timestamp": sth["timestamp"], "root_hash": root,
                     "root_hash_hex": root.hex(),
                     "signature": sth["tree_head_signature"],
                     "response_digest": response_digest(raw_payload)}
            valid.append(entry)
            report["mirrors"][name] = {
                "status": "signed", "tree_size": sth["tree_size"],
                "root_hash": root.hex()}
        return valid

    # -- 第 2 步：镜像间树头交叉核对 ------------------------------------------

    def _cross_check_heads(self, valid_sths, report):
        """返回 True 表示存在阻断性问题，本轮不能推进。"""
        blocked = False
        wm = cp.current_watermark(self.conn, self.log_id)

        # 同树大小必须同根：两个签名树头互相矛盾即冲突。
        by_size = {}
        for sth in valid_sths:
            by_size.setdefault(sth["tree_size"], set()).add(sth["root_hash_hex"])
        for size, roots in sorted(by_size.items()):
            key = f"{K_DIVERGENCE}:{size}"
            if len(roots) > 1:
                blocked = True
                report["conflicts"].append(self._conflict(
                    K_DIVERGENCE, key,
                    {"reason": "同树大小的签名树根不一致", "tree_size": size,
                     "root_hashes": sorted(roots)}))
            else:
                cp.resolve_backlog(self.conn, self.log_id, K_DIVERGENCE, key)

        chosen_size = max(by_size)
        chosen_roots = by_size[chosen_size]
        chosen_root = next(iter(chosen_roots))

        # 回退：任何已签名树头小于已确认水位。
        if wm is not None:
            for sth in valid_sths:
                if sth["tree_size"] < wm["tree_size"]:
                    blocked = True
                    report["conflicts"].append(self._conflict(
                        K_ROLLBACK, sth["mirror"],
                        {"reason": "镜像树头回退到已确认水位之下",
                         "mirror": sth["mirror"],
                         "mirror_size": sth["tree_size"],
                         "watermark": wm["tree_size"]}))

        # 落后镜像：必须证明它的树是领头树的前缀。
        for sth in valid_sths:
            if sth["tree_size"] >= chosen_size:
                continue
            key = f"{sth['mirror']}:{sth['tree_size']}->{chosen_size}"
            mirror = self._mirror_by_name(sth["mirror"])
            try:
                hashes_hex, raw_payload = mirror.get_sth_consistency(
                    sth["tree_size"], chosen_size)
                hashes = [decode_hash(h, "一致性证明哈希") for h in hashes_hex]
            except tx.FetchError as exc:
                blocked = True
                report["pending"].append(self._pending(
                    K_LAGGARD, key,
                    {"mirror": sth["mirror"], "reason": str(exc),
                     "first": sth["tree_size"], "second": chosen_size}))
                continue
            except (tx.ProtocolError, VerificationError) as exc:
                blocked = True
                report["inadmissible"].append(self._inadmissible(
                    K_LAGGARD, key,
                    {"mirror": sth["mirror"], "reason": str(exc),
                     "first": sth["tree_size"], "second": chosen_size}))
                continue
            if not merkle.verify_consistency(
                    sth["tree_size"], chosen_size, sth["root_hash"],
                    bytes.fromhex(chosen_root), hashes):
                blocked = True
                report["inadmissible"].append(self._inadmissible(
                    K_LAGGARD, key,
                    {"reason": "落后镜像追加一致性证明核验失败",
                     "mirror": sth["mirror"],
                     "proof_response_digest": response_digest(raw_payload)}))
                continue
            cp.resolve_backlog(self.conn, self.log_id, K_LAGGARD, key)
        return blocked

    # -- 第 3 步：与上一确认树头的连续性 --------------------------------------

    def _check_continuity(self, chosen, previous, valid_sths, report):
        # bootstrap 或从已确认空树扩容：RFC 6962 规定 first=0 无需一致性
        # 证明，新根完全由全量条目包含证明建立。
        if previous is None or previous["tree_size"] == 0:
            chosen["consistency_from_size"] = (
                None if previous is None else 0)
            chosen["proof_digest"] = None
            return True
        if chosen["tree_size"] == previous["tree_size"]:
            # 同大小重确认：根一致已由交叉核对保证。
            chosen["consistency_from_size"] = None
            chosen["proof_digest"] = None
            return True
        key = f"{previous['tree_size']}->{chosen['tree_size']}"
        mirror = self._mirror_by_name(chosen["mirror"])
        try:
            hashes_hex, raw_payload = mirror.get_sth_consistency(
                previous["tree_size"], chosen["tree_size"])
            hashes = [decode_hash(h, "一致性证明哈希") for h in hashes_hex]
        except tx.FetchError as exc:
            report["pending"].append(self._pending(
                K_CONSISTENCY, key,
                {"mirror": chosen["mirror"], "reason": str(exc),
                 "first": previous["tree_size"], "second": chosen["tree_size"]}))
            return False
        except (tx.ProtocolError, VerificationError) as exc:
            report["inadmissible"].append(self._inadmissible(
                K_CONSISTENCY, key,
                {"mirror": chosen["mirror"], "reason": str(exc)}))
            return False
        if not merkle.verify_consistency(
                previous["tree_size"], chosen["tree_size"],
                bytes.fromhex(previous["root_hash"]), chosen["root_hash"],
                hashes):
            report["inadmissible"].append(self._inadmissible(
                K_CONSISTENCY, key,
                {"reason": "相对已确认树头的追加一致性证明核验失败",
                 "mirror": chosen["mirror"],
                 "proof_response_digest": response_digest(raw_payload)}))
            return False
        chosen["consistency_from_size"] = previous["tree_size"]
        chosen["proof_digest"] = response_digest(raw_payload)
        cp.resolve_backlog(self.conn, self.log_id, K_CONSISTENCY, key)
        return True

    # -- 第 4 步：增量条目与包含证明 ------------------------------------------

    def _verify_segment(self, chosen, previous, report):
        """核验增量段，成功返回暂存叶子列表，任何失败返回 None。

        暂存叶子不入库：它们与树头确认在 _advance 的同一事务里提交，
        杜绝"叶子可见但树版本未确认"的中间态。
        """
        start = 0 if previous is None else previous["tree_size"]
        end = chosen["tree_size"] - 1
        if start > end:
            return []
        mirror = self._mirror_by_name(chosen["mirror"])
        segment_key = f"{start}-{end}"
        try:
            entries, entries_payload = mirror.get_entries(start, end)
        except tx.FetchError as exc:
            report["pending"].append(self._pending(
                K_ENTRIES, segment_key,
                {"mirror": chosen["mirror"], "reason": str(exc),
                 "start": start, "end": end}))
            return None
        except tx.ProtocolError as exc:
            report["inadmissible"].append(self._inadmissible(
                K_ENTRIES, segment_key,
                {"mirror": chosen["mirror"], "reason": str(exc)}))
            return None

        expected_indices = list(range(start, end + 1))
        actual_indices = [e["index"] for e in entries]
        if actual_indices != expected_indices[:len(actual_indices)]:
            report["inadmissible"].append(self._inadmissible(
                K_ENTRIES, segment_key,
                {"reason": "返回条目索引不连续或起点不符",
                 "expected_head": expected_indices[:len(actual_indices)],
                 "actual": actual_indices}))
            return None
        if len(entries) != len(expected_indices):
            # 镜像暂时给不全整段：待补，下轮从缺口重取。
            missing = expected_indices[len(entries):]
            report["pending"].append(self._pending(
                K_ENTRIES, segment_key,
                {"mirror": chosen["mirror"],
                 "reason": "镜像只返回了部分条目",
                 "returned": len(entries), "expected": len(expected_indices),
                 "missing_from": missing[0]}))
            return None

        staged = []
        for entry in entries:
            idx = entry["index"]
            try:
                leaf_bytes = decode_leaf(entry["leaf_input"])
                leaf_hash_value = merkle.leaf_hash(leaf_bytes)
                hashes_hex, leaf_hash_hex, proof_payload = \
                    mirror.get_proof_by_leaf(idx, chosen["tree_size"])
                proof = [decode_hash(h, "包含证明哈希") for h in hashes_hex]
                stated_hash = decode_hash(leaf_hash_hex, "叶子哈希")
            except tx.FetchError as exc:
                report["pending"].append(self._pending(
                    K_INCLUSION, str(idx),
                    {"mirror": chosen["mirror"], "reason": str(exc),
                     "leaf_index": idx}))
                return None
            except (tx.ProtocolError, VerificationError) as exc:
                report["inadmissible"].append(self._inadmissible(
                    K_INCLUSION, str(idx),
                    {"mirror": chosen["mirror"], "reason": str(exc),
                     "leaf_index": idx}))
                return None

            if stated_hash != leaf_hash_value:
                report["inadmissible"].append(self._inadmissible(
                    K_LEAF, str(idx),
                    {"reason": "叶子原文哈希与证明声明的 leaf_hash 不符",
                     "mirror": chosen["mirror"], "leaf_index": idx}))
                return None
            if not merkle.verify_inclusion(
                    idx, chosen["tree_size"], leaf_hash_value,
                    chosen["root_hash"], proof):
                report["inadmissible"].append(self._inadmissible(
                    K_INCLUSION, str(idx),
                    {"reason": "条目包含证明核验失败",
                     "mirror": chosen["mirror"], "leaf_index": idx,
                     "proof_response_digest": response_digest(proof_payload)}))
                return None

            parsed = parse_leaf(leaf_bytes)
            staged.append({
                "leaf_index": idx,
                "leaf_hash": leaf_hash_value.hex(),
                "raw_b64": base64.b64encode(leaf_bytes).decode("ascii"),
                "certificate": parsed.get("certificate"),
                "subject": parsed.get("subject"),
                "san": parsed.get("san"),
                "included_tree_size": chosen["tree_size"],
                "root_hash": chosen["root_hash_hex"],
                "inclusion_proof_digest": response_digest(proof_payload),
                "source_mirror": chosen["mirror"],
                "response_digest": response_digest(entries_payload),
            })

        # 全部条目通过后只暂存；叶子与树头在 _advance 的同一事务提交，
        # 伪造重复索引会在该事务内触发回滚并归类为冲突。
        cp.resolve_backlog(self.conn, self.log_id, K_ENTRIES, segment_key)
        for leaf in staged:
            cp.resolve_backlog(self.conn, self.log_id, K_INCLUSION,
                               str(leaf["leaf_index"]))
            cp.resolve_backlog(self.conn, self.log_id, K_LEAF,
                               str(leaf["leaf_index"]))
        return staged

    # -- 第 5 步：原子推进 ----------------------------------------------------

    def _advance(self, chosen, staged, report):
        head = {
            "tree_size": chosen["tree_size"],
            "root_hash": chosen["root_hash_hex"],
            "timestamp": chosen["timestamp"],
            "signature": chosen["signature"],
            "consistency_from_size": chosen.get("consistency_from_size"),
            "proof_digest": chosen.get("proof_digest"),
            "source_mirror": chosen["mirror"],
            "response_digest": chosen["response_digest"],
        }
        watermark = {"tree_size": chosen["tree_size"],
                     "root_hash": chosen["root_hash_hex"]}
        try:
            inserted = cp.commit_segment(
                self.conn, self.log_id, staged, head, watermark)
        except ValueError as exc:
            report["conflicts"].append(self._conflict(
                K_DUPLICATE, f"segment-{head['tree_size']}",
                {"reason": str(exc), "mirror": chosen["mirror"]}))
            return []
        report["advanced"] = True
        report["confirmed_head"] = head
        return inserted
