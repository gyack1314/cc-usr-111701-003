"""检查点驱动增量采集的端到端行为测试。

用合成日志 + 脚本化镜像驱动 Collector，覆盖：正常增量、重启不丢树根、
镜像分歧三态、证明缺失、暂时缺段、伪造叶子、伪造重复索引、回退、
发布闸门与追溯信息。
"""
import tempfile
import unittest
from pathlib import Path

from capture_data import checkpoint as cp
from capture_data.collector import Collector
from capture_data.io import Replay
from capture_data.retrieval import checkpoint_view, raw_leaf_trace, traceable_certificates
from capture_data.transport import Mirror
from tests.support.mirror import ScriptedMirror
from tests.support.synthetic import SyntheticLog, make_leaf_bytes

KEY = b"synthetic-log-key-001"
MIRROR_A = "mirror-a"
MIRROR_B = "mirror-b"


def build_log(n):
    log = SyntheticLog(KEY)
    for i in range(n):
        log.append(make_leaf_bytes(i))
    return log


def collector(conn, log, behaviors=None, names=(MIRROR_A, MIRROR_B)):
    behaviors = behaviors or {}
    mirrors = [Mirror(name, ScriptedMirror(name, log, behaviors.get(name, {})))
               for name in names]
    return Collector(conn, KEY, mirrors)


def first(classification, report):
    return report[classification][0]


class HappyPathTest(unittest.TestCase):
    def test_bootstrap_and_incremental_advance(self):
        log = build_log(4)
        conn = cp.connect(":memory:")
        run = collector(conn, log).run_once()
        self.assertTrue(run["advanced"])
        self.assertEqual(run["watermark_after"]["tree_size"], 4)
        self.assertEqual(sorted(run["verified_leaves"]), [0, 1, 2, 3])
        view = checkpoint_view(conn, log.log_id)
        self.assertEqual(view["watermark"]["tree_size"], 4)
        self.assertEqual(len(view["confirmed_heads"]), 1)
        self.assertEqual(view["confirmed_heads"][0]["root_hash"],
                         log.root_hash().hex())
        # 正式结果带完整树版本追溯。
        result = traceable_certificates(conn, log.log_id)
        self.assertEqual(result["count"], 4)
        prov = result["certificates"][0]["provenance"]
        self.assertEqual(prov["tree_size"], 4)
        self.assertEqual(prov["tree_root_hash"], log.root_hash().hex())
        self.assertEqual(prov["source_mirror"], MIRROR_A)
        self.assertTrue(prov["inclusion_proof_digest"])
        trace = raw_leaf_trace(conn, log.log_id, 2)
        self.assertEqual(trace["verified_against"]["tree_size"], 4)
        conn.close()

    def test_incremental_second_head_uses_consistency_proof(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        log.append(make_leaf_bytes(3))
        log.append(make_leaf_bytes(4))
        run = collector(conn, log).run_once()
        self.assertTrue(run["advanced"])
        head = run["confirmed_head"]
        self.assertEqual(head["tree_size"], 5)
        self.assertEqual(head["consistency_from_size"], 3)
        self.assertTrue(head["proof_digest"])
        view = checkpoint_view(conn, log.log_id)
        self.assertEqual([h["tree_size"] for h in view["confirmed_heads"]],
                         [3, 5])
        self.assertEqual(view["watermark"]["tree_size"], 5)
        # 新叶子只在新树版本下核验，旧叶子不重复写入。
        self.assertEqual(run["verified_leaves"], [3, 4])
        conn.close()

    def test_restart_keeps_confirmed_tree_roots(self):
        log = build_log(3)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "checkpoint.sqlite3"
            conn = cp.connect(db_path)
            collector(conn, log).run_once()
            conn.close()
            # 模拟进程重启：重新打开库，确认树根与水位原样恢复。
            restarted = cp.connect(db_path)
            view = checkpoint_view(restarted, log.log_id)
            self.assertEqual(view["watermark"]["tree_size"], 3)
            self.assertEqual(view["confirmed_heads"][0]["root_hash"],
                             log.root_hash(3).hex())
            # 新采集器从旧检查点继续，不重写历史。
            log.append(make_leaf_bytes(3))
            report = collector(restarted, log).run_once()
            self.assertTrue(report["advanced"])
            self.assertEqual(report["watermark_before"]["tree_size"], 3)
            self.assertEqual(
                [h["tree_size"] for h in
                 checkpoint_view(restarted, log.log_id)["confirmed_heads"]],
                [3, 4])
            restarted.close()

    def test_replay_same_head_is_idempotent(self):
        log = build_log(2)
        conn = cp.connect(":memory:")
        first_run = collector(conn, log).run_once()
        second_run = collector(conn, log).run_once()
        self.assertFalse(second_run["advanced"])
        self.assertEqual(second_run["watermark_after"],
                         first_run["watermark_after"])
        self.assertEqual(len(checkpoint_view(conn, log.log_id)["confirmed_heads"]),
                         1)
        result = traceable_certificates(conn, log.log_id)
        self.assertEqual(result["count"], 2)
        conn.close()


class PendingTest(unittest.TestCase):
    def test_transient_sth_failure_is_pending_and_retries(self):
        log = build_log(2)
        conn = cp.connect(":memory:")
        # 自动重试 1 次仍失败（共 2 次 503）才登记待补。
        behaviors = {MIRROR_B: {"ct/v1/get-sth": {"fail_times": 2}}}
        run = collector(conn, log, behaviors).run_once()
        # 多数派未达成：A 虽有有效签名树头，本轮也不能推进。
        self.assertFalse(run["advanced"])
        pending_kinds = {p["kind"] for p in run["pending"]}
        self.assertIn("sth-pending", pending_kinds)
        self.assertTrue(any(p["detail"].get("reason", "").startswith(
            "有效签名树头未达多数派") for p in run["pending"]))
        backlog = cp.list_backlog(conn, log.log_id)
        self.assertTrue(any(b["kind"] == "sth-pending" for b in backlog))
        # 下一轮 B 恢复，多数派达成后推进，待补项自动消除。
        again = collector(conn, log).run_once()
        self.assertTrue(again["advanced"])
        self.assertFalse(again["pending"])
        self.assertFalse(cp.list_backlog(conn, log.log_id))
        conn.close()

    def test_entry_segment_temporarily_unavailable_blocks_advance(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        behaviors = {
            MIRROR_A: {"ct/v1/get-entries": {"fail_times": 2}},
            MIRROR_B: {"ct/v1/get-entries": {"fail_times": 2}},
        }
        run = collector(conn, log, behaviors).run_once()
        self.assertFalse(run["advanced"])
        self.assertIsNone(cp.current_watermark(conn, log.log_id))
        item = first("pending", run)
        self.assertEqual(item["kind"], "entries")
        self.assertEqual(item["detail"]["start"], 0)
        # 候选叶子不得进入正式结果。
        self.assertEqual(
            traceable_certificates(conn, log.log_id)["count"], 0)
        # 恢复后同检查点重放成功。
        retry = collector(conn, log).run_once()
        self.assertTrue(retry["advanced"])
        self.assertFalse(cp.list_backlog(conn, log.log_id))
        conn.close()

    def test_partial_segment_is_pending_not_partial_publish(self):
        log = build_log(4)
        conn = cp.connect(":memory:")
        behaviors = {
            MIRROR_A: {"ct/v1/get-entries": {"partial": 2}},
            MIRROR_B: {"ct/v1/get-entries": {"partial": 2}},
        }
        run = collector(conn, log, behaviors).run_once()
        self.assertFalse(run["advanced"])
        item = first("pending", run)
        self.assertEqual(item["kind"], "entries")
        self.assertEqual(item["detail"]["missing_from"], 2)
        self.assertIsNone(cp.current_watermark(conn, log.log_id))
        conn.close()

    def test_lagging_mirror_temporarily_missing_proof_is_pending(self):
        log = build_log(5)
        conn = cp.connect(":memory:")
        # B 停在大小 3，且一致性端点前两次请求均 503（耗尽自动重试）。
        behaviors = {MIRROR_B: {
            "ct/v1/get-sth": {"view_size": 3},
            "ct/v1/get-sth-consistency": {"fail_times": 2},
        }}
        run = collector(conn, log, behaviors).run_once()
        self.assertFalse(run["advanced"])
        item = first("pending", run)
        self.assertEqual(item["kind"], "laggard")
        self.assertEqual(item["detail"]["first"], 3)
        self.assertEqual(item["detail"]["second"], 5)
        # 第二轮证明可用，落后镜像被接受，采集继续。
        retry = collector(conn, log, {
            MIRROR_B: {"ct/v1/get-sth": {"view_size": 3}}}).run_once()
        self.assertTrue(retry["advanced"])
        self.assertFalse(cp.list_backlog(conn, log.log_id))
        conn.close()


class InadmissibleTest(unittest.TestCase):
    def test_bad_signature_is_inadmissible(self):
        log = build_log(2)
        conn = cp.connect(":memory:")
        sth = log.sth_payload()
        sth["tree_head_signature"] = "00" * 32
        run = collector(conn, log, {
            MIRROR_A: {"ct/v1/get-sth": {"sth_override": sth}},
            MIRROR_B: {"ct/v1/get-sth": {"sth_override": sth}},
        }).run_once()
        self.assertFalse(run["advanced"])
        self.assertEqual(len(run["inadmissible"]), 2)
        self.assertEqual(first("inadmissible", run)["kind"], "sth")
        self.assertEqual(
            first("inadmissible", run)["detail"]["reason"], "树头签名核验失败")
        quarantined = cp.list_quarantine(conn, log.log_id)
        self.assertTrue(all(q["classification"] == cp.INADMISSIBLE
                            for q in quarantined))
        conn.close()

    def test_foreign_log_identity_rejected(self):
        log = build_log(2)
        foreign = SyntheticLog(b"another-verification-key")
        run = collector(cp.connect(":memory:"), log, {
            MIRROR_A: {"ct/v1/get-sth": {"sth_override": foreign.sth_payload()}},
            MIRROR_B: {"ct/v1/get-sth": {"sth_override": foreign.sth_payload()}},
        }).run_once()
        self.assertFalse(run["advanced"])
        self.assertTrue(all(i["detail"]["reason"] in
                            ("树头日志身份与配置不符", "树头签名核验失败")
                            for i in run["inadmissible"]))

    def test_missing_consistency_proof_is_inadmissible(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        log.append(make_leaf_bytes(3))
        run = collector(conn, log, {
            MIRROR_A: {"ct/v1/get-sth-consistency": {"omit": True}},
            MIRROR_B: {"ct/v1/get-sth-consistency": {"omit": True}},
        }).run_once()
        self.assertFalse(run["advanced"])
        item = first("inadmissible", run)
        self.assertEqual(item["kind"], "consistency")
        # 旧树根与水位保持不变。
        self.assertEqual(cp.current_watermark(conn, log.log_id)["tree_size"], 3)
        conn.close()

    def test_tampered_consistency_proof_is_inadmissible(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        log.append(make_leaf_bytes(3))
        run = collector(conn, log, {
            MIRROR_A: {"ct/v1/get-sth-consistency": {"tamper": True}},
            MIRROR_B: {"ct/v1/get-sth-consistency": {"tamper": True}},
        }).run_once()
        self.assertFalse(run["advanced"])
        self.assertIn("一致性证明核验失败",
                      first("inadmissible", run)["detail"]["reason"])
        conn.close()

    def test_missing_inclusion_proof_is_inadmissible(self):
        log = build_log(3)
        run = collector(cp.connect(":memory:"), log, {
            MIRROR_A: {"ct/v1/get-proof-by-leaf": {"omit": True}},
            MIRROR_B: {"ct/v1/get-proof-by-leaf": {"omit": True}},
        }).run_once()
        self.assertFalse(run["advanced"])
        self.assertEqual(first("inadmissible", run)["kind"], "inclusion")
        self.assertFalse(run["verified_leaves"])

    def test_leaf_hash_mismatch_is_inadmissible(self):
        log = build_log(3)
        run = collector(cp.connect(":memory:"), log, {
            MIRROR_A: {"ct/v1/get-proof-by-leaf": {"bad_leaf_hash": True}},
            MIRROR_B: {"ct/v1/get-proof-by-leaf": {"bad_leaf_hash": True}},
        }).run_once()
        self.assertFalse(run["advanced"])
        self.assertEqual(first("inadmissible", run)["kind"], "leaf")
        self.assertIn("leaf_hash 不符",
                      first("inadmissible", run)["detail"]["reason"])

    def test_tampered_leaf_bytes_is_inadmissible(self):
        log = build_log(3)
        run = collector(cp.connect(":memory:"), log, {
            MIRROR_A: {"ct/v1/get-entries": {"tamper_leaf": True}},
            MIRROR_B: {"ct/v1/get-entries": {"tamper_leaf": True}},
        }).run_once()
        self.assertFalse(run["advanced"])
        # 原文被改后重算哈希与证明声明的 leaf_hash 不符，先在叶子闸拦截。
        self.assertEqual(first("inadmissible", run)["kind"], "leaf")


class ConflictTest(unittest.TestCase):
    def test_same_size_different_roots_is_conflict(self):
        log = build_log(4)
        forked = SyntheticLog(KEY)
        for i in range(3):
            forked.append(make_leaf_bytes(i))
        forked.append(make_leaf_bytes(99, "forked.test"))
        self.assertEqual(forked.size(), log.size())
        self.assertNotEqual(forked.root_hash().hex(), log.root_hash().hex())
        conn = cp.connect(":memory:")
        run = collector(conn, log, {
            MIRROR_B: {"ct/v1/get-sth": {"sth_override": forked.sth_payload()}},
        }).run_once()
        self.assertFalse(run["advanced"])
        item = first("conflicts", run)
        self.assertEqual(item["kind"], "divergent-head")
        self.assertEqual(item["detail"]["tree_size"], 4)
        self.assertEqual(
            cp.list_quarantine(conn, log.log_id)[0]["classification"],
            cp.CONFLICT)
        conn.close()

    def test_lagging_mirror_with_invalid_consistency_is_inadmissible(self):
        log = build_log(5)
        conn = cp.connect(":memory:")
        behaviors = {MIRROR_B: {
            "ct/v1/get-sth": {"view_size": 3},
            "ct/v1/get-sth-consistency": {"tamper": True},
        }}
        run = collector(conn, log, behaviors).run_once()
        self.assertFalse(run["advanced"])
        self.assertEqual(first("inadmissible", run)["kind"], "laggard")
        conn.close()

    def test_rollback_below_watermark_is_conflict(self):
        log = build_log(5)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        # 新一轮两个镜像都声明回退到大小 3（用同一把钥匙签名的旧视图）。
        run = collector(conn, log, {
            MIRROR_A: {"ct/v1/get-sth": {"view_size": 3}},
            MIRROR_B: {"ct/v1/get-sth": {"view_size": 3}},
        }).run_once()
        self.assertFalse(run["advanced"])
        kinds = {c["kind"] for c in run["conflicts"]}
        self.assertIn("rollback", kinds)
        self.assertEqual(cp.current_watermark(conn, log.log_id)["tree_size"], 5)
        conn.close()

    def test_forged_duplicate_index_is_conflict(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        # 直接验证重复索引写入门禁：原叶子不会被覆盖。
        leaf = cp.get_verified_leaf(conn, log.log_id, 0)
        forged = dict(leaf)
        forged["leaf_hash"] = "ff" * 32
        with self.assertRaises(ValueError):
            cp.add_verified_leaf(conn, log.log_id, forged)
        self.assertEqual(cp.get_verified_leaf(conn, log.log_id, 0)["leaf_hash"],
                         leaf["leaf_hash"])
        conn.close()

    def test_segment_commit_is_atomic_on_conflict(self):
        # 已确认大小 3 后，手工在 verified_leaves 预置一条与即将核验段
        # 同索引但不同哈希的叶子，commit_segment 必须整体回滚：水位不动、
        # 同段其他叶子也不可见。
        log = build_log(3)
        conn = cp.connect(":memory:")
        collector(conn, log).run_once()
        log.append(make_leaf_bytes(3))
        log.append(make_leaf_bytes(4))
        # 先正常推进到 5，随后构造一个"库里索引 4 被换哈希"的场景：
        # 直接调用 commit_segment 验证事务回滚语义。
        report = collector(conn, log).run_once()
        self.assertTrue(report["advanced"])
        good = cp.get_verified_leaf(conn, log.log_id, 4)
        forged = dict(good)
        forged["leaf_hash"] = "ee" * 32
        head = {"tree_size": 7, "root_hash": "ab" * 32, "timestamp": 1,
                "signature": "s", "consistency_from_size": 5,
                "proof_digest": "p", "source_mirror": MIRROR_A,
                "response_digest": "r"}
        with self.assertRaises(ValueError):
            cp.commit_segment(
                conn, log.log_id, [forged, {**good, "leaf_index": 5}],
                head, {"tree_size": 7, "root_hash": "ab" * 32})
        # 回滚后：水位仍是 5，索引 5 没有残留，索引 4 哈希未被改。
        self.assertEqual(cp.current_watermark(conn, log.log_id)["tree_size"], 5)
        self.assertIsNone(cp.get_verified_leaf(conn, log.log_id, 5))
        self.assertEqual(cp.get_verified_leaf(conn, log.log_id, 4)["leaf_hash"],
                         good["leaf_hash"])
        conn.close()


class PublicationGateTest(unittest.TestCase):
    def test_single_mirror_deployment_quorum_is_one(self):
        log = build_log(2)
        conn = cp.connect(":memory:")
        run = collector(conn, log, names=(MIRROR_A,)).run_once()
        self.assertTrue(run["advanced"])
        self.assertEqual(run["watermark_after"]["tree_size"], 2)
        conn.close()

    def test_classification_cannot_be_downgraded(self):
        log = build_log(1)
        conn = cp.connect(":memory:")
        cp.upsert_quarantine(conn, log.log_id, "leaf", "0",
                             cp.INADMISSIBLE, {"reason": "x"})
        with self.assertRaises(ValueError):
            cp.upsert_quarantine(conn, log.log_id, "leaf", "0",
                                 cp.PENDING, {"reason": "y"})
        # 同级或升级允许，且原因被刷新。
        cp.upsert_quarantine(conn, log.log_id, "leaf", "0",
                             cp.CONFLICT, {"reason": "z"})
        rows = cp.list_quarantine(conn, log.log_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], cp.CONFLICT)
        conn.close()

    def test_unverified_candidates_never_published(self):
        log = build_log(3)
        conn = cp.connect(":memory:")
        # 包含证明缺失：叶子连 verified_leaves 都不能进入。
        collector(conn, log, {
            MIRROR_A: {"ct/v1/get-proof-by-leaf": {"omit": True}},
            MIRROR_B: {"ct/v1/get-proof-by-leaf": {"omit": True}},
        }).run_once()
        self.assertIsNone(cp.get_verified_leaf(conn, log.log_id, 0))
        result = traceable_certificates(conn, log.log_id)
        self.assertEqual(result["count"], 0)
        self.assertIsNone(result["watermark"])
        self.assertGreaterEqual(result["candidates_excluded"], 1)
        conn.close()

    def test_replay_frozen_records_through_real_replay_class(self):
        # 用 io.Replay 回放 ScriptedMirror 录制的冻结记录，证明传输
        # 适配层与项目既有回放设施兼容。
        log = build_log(3)
        scripted = ScriptedMirror(MIRROR_A, log)
        probe = Mirror(MIRROR_A, scripted)
        probe.get_sth()
        probe.get_entries(0, 2)
        frozen = scripted.export_records()
        replay = Mirror(MIRROR_A, Replay(frozen))
        sth, _ = replay.get_sth()
        self.assertEqual(sth["tree_size"], 3)
        entries, _ = replay.get_entries(0, 2)
        self.assertEqual([e["index"] for e in entries], [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
