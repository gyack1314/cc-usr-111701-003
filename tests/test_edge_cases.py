"""补充对抗性边界：空树头、非 JSON 叶子、跨树包含证明、水位回退写入。"""
import unittest

from capture_data import checkpoint as cp
from capture_data.collector import Collector
from capture_data.retrieval import raw_leaf_trace, traceable_certificates
from capture_data.transport import Mirror
from capture_data.verifier import VerificationError
from tests.support.mirror import ScriptedMirror
from tests.support.synthetic import SyntheticLog, make_leaf_bytes, http_200

KEY = b"edge-case-key"
A, B = "mirror-a", "mirror-b"


def make_collector(conn, log, behaviors):
    mirrors = [Mirror(name, ScriptedMirror(name, log, behaviors.get(name, {})))
               for name in (A, B)]
    return Collector(conn, KEY, mirrors)


class EmptyHeadTest(unittest.TestCase):
    def test_zero_size_signed_head_is_accepted_but_publishes_nothing(self):
        log = SyntheticLog(KEY)  # 空日志
        conn = cp.connect(":memory:")
        run = make_collector(conn, log, {}).run_once()
        self.assertTrue(run["advanced"])
        self.assertEqual(run["watermark_after"]["tree_size"], 0)
        result = traceable_certificates(conn, log.log_id)
        self.assertEqual(result["count"], 0)
        # 空树之后追加叶子：从大小 0 到 N 按 RFC 6962 无需一致性证明，
        # 全量包含证明建立根。
        for i in range(2):
            log.append(make_leaf_bytes(i, "edge.test"))
        run = make_collector(conn, log, {}).run_once()
        self.assertTrue(run["advanced"])
        self.assertEqual(run["confirmed_head"]["consistency_from_size"], 0)
        self.assertEqual(traceable_certificates(conn, log.log_id)["count"], 2)
        conn.close()


class NonJsonLeafTest(unittest.TestCase):
    def test_unparseable_leaf_keeps_raw_but_no_fake_certificate(self):
        log = SyntheticLog(KEY)
        log.append(b"\x00\x01binary-not-json")
        log.append(make_leaf_bytes(1, "edge.test"))
        conn = cp.connect(":memory:")
        run = make_collector(conn, log, {}).run_once()
        self.assertTrue(run["advanced"])
        result = traceable_certificates(conn, log.log_id)
        # 只有第二片叶子产出证书；第一片不伪造。
        self.assertEqual([c["leaf_index"] for c in result["certificates"]], [1])
        trace = raw_leaf_trace(conn, log.log_id, 0)
        self.assertIsNone(trace["parsed"]["certificate"])
        self.assertTrue(trace["raw_b64"])
        self.assertEqual(trace["verified_against"]["tree_size"], 2)
        conn.close()


class CrossTreeInclusionTest(unittest.TestCase):
    def test_inclusion_proof_from_other_tree_rejected(self):
        log = SyntheticLog(KEY)
        for i in range(4):
            log.append(make_leaf_bytes(i))
        other = SyntheticLog(KEY)
        for i in range(3):
            other.append(make_leaf_bytes(i))
        other.append(make_leaf_bytes(99, "other.test"))  # 同大小不同内容
        # 只让包含证明端点返回分叉树的证明；树头与条目仍来自本日志，
        # 因此能越过签名与分叉闸，最终在包含证明闸被拦截。
        foreign = other.inclusion_payload
        scripted = ScriptedMirror(A, log, {})

        def foreign_dispatch(route, query):
            if route == "ct/v1/get-proof-by-leaf":
                return http_200(foreign(int(query["leaf_index"]),
                                        int(query["tree_size"])))
            return ScriptedMirror._dispatch(scripted, route, query)

        scripted._dispatch = foreign_dispatch
        conn = cp.connect(":memory:")
        mirrors = [Mirror(A, scripted),
                   Mirror(B, ScriptedMirror(B, log, {}))]
        run = Collector(conn, KEY, mirrors).run_once()
        self.assertFalse(run["advanced"])
        kinds = {i["kind"] for i in run["inadmissible"]}
        self.assertIn("inclusion", kinds)
        conn.close()


class WatermarkGuardTest(unittest.TestCase):
    def test_watermark_cannot_move_backwards(self):
        log = SyntheticLog(KEY)
        conn = cp.connect(":memory:")
        head = {"tree_size": 5, "root_hash": "ab" * 32, "timestamp": 1,
                "signature": "01", "consistency_from_size": None,
                "proof_digest": None, "source_mirror": A,
                "response_digest": "02"}
        cp.commit_advance(conn, log.log_id, head,
                          {"tree_size": 5, "root_hash": "ab" * 32})
        with self.assertRaises(ValueError):
            cp.commit_advance(conn, log.log_id,
                              {**head, "tree_size": 4, "root_hash": "cd" * 32},
                              {"tree_size": 4, "root_hash": "cd" * 32})
        # 同大小不同根也拒绝。
        with self.assertRaises(ValueError):
            cp.commit_advance(conn, log.log_id,
                              {**head, "root_hash": "cd" * 32},
                              {"tree_size": 5, "root_hash": "cd" * 32})
        conn.close()

    def test_wrong_log_id_rejected_at_construction(self):
        conn = cp.connect(":memory:")
        with self.assertRaises(VerificationError):
            Collector(conn, KEY, [], log_id="00" * 32)
        conn.close()


if __name__ == "__main__":
    unittest.main()
