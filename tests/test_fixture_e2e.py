"""冻结资产端到端：清单身份、三轮回放、重启恢复与检索追溯。"""
import json
import tempfile
import unittest
from pathlib import Path

from capture_data.checkpoint import connect
from capture_data.cli import main as cli_main
from capture_data.collector import Collector
from capture_data.fixture import load_fixture
from capture_data.retrieval import traceable_certificates
import io
import sys
from contextlib import redirect_stdout

DATA = Path(__file__).resolve().parents[1] / "data" / "checkpoint"
FIXTURE = DATA / "fixture.json"


class FixtureE2ETest(unittest.TestCase):
    def test_three_round_collection_and_restart(self):
        config, mirror_rounds = load_fixture(FIXTURE)
        self.assertEqual(config["rounds"], 3)
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cp.sqlite3"
            conn = connect(db)

            # 第 1 轮：B 的 sth 与 A 的 entries 各有一次 503，待补后
            # 同轮重试成功，bootstrap 到大小 3。
            r1 = Collector(conn, config["verification_key"],
                           mirror_rounds[0], log_id=config["log_id"]).run_once()
            self.assertTrue(r1["advanced"])
            self.assertEqual(r1["watermark_after"]["tree_size"], 3)
            self.assertFalse(r1["conflicts"])
            self.assertFalse(r1["inadmissible"])

            # 第 2 轮：扩到 5，B 落后但一致性证明成立。
            r2 = Collector(conn, config["verification_key"],
                           mirror_rounds[1], log_id=config["log_id"]).run_once()
            self.assertTrue(r2["advanced"])
            self.assertEqual(r2["confirmed_head"]["consistency_from_size"], 3)
            self.assertEqual(r2["watermark_after"]["tree_size"], 5)

            # 模拟重启：重新打开库，已确认的两个树根都还在。
            conn.close()
            conn = connect(db)
            self.assertEqual(
                [row[0] for row in
                 conn.execute("SELECT tree_size FROM confirmed_heads "
                              "ORDER BY tree_size").fetchall()],
                [3, 5])

            # 第 3 轮：同步重确认，幂等无新版本。
            r3 = Collector(conn, config["verification_key"],
                           mirror_rounds[2], log_id=config["log_id"]).run_once()
            self.assertFalse(r3["advanced"])
            self.assertEqual(r3["watermark_after"]["tree_size"], 5)

            result = traceable_certificates(conn, config["log_id"])
            self.assertEqual(result["count"], 5)
            self.assertEqual(result["watermark"]["tree_size"], 5)
            first_cert = result["certificates"][0]
            self.assertEqual(first_cert["leaf_index"], 0)
            self.assertEqual(first_cert["provenance"]["tree_size"], 3)
            self.assertTrue(first_cert["provenance"]["tree_head_signature"])
            self.assertEqual(first_cert["provenance"]["source_mirror"],
                             "mirror-a")
            # 后两片叶子追溯到大小 5 的树版本。
            self.assertEqual(
                result["certificates"][3]["provenance"]["tree_size"], 5)
            conn.close()

    def test_asset_identity_rejects_tampered_fixture(self):
        import hashlib
        manifest = json.loads(FIXTURE.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp)
            shutil_copy = (DATA / manifest["mirrors"][0]["asset"]["path"]).read_bytes()
            (bad / manifest["mirrors"][0]["asset"]["path"]).write_bytes(shutil_copy)
            other = (DATA / manifest["mirrors"][1]["asset"]["path"]).read_bytes()
            (bad / manifest["mirrors"][1]["asset"]["path"]).write_bytes(other)
            tampered_manifest = json.loads(json.dumps(manifest))
            tampered_manifest["mirrors"][0]["asset"]["sha256"] = "00" * 32
            (bad / "fixture.json").write_text(json.dumps(tampered_manifest))
            with self.assertRaises(ValueError):
                load_fixture(bad / "fixture.json")

    def test_cli_collect_and_retrieve(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "cli.sqlite3")
            buf = io.StringIO()
            argv = sys.argv
            try:
                sys.argv = ["cli", "collect", str(FIXTURE), "--database", db]
                with redirect_stdout(buf):
                    cli_main()
                out = json.loads(buf.getvalue())
                self.assertEqual(out["checkpoint"]["watermark"]["tree_size"], 5)
                self.assertEqual(len(out["checkpoint"]["confirmed_heads"]), 2)

                buf = io.StringIO()
                sys.argv = ["cli", "retrieve", str(FIXTURE), "--database", db]
                with redirect_stdout(buf):
                    cli_main()
                result = json.loads(buf.getvalue())
                self.assertEqual(result["count"], 5)

                buf = io.StringIO()
                sys.argv = ["cli", "retrieve", str(FIXTURE), "--database", db,
                            "--leaf", "2"]
                with redirect_stdout(buf):
                    cli_main()
                trace = json.loads(buf.getvalue())
                self.assertEqual(trace["leaf_index"], 2)
                self.assertEqual(trace["verified_against"]["tree_size"], 3)
            finally:
                sys.argv = argv


if __name__ == "__main__":
    unittest.main()
