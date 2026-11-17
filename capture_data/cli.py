"""命令行入口。

inspect    原有冻结来源资料查看（保持兼容）；
collect    回放冻结镜像资产，跑检查点驱动的增量采集；
checkpoint 查看已确认树版本链、水位、待补与隔离区；
retrieve   输出可追溯正式证书（未完成证明的候选不可见）。
"""
import argparse
import json
from pathlib import Path

from .checkpoint import connect
from .collector import Collector
from .domain import summarize
from .fixture import load_fixture
from .io import load
from .journal import connect as journal_connect
from .journal import receive
from .projection import overview
from .retrieval import checkpoint_view, raw_leaf_trace, traceable_certificates


def _print(payload):
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def cmd_inspect(args):
    path = Path(args.file)
    manifest, digest = load(path)
    summary = summarize(manifest, path.parent)
    conn = journal_connect(":memory:")
    source = receive(conn, manifest, path.parent)
    _print({"manifest_sha256": digest, "source_sha256": source,
            "summary": summary,
            "overview": overview(conn, manifest["collection"])})
    conn.close()


def cmd_collect(args):
    config, mirror_rounds = load_fixture(args.fixture)
    db_path = Path(args.database)
    conn = connect(db_path)
    rounds = []
    for idx, mirrors in enumerate(mirror_rounds, start=1):
        collector = Collector(conn, config["verification_key"], mirrors,
                              log_id=config["log_id"])
        report = collector.run_once()
        rounds.append({
            "round": idx,
            "advanced": report["advanced"],
            "watermark": report["watermark_after"],
            "verified_leaves": report["verified_leaves"],
            "pending": report["pending"],
            "conflicts": report["conflicts"],
            "inadmissible": report["inadmissible"],
        })
    view = checkpoint_view(conn, config["log_id"])
    _print({"collection": config["collection"], "log_id": config["log_id"],
            "database": str(db_path), "rounds": rounds, "checkpoint": view})
    conn.close()


def cmd_checkpoint(args):
    config, _ = load_fixture(args.fixture)
    conn = connect(args.database)
    _print(checkpoint_view(conn, config["log_id"]))
    conn.close()


def cmd_retrieve(args):
    config, _ = load_fixture(args.fixture)
    conn = connect(args.database)
    if args.leaf is not None:
        payload = raw_leaf_trace(conn, config["log_id"], args.leaf)
        if payload is None:
            raise SystemExit(f"叶子 {args.leaf} 未通过核验或不存在")
    else:
        payload = traceable_certificates(conn, config["log_id"])
    _print(payload)
    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="CT 检查点驱动采集与可追溯检索")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="查看冻结来源资料")
    p_inspect.add_argument("file")
    p_inspect.set_defaults(func=cmd_inspect)

    p_collect = sub.add_parser("collect", help="回放冻结镜像并增量采集")
    p_collect.add_argument("fixture", help="fixture.json 清单路径")
    p_collect.add_argument("--database", required=True, help="检查点 sqlite 路径")
    p_collect.set_defaults(func=cmd_collect)

    p_cp = sub.add_parser("checkpoint", help="查看检查点与待补/隔离区")
    p_cp.add_argument("fixture")
    p_cp.add_argument("--database", required=True)
    p_cp.set_defaults(func=cmd_checkpoint)

    p_retr = sub.add_parser("retrieve", help="检索可追溯正式证书")
    p_retr.add_argument("fixture")
    p_retr.add_argument("--database", required=True)
    p_retr.add_argument("--leaf", type=int, default=None,
                        help="只看某条叶子的完整追溯链")
    p_retr.set_defaults(func=cmd_retrieve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
