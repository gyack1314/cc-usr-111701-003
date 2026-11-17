"""装载 data/checkpoint 下的冻结采集资产并按轮次切分镜像回放器。

清单（fixture.json）记录每个镜像记录文件的长度与 SHA-256，装载前先
核对字节身份；记录按请求 URL 中的端点序列切成三轮，对应采集器的三次
run_once。装载器只负责身份核对与回放，不内置任何采集策略。
"""
import base64
import hashlib
import json
from pathlib import Path

from .io import Replay
from .transport import Mirror


def _load_asset(base: Path, ref: dict):
    path = (base / ref["path"]).resolve()
    if not path.is_relative_to(base.resolve()):
        raise ValueError("资产路径越界")
    raw = path.read_bytes()
    if len(raw) != ref["bytes"]:
        raise ValueError("资产长度不符")
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        raise ValueError("资产 SHA-256 不符")
    return json.loads(raw.decode("utf-8"))


def _split_rounds(records, round_count):
    """按录制时写入的 round 标记切分；缺轮或越界即拒绝。"""
    chunks = [[] for _ in range(round_count)]
    for record in records:
        round_index = record.get("round")
        if type(round_index) is not int or not 1 <= round_index <= round_count:
            raise ValueError("冻结记录缺少合法轮次标记")
        chunks[round_index - 1].append(record)
    for idx, chunk in enumerate(chunks, start=1):
        if not chunk:
            raise ValueError(f"第 {idx} 轮没有冻结记录")
    return chunks


def load_fixture(fixture_path):
    """读取清单并返回 (config, 每轮的镜像列表)。

    config 含 log_id、verification_key、collection 与轮次数；mirror_rounds
    是 [[Mirror,...], [Mirror,...], ...]，每轮的 Replay 都是独立游标。
    """
    fixture_path = Path(fixture_path)
    base = fixture_path.parent
    manifest = json.loads(fixture_path.read_text(encoding="utf-8"))
    if manifest.get("kind") != "ct-checkpoint-fixture":
        raise ValueError("清单类型不是 ct-checkpoint-fixture")
    key = base64.b64decode(manifest["verification_key_b64"], validate=True)
    mirror_rounds = [[] for _ in range(manifest["rounds"])]
    for entry in manifest["mirrors"]:
        records = _load_asset(base, entry["asset"])
        rounds = _split_rounds(records, manifest["rounds"])
        for idx, chunk in enumerate(rounds):
            mirror_rounds[idx].append(
                Mirror(entry["name"], Replay(chunk)))
    config = {"log_id": manifest["log_id"], "verification_key": key,
              "collection": manifest["collection"],
              "rounds": manifest["rounds"]}
    return config, mirror_rounds
