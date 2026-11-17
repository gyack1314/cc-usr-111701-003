"""生成离线冻结采集资产（开发期工具，非运行期依赖）。

在一个合成日志上模拟三轮镜像交换并录制全部 HTTP 记录：

* 第 1 轮（bootstrap 到大小 3）：镜像 B 的 get-sth 首次 503、镜像 A 的
  get-entries 首次 503（均为待补），传输层同轮自动重试后恢复；
* 第 2 轮（扩到大小 5）：镜像 B 停留在大小 3，给出到大小 5 的追加
  一致性证明（落后镜像追赶）；
* 第 3 轮：两镜像同步到大小 5，重确认幂等。

全程复用 Mirror 实例，录制的请求/响应序列与采集器 run_once 的实际
调用序列（含重试）完全一致，可直接交给 io.Replay 回放。

输出到 data/checkpoint/：两份镜像的冻结记录 JSON 与带字节哈希的清单。
运行：python tools/build_fixture.py
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture_data.transport import FetchError, Mirror  # noqa: E402
from capture_data.verifier import log_identity  # noqa: E402
from tests.support.mirror import ScriptedMirror  # noqa: E402
from tests.support.synthetic import SyntheticLog, make_leaf_bytes  # noqa: E402

KEY = b"frozen-demo-log-key"
OUT = ROOT / "data" / "checkpoint"
NAMES = ("mirror-a", "mirror-b")


def asset_ref(path: Path):
    raw = path.read_bytes()
    return {"path": path.name, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    log = SyntheticLog(KEY)
    for i in range(3):
        log.append(make_leaf_bytes(i, "demo.test"))
    scripts = {name: ScriptedMirror(name, log) for name in NAMES}
    mirrors = {name: Mirror(name, scripts[name]) for name in NAMES}

    # -- 第 1 轮：bootstrap，注入两处瞬时故障，同轮重试恢复 ------------------
    for script in scripts.values():
        script.begin_round(1)
    scripts["mirror-b"].behaviors = {"ct/v1/get-sth": {"fail_times": 1}}
    scripts["mirror-a"].behaviors = {"ct/v1/get-entries": {"fail_times": 1}}
    for name in NAMES:
        try:
            mirrors[name].get_sth()
        except FetchError:
            mirrors[name].get_sth()  # 第二次成功
    try:
        mirrors["mirror-a"].get_entries(0, 2)
    except FetchError:
        mirrors["mirror-a"].get_entries(0, 2)
    for idx in range(3):
        mirrors["mirror-a"].get_proof_by_leaf(idx, 3)

    # -- 第 2 轮：日志扩到 5，B 落后 -----------------------------------------
    for script in scripts.values():
        script.begin_round(2)
    log.append(make_leaf_bytes(3, "demo.test"))
    log.append(make_leaf_bytes(4, "demo.test"))
    scripts["mirror-a"].behaviors = {}
    scripts["mirror-b"].behaviors = {"ct/v1/get-sth": {"view_size": 3}}
    for name in NAMES:
        mirrors[name].get_sth()
    mirrors["mirror-b"].get_sth_consistency(3, 5)
    mirrors["mirror-a"].get_sth_consistency(3, 5)
    mirrors["mirror-a"].get_entries(3, 4)
    for idx in range(3, 5):
        mirrors["mirror-a"].get_proof_by_leaf(idx, 5)

    # -- 第 3 轮：B 追平，同步重确认 -----------------------------------------
    for script in scripts.values():
        script.begin_round(3)
    scripts["mirror-b"].behaviors = {}
    for name in NAMES:
        mirrors[name].get_sth()

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {
        "kind": "ct-checkpoint-fixture",
        "protocol": "ct-log",
        "collection": "checkpoint-demo",
        "log_id": log_identity(KEY),
        "verification_key_b64": base64.b64encode(KEY).decode(),
        "rounds": 3,
        "mirrors": [],
    }
    for name in NAMES:
        path = OUT / f"{name}.records.json"
        path.write_text(json.dumps(
            scripts[name].export_records(), ensure_ascii=False, indent=2))
        manifest["mirrors"].append({"name": name, "asset": asset_ref(path)})
    manifest_path = OUT / "fixture.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"已生成冻结资产于 {OUT}")
    for name in NAMES:
        print(f"  {name}: {len(scripts[name].records)} 条冻结响应")
    print(f"  log_id: {log_identity(KEY)}")


if __name__ == "__main__":
    main()
