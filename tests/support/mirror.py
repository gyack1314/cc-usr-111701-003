"""脚本化 CT 镜像：与 io.Replay 同接口的故障注入响应器。

behaviors 按端点配置故障策略，未配置的端点正常应答合成日志。所有请求
与响应同时记录到 records，可直接导出为 io.Replay 消费的冻结回放资产。

故障策略（每个端点可叠加 fail_times 类瞬时故障）：

* {"fail_times": n, "kind": "fetch"}     前 n 次 HTTP 503（待补）
* {"fail_times": n, "kind": "eof"}       前 n 次连接中断（待补）
* {"fail_times": n, "kind": "protocol"}  前 n 次 HTTP 404（不可采信）
* sth 专属：{"sth_override": payload}    应答任意树头（伪造/分叉）
* consistency/inclusion 专属：
  {"tamper": True}                       替换首个证明哈希
  {"omit": True}                         证明哈希为空（证明缺失）
* entries 专属：{"partial": n}           只返回前 n 条
                 {"tamper_leaf": True}   替换叶子原文
* inclusion 专属：{"bad_leaf_hash": True} leaf_hash 字段与原文不符
* 镜像冻结视图：{"view_size": N}        所有应答基于大小 N 的旧视图
"""
import json
from urllib.parse import parse_qs, urlparse

from tests.support.synthetic import http_200, http_error


class ScriptedMirror:
    def __init__(self, name, log, behaviors=None):
        self.name = name
        self.log = log
        self.behaviors = behaviors or {}
        self.calls = []
        self.records = []
        self.round = 0

    def begin_round(self, round_index):
        """标记后续请求所属的采集轮次，供冻结资产按轮回放。"""
        self.round = round_index

    # -- io.Replay 兼容接口 ---------------------------------------------------

    def next(self, method, url, headers=None):
        parsed = urlparse(url)
        route = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self.calls.append({"method": method, "url": url,
                           "headers": dict(headers or {})})
        response = self._dispatch(route, query)
        self.records.append({
            "round": self.round,
            "request": {"method": method, "url": url,
                        "headers": dict(headers or {})},
            "response": response,
        })
        return response

    def export_records(self):
        return list(self.records)

    # -- 内部分发 -------------------------------------------------------------

    def _cfg(self, route):
        return self.behaviors.get(route, {})

    def _transient(self, route):
        """返回瞬时故障响应；故障次数耗尽返回 None。"""
        cfg = self._cfg(route)
        counter = self.behaviors.setdefault("_counters", {})
        used = counter.get(route, 0)
        fail_times = cfg.get("fail_times", 0)
        if used < fail_times:
            counter[route] = used + 1
            kind = cfg.get("kind", "fetch")
            if kind == "eof":
                raise EOFError(f"{self.name} {route} 连接中断")
            if kind == "protocol":
                return http_error(404, "not found")
            return http_error(503, "temporarily unavailable")
        return None

    def _view_size(self, cfg):
        return cfg["view_size"] if "view_size" in cfg else self.log.size()

    def _dispatch(self, route, query):
        transient = self._transient(route)
        if transient is not None:
            return transient
        cfg = self._cfg(route)

        if route == "ct/v1/get-sth":
            if "sth_override" in cfg:
                return http_200(cfg["sth_override"])
            return http_200(self.log.sth_payload(self._view_size(cfg)))

        if route == "ct/v1/get-entries":
            start, end = int(query["start"]), int(query["end"])
            payload = self.log.entries_payload(
                start, end, view_size=self._view_size(cfg))
            if cfg.get("partial"):
                payload = {"entries": payload["entries"][:cfg["partial"]]}
            if cfg.get("tamper_leaf") and payload["entries"]:
                first = payload["entries"][0]
                tampered = ("AA" + first["leaf_input"][2:]) if len(
                    first["leaf_input"]) > 2 else "AA=="
                payload = json.loads(json.dumps(payload))
                payload["entries"][0]["leaf_input"] = tampered
            return http_200(payload)

        if route == "ct/v1/get-sth-consistency":
            first, second = int(query["first"]), int(query["second"])
            payload = self.log.consistency_payload(first, second)
            if cfg.get("omit"):
                payload = {"hashes": []}
            if cfg.get("tamper") and payload["hashes"]:
                bad = ("00" * 32) if payload["hashes"][0] != "00" * 32 else "11" * 32
                payload["hashes"][0] = bad
            return http_200(payload)

        if route == "ct/v1/get-proof-by-leaf":
            index, size = int(query["leaf_index"]), int(query["tree_size"])
            payload = self.log.inclusion_payload(index, size)
            if cfg.get("omit"):
                payload["hashes"] = []
            if cfg.get("tamper") and payload["hashes"]:
                bad = ("00" * 32) if payload["hashes"][0] != "00" * 32 else "11" * 32
                payload["hashes"][0] = bad
            if cfg.get("bad_leaf_hash"):
                payload["leaf_hash"] = "00" * 32
            return http_200(payload)

        return http_error(404, "unknown route")
