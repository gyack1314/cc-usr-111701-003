"""CT 镜像传输适配：把冻结 HTTP 回放器包装成 RFC 6962 只读端点。

传输层只负责请求/响应与可重试错误，不做密码学判断。所有 JSON 均为
合成样例，不访问真实站点；responder 与 capture_data.io.Replay 的
next(method, url, headers) 接口一致，因此同一采集流程既能跑冻结回放，
也能换成真实 HTTP 客户端。
"""
import json

GET_STH = "ct/v1/get-sth"
GET_ENTRIES = "ct/v1/get-entries"
GET_STH_CONSISTENCY = "ct/v1/get-sth-consistency"
GET_PROOF_BY_LEAF = "ct/v1/get-proof-by-leaf"


class FetchError(Exception):
    """暂时取不到资料（超时、断连、响应流耗尽等），调用方归入待补。"""


class ProtocolError(Exception):
    """镜像给出不可解析或语义非法的响应，调用方归入不可采信。"""


def _require_str(response, field):
    value = response.get(field)
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"响应缺少合法字段 {field}")
    return value


def _require_int(response, field, minimum=0):
    value = response.get(field)
    if type(value) is not int or value < minimum:
        raise ProtocolError(f"响应缺少合法字段 {field}")
    return value


class Mirror:
    """单镜像只读客户端。

    name 用于候选与追溯记录；responder.next 抛 EOFError/ConnectionError/
    TimeoutError 时统一转成 FetchError（待补），HTTP 5xx 同理；HTTP 4xx
    与非法 JSON 属于镜像自身问题，转成 ProtocolError（不可采信）。
    """

    def __init__(self, name, responder, transient_retries=1):
        self.name = name
        self._responder = responder
        self.requests = []
        # 同一轮内对瞬时故障（5xx/断连/流耗尽）的自动重试次数；
        # 重试用尽后抛出 FetchError，由采集器登记为待补。
        self.transient_retries = transient_retries

    def _call(self, method, url, headers=None):
        attempts = self.transient_retries + 1
        last_fetch = None
        for _ in range(attempts):
            try:
                response = self._responder.next(method, url, headers)
            except (EOFError, ConnectionError, TimeoutError) as exc:
                last_fetch = FetchError(f"{self.name} {url} 暂时取不到：{exc}")
                continue
            self.requests.append({"method": method, "url": url,
                                  "headers": dict(headers or {})})
            status = response.get("status")
            if type(status) is not int:
                raise ProtocolError(f"{self.name} 响应缺少 HTTP 状态码")
            if 500 <= status < 600:
                last_fetch = FetchError(
                    f"{self.name} {url} 返回 {status}，稍后重试")
                continue
            if status != 200:
                raise ProtocolError(
                    f"{self.name} {url} 返回非 200 状态 {status}")
            body = response.get("body")
            if isinstance(body, (bytes, bytearray)):
                body = body.decode("utf-8")
            if not isinstance(body, str):
                raise ProtocolError(f"{self.name} {url} 响应体非法")
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as exc:
                raise ProtocolError(
                    f"{self.name} {url} 响应不是合法 JSON") from exc
            if not isinstance(payload, dict):
                raise ProtocolError(f"{self.name} {url} 响应文档必须为对象")
            return payload
        raise last_fetch

    def get_sth(self):
        payload = self._call("GET", GET_STH)
        sth = {
            "tree_size": _require_int(payload, "tree_size"),
            "timestamp": _require_int(payload, "timestamp"),
            "sha256_root_hash": _require_str(payload, "sha256_root_hash"),
            "tree_head_signature": _require_str(payload, "tree_head_signature"),
        }
        if sth["tree_size"] == 0 and payload.get("sha256_root_hash") not in (
                None, ""):
            # 空树根另行允许；这里只保证字段类型，哈希值由核验层判定。
            pass
        return sth, payload

    def get_entries(self, start, end):
        if type(start) is not int or type(end) is not int or start < 0 or end < start:
            raise ProtocolError("条目范围参数非法")
        url = f"{GET_ENTRIES}?start={start}&end={end}"
        payload = self._call("GET", url)
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ProtocolError("get-entries 未返回条目数组")
        parsed = []
        for pos, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ProtocolError("条目结构非法")
            parsed.append({
                "index": start + pos,
                "leaf_input": _require_str(entry, "leaf_input"),
            })
        if len(parsed) > end - start + 1:
            raise ProtocolError("返回条目超出请求范围")
        return parsed, payload

    def get_sth_consistency(self, first, second):
        if first <= 0 or first >= second:
            raise ProtocolError("一致性证明区间非法")
        url = f"{GET_STH_CONSISTENCY}?first={first}&second={second}"
        payload = self._call("GET", url)
        hashes = payload.get("hashes")
        if not isinstance(hashes, list) or not hashes:
            # 端点可达但未给出证明：证明缺失，属不可采信而非待补。
            raise ProtocolError("一致性证明缺失")
        return hashes, payload

    def get_proof_by_leaf(self, leaf_index, tree_size):
        if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
            raise ProtocolError("包含证明参数非法")
        url = f"{GET_PROOF_BY_LEAF}?leaf_index={leaf_index}&tree_size={tree_size}"
        payload = self._call("GET", url)
        hashes = payload.get("hashes")
        if not isinstance(hashes, list):
            raise ProtocolError("包含证明缺失")
        leaf_hash_hex = payload.get("leaf_hash")
        if not isinstance(leaf_hash_hex, str) or not leaf_hash_hex:
            raise ProtocolError("包含证明缺少 leaf_hash")
        return hashes, leaf_hash_hex, payload
