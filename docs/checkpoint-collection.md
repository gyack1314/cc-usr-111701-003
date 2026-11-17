# 检查点驱动的 CT 增量采集

旧流程只按"最后见过的 index"续采，镜像扩容后无法证明新目录接在旧目录
之后，伪造的重复索引也可能被写成新证书。本模块把推进依据从 index 换成
**已确认树头（检查点）**，每一轮都先过密码学闸门，再在事务里推进可发布
水位。

## 核验闸门

采集器（`capture_data.collector.Collector.run_once`）按顺序执行：

1. **签名身份**：对每个镜像的 get-sth 核对 log_id 与树头签名
   （`verifier.verify_signed_tree_head`）。合成日志用 HMAC-SHA256 代替
   RFC 6962 的 ECDSA/RSA 日志签名，log_id 由验证密钥派生，接入真实日志
   时只需替换这一个函数。
2. **镜像间交叉核对**：同树大小不同根 → 冲突；树头小于已确认水位 →
   回退冲突；落后镜像必须给出到领头树头的**追加一致性证明**。
3. **树头连续性**：领头树头相对上一确认树头做 RFC 6962 一致性证明
   （`merkle.verify_consistency`）。首启空树无需证明，改由全量包含证明
   建立根。
4. **条目包含证明与叶子原文**：增量段逐条重算叶子哈希，核对证明声明的
   leaf_hash 与 `merkle.verify_inclusion`；索引必须连续、整段齐全。
5. **原子推进**：全部通过后，在单个 sqlite 事务（`checkpoint.commit_segment`）
   里写入整段已核验叶子、追加 `confirmed_heads` 并前移 `watermark`。
   任何一步失败（含伪造重复索引触发的主键冲突）整体回滚，绝不出现
   "叶子已入库但树版本未确认"的中间态，重启后从旧检查点重放。

## 三态分类

| 现象 | 分类 | 落点 | 后续 |
| --- | --- | --- | --- |
| get-sth / 条目 / 证明暂时取不到（5xx、断连、流耗尽） | 待补 pending | `backlog` | 下轮自动重试，成功后清除 |
| 镜像只返回部分条目 | 待补 pending | `backlog` | 从缺口索引重取 |
| 落后镜像的一致性证明暂时取不到 | 待补 pending | `backlog` | 下轮重试 |
| 同树大小两个签名根不一致 | 冲突 conflict | `quarantine` | 人工处置，不自动覆盖 |
| 树头回退到已确认水位之下 | 冲突 conflict | `quarantine` | 阻断推进 |
| 同索引写入不同叶子哈希（伪造重复索引） | 冲突 conflict | `quarantine` | 保留先确认叶子 |
| 签名/日志身份核验失败 | 不可采信 inadmissible | `quarantine` | 阻断推进 |
| 证明缺失（端点可达但 hashes 为空） | 不可采信 inadmissible | `quarantine` | 阻断推进 |
| 一致性/包含证明核验失败、叶子哈希不符 | 不可采信 inadmissible | `quarantine` | 阻断推进 |
| 响应非 200（4xx）、JSON/结构非法 | 不可采信 inadmissible | `quarantine` | 阻断推进 |

分类只允许保持或升级（待补 → 冲突/不可采信），不允许降级抹除。

## 重启与水位语义

* `confirmed_heads` 只追加：每个通过核验的树版本（tree_size、根哈希、
  签名、一致性证明摘要、来源镜像、响应摘要）永久留痕，重启不丢。
* `watermark` 单调不减，回退尝试直接抛错。
* `verified_leaves` 以 `(log_id, leaf_index)` 为主键，同索引不同哈希
  写入即抛错，从存储层挡住伪造重复索引。
* 未完成全部证明的候选只在 `backlog`/`quarantine` 中，绝不写入
  `verified_leaves`，也不出现在检索结果里。

## 检索追溯

`retrieval.traceable_certificates` 只发布水位以下的证书，每条带
`provenance`：被核验时的 tree_size、tree_root_hash、树头签名与时间戳、
包含证明响应摘要、条目响应摘要、来源镜像。`retrieval.raw_leaf_trace`
提供单条叶子的完整追溯链（含无法解析为证书的原始叶子）。无法解析的
叶子不伪造证书字段，仅保留 raw_b64 与哈希。

## 离线演示

`data/checkpoint/` 是带 SHA-256 清单的冻结镜像资产（由
`tools/build_fixture.py` 生成），三轮分别演示待补重试、落后镜像一致性
追赶、同步幂等重确认：

```sh
python tools/build_fixture.py
python -m capture_data.cli collect data/checkpoint/fixture.json --database /tmp/cp.sqlite3
python -m capture_data.cli checkpoint data/checkpoint/fixture.json --database /tmp/cp.sqlite3
python -m capture_data.cli retrieve data/checkpoint/fixture.json --database /tmp/cp.sqlite3
python -m capture_data.cli retrieve data/checkpoint/fixture.json --database /tmp/cp.sqlite3 --leaf 4
```

传输层 `transport.Mirror` 包装的 responder 与 `io.Replay` 同接口，
换成真实 HTTP 客户端即可接入线上 CT 镜像，采集状态机不变。
