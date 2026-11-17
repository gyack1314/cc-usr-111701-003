# ct-log 来源契约

来源清单中的资产长度与 SHA-256 用于核对本地原文字节。文档的 collection 与 protocol 必须匹配清单，现有记录类型包括 tree_size, leaf, tree_root, proof。每条记录以 kind、id、version 定位，refs 指向同集合的其他记录，payload 原样留存。来源版本冲突会中断接收；本地引用闭合只表示当前收到的引用能定位，不表示远端序列或授权资料已经完整。

## 已接收的协议资料
现有入口保留 CT 树大小、时间戳、根哈希、签名原文、叶子索引和一致性证明候选。它只做结构检查，不验证签名或 Merkle 证明，也不发布可信证书。


同集合第二次来源接收保存在 data/conflict-case.json。冲突事务必须保持第一份收据和旧投影。

## 检查点冻结采集资产

data/checkpoint/fixture.json 是 ct-checkpoint-fixture 清单：记录 log_id、base64 验证密钥、轮次数，以及每个镜像记录文件的路径、字节长度与 SHA-256。装载前必须核对资产字节身份；每条冻结记录带 round 标记，装载器按轮次切成独立的 io.Replay 回放器，请求序列与采集器 run_once 的实际调用（含瞬时故障重试）严格对齐。记录文件为不可信数据，采集器只通过 transport.Mirror 访问，不直接 import 或执行。

检查点库（sqlite）的 confirmed_heads 只追加已确认树版本，watermark 单调前移，verified_leaves 以 (log_id, leaf_index) 为主键并记录核验时的树版本与证明响应摘要；backlog/quarantine 分别保存待补、冲突与不可采信候选，候选不进入正式检索结果。
