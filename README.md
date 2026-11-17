# 证书透明日志的检查点一致性与条目采集资料服务

项目接收 ct-log 来源资料。`capture_data.io` 冻结字节和请求来源，`capture_data.domain` 核对本领域记录结构，`capture_data.journal` 封存来源原文和版本，`capture_data.projection` 显示本地引用缺口。

在此之上新增**检查点驱动的增量采集**：`capture_data.merkle` 实现 RFC 6962 叶子哈希、条目包含证明与追加一致性证明；`capture_data.verifier` 核对日志身份与树头签名（合成日志为 HMAC，接口可替换为真实 RFC 6962 签名核验）；`capture_data.transport` 把冻结 HTTP 回放包装成 CT 镜像客户端并区分待补与不可采信；`capture_data.checkpoint` 持久化只追加的已确认树头、单调水位、已核验叶子、待补与隔离区；`capture_data.collector` 按"签名身份 → 镜像交叉核对 → 树头一致性 → 条目包含证明与叶子原文 → 事务推进水位"的闸门运行；`capture_data.retrieval` 发布带树版本追溯的正式证书，未完成证明的候选不可见。设计细节见 [docs/checkpoint-collection.md](docs/checkpoint-collection.md)。

Python 3.11 以上，无第三方依赖。样例均为合成，不访问真实站点。

```sh
python -m unittest discover -s tests -v
python -m compileall -q capture_data tests tools
python -m capture_data.cli inspect data/normal.json
```

检查点采集的离线端到端演示（冻结镜像资产，三轮：待补重试、落后追赶、幂等重确认）：

```sh
python tools/build_fixture.py
python -m capture_data.cli collect data/checkpoint/fixture.json --database /tmp/cp.sqlite3
python -m capture_data.cli retrieve data/checkpoint/fixture.json --database /tmp/cp.sqlite3
```

Dockerfile 提供 Linux 运行环境；`docker build -t source-capture .` 构建，`docker run --rm source-capture python -m unittest discover -s tests -v` 运行测试。

协议样例可通过 python -m capture_data.cli inspect data/protocol-case.json 查看。该命令只说明现有接收能力；新采集流程的连续性与全量完整性由 collect/retrieve 命令及其密码学闸门保证。
