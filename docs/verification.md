# 当前 API 分钟统计验证

2026-11-03，按根 `docs/risk-v1-contract.md` 与 `risk-v1-implementation-contract.md` 的用户批准冻结实施；本文件只记录本轮，不混用旧协议历史测试数量。

## 实施结果

仅 API 进入统计与 Geo；页面、静态、已知 SSE、风控管理及内部 Geo 先过滤，过滤仍原子推进检查点。可信规范原 IP 直接写 sourceIp，未知 null；IPv4-mapped IPv6 归一为 IPv4。每行按 minuteAt/method/pathTemplate/sourceIp/httpStatus 合并，地域快照与次数同一行；失败降级保留次数，同自然维度定位失败不覆盖已有有效地域。

Envelope 精确五字段 schemaVersion/batchId/businessDate/createdAt/records，record 精确十二字段。去除多kind、HLL、24桶、耗时/字节聚合、recordId、checksum、日密钥；路径改固定脱敏占位。仅保留当前 wire，不保留旧协议兼容路径。MMDB/Geo 内容摘要和令牌验证不变，Geo 权威源未修改。Python 的 Geo 测试资源只投影 control/result 输入，排除权威源中本端不消费的历史风险记录。

发布脚本改六键，不再写 day-key-ids。tailer/半行/轮转/租约/原子检查点/同ID同正文不确定重试保留。10秒/500行/1MiB继续生效。300ms Geo/单在途/绝对截止与失败指标保留。坏日志和 Geo 诊断仅固定安全原因及数量，已退出统计 records。

精确重建工具默认预览，显式目标须匹配私有配置，执行需 --execute 和 --writers-stopped。只处理 days、day-key-ids、合法日期 pending、合法日期/UUID batch 及 query 缓存，保留 checkpoints、lease、heartbeat、全部 Geo 数据、服务器配置和其他业务。离线实际 Collector 测试证明：清统计后保留原检查点，再启动不会重读旧行；新追加1行只计1次。

本机退役 HMAC 行注释保留，原私有值未输出；移除注释前缀后的整个私有文件 SHA 与执行前相同。其余私有地址、密码和令牌不改动。此前本机 GEO_SERVICE_URL 缺完整 endpoint 的配置问题不由本轮私自更换私有地址。

## 本轮实际验证

- 完整离线 unittest **120项通过**：`/tmp/risk-minute-tests.log`。使用 fakeredis/Lupa 执行当前 Lua；涵盖先校验后写、错误类型、后续坏行不写、检查点冲突、租约、未知字段、重复自然行、日期/状态/IP/Geo边界、64位计数溢出、半行、轮转、重启、提交结果丢失及 Java 清理后重试、实际500行/1MiB拆分、10秒提交、先过滤后Geo和失败仍计数。
- Geo cache/固定目标/令牌/300ms共享预算/慢滴绝对截止/单worker等离线回归继续通过。
- compileall、git diff --check 通过。
- wheel/sdist 构建于 `/tmp/be-data-risk-minute-dist/`，日志 `/tmp/risk-minute-build.log`。wheel 隔离目录验证 schema SHA、外部当前批次及 CLI 通过；不含测试、fixture、文档或工具。sdist 含当前测试和默认预览工具，不含私有 .env；运行资产没有 fixture/Markdown。构建工具仅使用本地已有依赖。

## Collector 实际离线产物

`/tmp/risk-minute-python-envelope.json` 由 `scripts/export_fixture.py` 驱动实际 Collector、RedisStore 与当前 Lua 产生，不是手写 envelope。输入为临时合成日志；Geo 使用当前 UnifiedGeoClient、假 Redis 与合成 Java wire transport，无实际 HTTP/Redis/MySQL 连接。实际检查点已推进到全部17行结尾。

3个批次，11行，12次API请求；成功7、失败3、other2、精确IP4、接口2、过滤5。包含499、未知/非可信来源、规范IPv6、mapped IPv4、中文路径、城市快照、同维度重复合并、分钟/日期边界和单项坏Geo响应。有效Geo项保留，坏项按UNKNOWN计数；未输入任意客户端XFF作为可信来源。批次日期2026-11-02/03/04均为合成边界，不用于生产。

根 `docs/risk-v1/batches.json` 为同一当前样例，`canonicalEnvelopes` 用于确认 Producer 字节；Java 消费 `batches` 数组。根风险 manifest SHA256：`78796cade0ac89a8290df90c06c69e710d7dbbafafc379401e083efa31843422`。根 schema/Lua 与 Python 运行副本按清单一致。Java 独占的 java-service-response.json 未修改，不纳入 Python 风险资产消费。

## 删除与未验

运行 Python 1859→1585行，净减274行。删除旧 HLL/桶/校验和/日密钥实现及对应测试，替换旧多类型黄金样例；移除独立旧路径/协议修正测试文件，以当前分钟与脱敏边界测试覆盖。删除旧根风险 path/Geo风险行/边界统计样例及旧根两份基础样例，统一当前 batches.json；定位权威源及本端实际 Geo 测试保留。完整执行前 SHA、非私有备份与变更清单分别在 `/tmp/risk-minute-baseline.json`、`/tmp/risk-minute-baseline.tar.gz`、`/tmp/risk-minute-change-summary.json`。

未连接现有 Redis/MySQL/Nginx、未执行真实清理/SQL/服务启动或部署、未提交、未启用 Review。Python 产物已交付，Java 实际解析/事务入库/查询与 Vue 响应消费需由对应开发会话完成，不将 fake 验证称为跨端或生产验收。
