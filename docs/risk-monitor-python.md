# 风控采集端说明

现行单一访问、配置和资源协议为 schemaVersion=2，字段及无版本 Redis 键以工作区根 `docs/risk-monitor-v1-contract.md` 为准。旧统计不读取、不双写。

本机配置提供 `COLLECTOR_ID`、日志源和可选 `SM4_KEY`。启用的 REMOTE 目标使用 Java 下发的 SM4/ECB/PKCS5Padding 密文，在采样时解密，并严格校验服务用户 `~/.ssh/known_hosts` 中的远程主机公钥；Redis 不保存明文密码。本地目标直接采集。Nginx 日志源独立于资源目标启停。资源只覆盖 Redis 最新值，首次采样和计数器回退不推算速率。

采集器状态写入 `risk:heartbeat` 的 `monitor:{编码采集器ID}` 字段；Redis 服务器时间用于状态更新时间，同 ID 采集器通过 30 秒租约和递增 epoch 排他，10 秒续租。日志和资源的发布 Lua 在提交时校验租约；资源发布还校验当前配置版本。Nginx 日志缺乏完整水位证据，来源连续性始终标为 `UNKNOWN`、时间为 null。线协议以根共享契约为准。

生产切换先停止旧生产者及消费者，核对 Redis 目标和计划，按源迁移旧检查点至 `risk:checkpoints`，避免意外从日志头回读。`tools/rebuild_redis.py` 只提供只读预览；旧配置和检查点默认受保护，不执行删除或迁移。切换操作仍需隔离联调和单独授权。

动态 `sourceId`、`collectorId` 和 Geo `cacheVersion` 进入 key 段前编码为 UTF-8 大写十六进制，报文与检查点 Hash 字段保留原值；源/采集器 ID 上限 80 字节、Geo cacheVersion 当前上限 256 字节，Java 须使用同一限制和编码。未连接现有 Redis、MySQL、Nginx 或 SSH，未部署和提交。
