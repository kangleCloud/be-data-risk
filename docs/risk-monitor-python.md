# 风控采集端说明

现行单一访问、配置和资源协议为 schemaVersion=2，字段及无版本 Redis 键以工作区根 `docs/risk-monitor-v1-contract.md` 为准。旧统计不读取、不双写。

本机配置提供 `COLLECTOR_ID`、日志源和可选 `SM4_KEY`。启用的 REMOTE 目标使用 Java 下发的 SM4/ECB/PKCS5Padding 密文，在采样时解密，并严格校验服务用户 `~/.ssh/known_hosts` 中的远程主机公钥；Redis 不保存明文密码。本地目标直接采集。Nginx 日志源独立于资源目标启停。资源只覆盖 Redis 最新值，首次采样和计数器回退不推算速率。



Python 按目标配置内容应用 Redis 快照，版本占位字段和刷新时间不参与判断。配置读取失败时继续使用最近一次有效快照，并在心跳报告错误。采集器状态通过普通 HSET 写入 `risk:heartbeat`，每个采集器 ID 和每个日志源只运行一个实例。心跳和资源样本中的配置版本占位字段写入空字符串。日志先保存检查点，再把独立统计记录推入有界队列；不确定的入队结果不重投。时间字段使用 `xxxTime` 或 `xxxTimeMillis`。

现网重建前停止旧风控进程。用 `python tools/rebuild_redis.py --config <私有配置路径> --target <无凭据的 Redis 地址和 DB>` 预览风控及 GeoIP 键数。核对后追加 `--execute --writers-stopped` 清除。旧检查点随风控数据清除，重新读取配置所指向的可用日志。
