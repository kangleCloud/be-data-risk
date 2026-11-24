# be-data-risk

Python 只读采集 Nginx 完成请求并采集本机或受控远程主机的资源，按日志来源、请求类别、分钟、方法、脱敏路径、可信 IP 和状态聚合。Java 负责目标配置、Geo 定位、入库与查询。

## 配置与启动

要求 Python >=3.11；Debian Python 3.13 需先安装 `python3.13-venv`。

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-runtime.txt
cp .env.example .env.prod
.venv/bin/python -m risk --config .env.prod
```

在私有 `.env.prod` 中配置 Redis、`COLLECTOR_ID`、可信代理、本地日志源及 Geo。远程资源采集还需设置 `SM4_KEY`，其值为 Java 原有 `Sm4Utils` 的 16 字节 UTF-8 密钥的 Base64 编码；不要提交密钥。Java 将加密后的 SSH 密码随监控配置快照发布到 Redis，Python 仅在启用远程目标采样时解密。LOCAL 直接采集，不读取密码。Nginx 日志按本机日志源采集，不依赖资源监控目标的启停或配置快照。

旧私有配置如含 `SSH_SERVERS`（JSON 格式为 `sshServers`），需自行移除旧字段后再启动；程序不会自动修改私有配置。

远程密码认证需在采集机安装 `sshpass`（Debian：`apt install sshpass`），并在采集服务用户的 `~/.ssh/known_hosts` 中预先登记经可信渠道核实的远程主机公钥。程序强制校验主机密钥，明文密码经文件描述符传递，不放入 SSH 命令参数、Redis 或日志。SM4 解密使用与 Java 相同的 ECB/PKCS5Padding 格式。

默认 `--config` 不读取环境变量或执行 shell；`--once` 处理当前完整日志及当前资源采集，`--check-file` 仅检查合成样本。systemd 样例在 `deploy/systemd/be-data-risk.service`，不自动安装或启动。

Geo 内部接口示例为 `http://127.0.0.1:19004/scheduler/api/internal/risk/geo/resolve-batch`；`GEO_SERVICE_TOKEN` 与 Java 专用令牌一致。雷池回源 topology 下，确认 Nginx 已规范化 `$remote_addr` 后才能设置 `DIRECT_PEER_TRUSTED=true`。未受信来源不从任意 XFF 提取 IP。

## 统计与交付

所有完成请求归 `API/PAGE/STATIC/OTHER`；SSE 完成日志计入 OTHER，不表示连接数。风控及内部 Geo 请求计数，内部 Geo 请求不再发起 Geo 解析。路径去参数并脱敏，不保存原始日志、请求体或认证信息。资源样本将缺失值置 null，按 `cpu/memory/disk/networkRate/load/uptime` 记录固定原因。

HTTP 分钟记录写入 `risk:http:pending`，检查点保存在 `risk:checkpoints`；其他键为 `risk:heartbeat`、`risk:monitor:config`、`risk:monitor:resource:current:{targetId}` 及 `geoip:*`。时间字段使用 `xxxTime`，配置与资源协议为 schemaVersion 2。

实时 QPS 的日志计数写入 `risk:http:qps:{epochMinute}`，分钟编号为 Unix 秒除以 60 取整。每条有效访问记录计一次，和检查点原子提交。持续采集期间，在分钟结束后所有日志源已追到文件末尾且计数已提交时，写入 `ready=1`；只有该标记存在时，缺少 `requestCount` 才代表零请求。分钟键在该分钟结束 10 分钟后过期，有效期内可接收迟到日志。

日志读取支持半行、轮转和截断。按最多 10 秒或 500 条聚合记录定期交付。提交检查点和 QPS 计数后再写历史队列，历史入队失败不重投。运行中若 Redis 丢失已知检查点，恢复游标并跳过待提交批次，让受影响的分钟保持不可用，防止旧计数仍在时重复累计。每个采集器 ID 和每个日志来源只部署一个实例。资源样本使用带 TTL 的普通 SET，SSH 继续严格验证主机密钥。

## 切换预览

停止旧生产者和消费者、检查旧统计及检查点迁移计划后才进行切换。新代码不会读取旧统计，也不会自动复制或删除旧检查点。旧检查点应按源迁移到 `risk:checkpoints`，避免文件从头重新读取；冲突需人工核对。目标配置与旧检查点默认保留，清理不能使用 FLUSHDB。

以下工具只预览，不提供执行删除的选项；目标不含凭据且必须匹配显式配置：

```sh
.venv/bin/python tools/rebuild_redis.py --config /path/to/.env.prod --target 'redis://HOST:6379/2'
```

预览输出旧统计及待处理键的数量和检查点冲突数量，不输出键名、值、目标或凭据。清理或迁移的实际执行需另行确认具体范围与步骤，本仓库未操作生产服务或数据。

## 验证

```sh
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m compileall -q risk tests
.venv/bin/python scripts/export_fixture.py /tmp/risk-producer.json
.venv/bin/python -m build --no-isolation --outdir /tmp/risk-dist
.venv/bin/python scripts/verify_package.py /tmp/risk-dist/be_data_risk-0.1.1-py3-none-any.whl
```

风控和 GeoIP schema 随包交付。以根契约和当前离线测试为准，验证文档中的旧批次及 Lua 记录保留作历史说明。
