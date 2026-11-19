# be-data-risk

Python 只读采集 Nginx 完成请求并采集本机或受控远程主机的资源，按目标、请求类别、分钟、方法、脱敏路径、可信 IP 和状态聚合。Java 负责目标配置、Geo 定位、入库与查询。跨端约定以工作区根 `docs/risk-monitor-v1-contract.md` 为准。

## 配置与启动

要求 Python >=3.11；Debian Python 3.13 需先安装 `python3.13-venv`。

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-runtime.txt
cp .env.example .env.prod
.venv/bin/python -m risk --config .env.prod
```

在私有 `.env.prod` 中配置 Redis、`COLLECTOR_ID`、可信代理、本地日志源及 Geo。REMOTE 目标的主机、端口、账号和密码使用本机 `SSH_SERVERS` 列表，格式见 `.env.example`；不要提交真实凭据。Java 向 `risk:monitor:config` 发布完整配置快照后，采集器按主机、端口和账号匹配自己负责的目标。Java 仍要求目标配置填写 `credentialAlias`，该值不存密码；采集器不依赖该别名匹配。首次无法取得配置则不采集；配置失联时保留进程内最近快照并报告过期。LOCAL 可只采资源而不绑定日志源。

远程密码认证需在采集机安装 `sshpass`（Debian：`apt install sshpass`），并在采集服务用户的 `~/.ssh/known_hosts` 中预先登记经可信渠道核实的远程主机公钥。程序强制校验主机密钥，密码经文件描述符传递，不放入 SSH 命令参数或 Redis。

默认 `--config` 不读取环境变量或执行 shell；`--once` 处理当前完整日志及当前资源采集，`--check-file` 仅检查合成样本。systemd 样例在 `deploy/systemd/be-data-risk.service`，不自动安装或启动。

Geo 内部接口示例为 `http://127.0.0.1:19004/scheduler/api/internal/risk/geo/resolve-batch`；`GEO_SERVICE_TOKEN` 与 Java 专用令牌一致。雷池回源 topology 下，确认 Nginx 已规范化 `$remote_addr` 后才能设置 `DIRECT_PEER_TRUSTED=true`。未受信来源不从任意 XFF 提取 IP。

## 统计与交付

所有完成请求归 `API/PAGE/STATIC/OTHER`；SSE 完成日志计入 OTHER，不表示连接数。风控及内部 Geo 请求计数，内部 Geo 请求不再发起 Geo 解析。路径去参数并脱敏，不保存原始日志、请求体或认证信息。资源样本将缺失值置 null，按 `cpu/memory/disk/networkRate/load/uptime` 记录固定原因。

访问批次、配置和资源样本均采用 `schemaVersion=2`。固定 Redis 键为 `risk:days`、`risk:pending:*`、`risk:batch:*`、`risk:checkpoints`、`risk:lease:*`、`risk:heartbeat`、`risk:monitor:config`、`risk:monitor:lease:*`、`risk:monitor:resource:*`；Geo 使用 `geoip:control`、`geoip:result:*`、`geoip:metrics:*`。动态源 ID、采集器 ID 和 Geo cacheVersion 作为 key 段时按 UTF-8 转大写十六进制；报文和检查点 Hash 字段保留原值。源和采集器 ID 限 80 字节，Geo cacheVersion 限 256 字节。

日志读取支持半行、轮转和截断，按 10 秒/500 行/1MiB 提交，批次与检查点原子发布；不确定时保持 ID 和正文重试。资源采样覆盖写入 `risk:monitor:resource:current:{targetId}`，按周期过期；写入失败仅记录固定诊断，下个周期重新采样。采集器租约失效或续租无法确认时停止提交，由服务管理器重启；普通 Nginx 来源覆盖标记为 UNKNOWN。SSH 只使用本机服务器列表与固定只读命令，严格检查主机密钥，拒绝任意远程命令。

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

新风险 schema/Lua 为本仓库运行资产；Geo schema 依 Java 权威资产同步。离线验证和跨端待验范围见 `docs/verification.md`。
