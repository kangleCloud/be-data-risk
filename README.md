# be-data-risk

Python 只读采集 Nginx JSON 日志，仅统计 API，按分钟/方法/脱敏路径/可信规范 IP/HTTP 状态合并次数，地域国家、省、市快照与次数在同一行。Java 负责 Geo 定位、持续入库与查询，Python 不加载 MMDB、不直连 MySQL。当前协议见工作区根 `docs/risk-v1-contract.md`，schemaVersion=1。

## 配置与启动

要求 Python >=3.11；Debian Python3.13 先安装对应 `python3.13-venv`。

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-runtime.txt
cp .env.example .env.prod
.venv/bin/python -m risk --config .env.prod
```

填写实际日志路径、Redis、信任规则和 Geo 后再启动。私有文件被 Git 忽略；不提交真实值。`--config` 显式选择文件，不读取进程环境覆盖，不执行 shell 或展开变量。`.env` 支持单行赋值、注释、单/双引号，含空格或 `#` 需加引号；布尔值用 true/false。`examples/config.example.json` 为同一当前配置模型。未知字段、重复键及冲突配置拒绝。

| 字段 | 用途 |
|---|---|
| REDIS_URL/PORT/DB/USERNAME/PASSWORD | 主机名及连接项；密码自动 URL 编码，与 Java 同实例同 DB |
| SOURCE_ID/SOURCE_LOG_PATH | 稳定源别名与实际日志绝对路径 |
| SOURCES | 多源 JSON 数组，每项 alias/path；与单源 SOURCE_LOG_PATH 互斥 |
| GEO_SERVICE_URL/GEO_SERVICE_TOKEN | 固定 Java Geo endpoint 与专用令牌；URL 留空仅用有效共享缓存，失败 UNKNOWN 照计 |
| TRUSTED_PROXIES/DIRECT_PEER_TRUSTED | 可信代理 CIDR 或已由 Nginx 规范化的来源信任 |
| MAX_LINE_BYTES/POLL_MILLIS | 默认单行65536字节、空闲轮询200毫秒 |
| PATH_RULES | 可选分组 JSON，仅 pattern/template，不能绕过脱敏或改变分类 |

```dotenv
SOURCES='[{"alias":"first","path":"/path/to/access.log"},{"alias":"second","path":"/path/to/other.log"}]'
PATH_RULES='[{"pattern":"/api/items/[0-9]+","template":"/api/items/{id}"}]'
```

日密钥配置已退出；本机旧私有值只注释保留，不参与运行。路径敏感段使用固定占位。systemd 模板为 `deploy/systemd/be-data-risk.service`；日志目录和服务安装由运维处理。`--once` 排空当前完整行并提交后退出；`--check-file` 仅离线校验合成样本，不写持久检查点。

## Geo 与来源信任

Geo 部署于 vita-scheduler，当前端口19004，服务器以实际 vita.http-port 为准。完整同机 endpoint 示例：

```dotenv
GEO_SERVICE_URL=http://127.0.0.1:19004/scheduler/api/internal/risk/geo/resolve-batch
GEO_SERVICE_TOKEN='仅在私有文件填写专用令牌'
```

令牌对应 Java `vita.risk.geo.internal-token`，只经 X-Risk-Geo-Token 发到配置的固定地址。URL 必须 HTTP/HTTPS、固定 IP 字面量、上述完整路径（允许 `/stock` 前缀），无凭据/query/fragment；禁止重定向与环境代理。服务器端校验令牌，不按客户端转发头选择目标。

客户端→雷池HTTPS443→本机Nginx HTTP18080→Spring Boot 的拓扑，按 `examples/nginx-waf-realip.conf.example` 核实 RealIP，并记录 `$remote_addr`。Nginx 已规范化来源时设置 DIRECT_PEER_TRUSTED=true、TRUSTED_PROXIES 留空；Python 不再从任意客户端 XFF 提取地址。其他拓扑使用明确可信代理 CIDR。IPv4-mapped IPv6 统一为 IPv4，未知来源写 null。

先过滤页面、静态和已知 SSE，再按最多100条预取调用 Geo。风控管理和内部 Geo 接口也计数；内部 Geo 接口本身不再发起 Geo 查询，以避免递归调用。非公网 INTERNAL、不可信 UNKNOWN 不进入定位请求。短 Redis 客户端与 Java 同实例同 DB；整体300ms包含缓存、内部 HTTP 与 best-effort 失败指标。保留版本绑定、令牌、单在途 worker、绝对截止与迟到结果隔离。定位失败仍计 API 次数，不清除同自然维度已获得的有效地域快照。

## 批次与检查点

Envelope 只有 schemaVersion、batchId、businessDate、createdAt、records；所有行显式提供 minuteAt、method、pathTemplate、sourceIp、httpStatus、requestCount、regionCode、countryCode、provinceCode、provinceName、cityCode、cityName。未知地域为 null，状态未知为0；2xx/3xx成功，4xx/5xx失败（包括499），0/1xx为 other。requestCount 为正十进制字符串，最大9223372036854775807，溢出拒绝整批。

同批自然维度合并；10秒/500行/1MiB提交，跨日/轮转先提交。所有 JSON、字段、规范 IP、日期、路径、Geo、整数与大小在发布前校验。Lua 在写入前校验键类型、租约、检查点和结构，再原子写 payload/pending/days/checkpoint/heartbeat。只有租约有 TTL，未入库批次及检查点没有 TTL。提交结果不确定时保留原 ID 和正文重试，Java 消费清理后重试不会重建批次。

读取游标可以在内存前进，持久检查点只随成功原子发布前进。过滤或坏日志可发布空 records 以推进检查点；诊断只输出固定原因与数量，不保存原日志。半行不推进；保留轮转、代次与租约冲突保护。启动不做全库盘点；可恢复 Redis 运行故障记录后重试。

路径去 query/fragment、严格 UTF8、最多两轮解码、NFC、最多512 Unicode码点，敏感字段及可识别敏感值替换为固定占位，普通 IP/省市/ISP 保留。未命中规则的 API 仍计数。不保存查询参数、请求体、Authorization、Cookie 或完整 UA。

## 切换与精确统计清理

本轮只交付脚本，不实际执行。停止 Python 采集与 Java 风控入库写者后，使用现有私有配置，并给出无凭据且 scheme/主机/端口/DB 一致的明确目标。默认预览：

```sh
.venv/bin/python tools/rebuild_redis.py --config /path/to/.env.prod --target 'redis://HOST:6379/2'
```

显式停写确认后执行：

```sh
.venv/bin/python tools/rebuild_redis.py --config /path/to/.env.prod --target 'redis://HOST:6379/2' --execute --writers-stopped
```

仅处理 `risk:v1:days`、`risk:v1:day-key-ids`、合法日期的 `pending:{date}`、合法日期/UUID 的 `batch:{date}:{UUID}` 和 `risk:v1:query:*`。保留 checkpoints、lease、heartbeat、全部 Geo 缓存/指标、服务器配置及其他业务。不删除整个 namespace，不修改日志或 MMDB；统计清空后从保留的检查点继续，不重读历史。数据库建表/旧表清理由 Java 的脚本单独负责。

SCAN/UNLINK 有界，默认每批100、最多1000；默认总扫描上限10000、最多100000。执行后补扫描直至目标统计键为空；达到上限或连接失败返回错误，可能已删部分需保持停写后复查。输出只有模式、模式匹配范围与数量，不输出键名、值、目标或凭据。

## 离线验证与资产

根 `docs/risk-v1/` 为风险 wire 权威，sha256.json 区分 runtime/test。Java 独占接口响应样例 java-service-response.json，不进入 Python 运行包。Geo 权威由 Java 维护；Python 只复制实际消费的 control/result schema，测试只投影定位输入，不携带无关旧统计记录。`scripts/sync_assets.py` 核对源 SHA 后生成副本。

```sh
.venv/bin/python scripts/sync_assets.py
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m compileall -q risk scripts tools tests
.venv/bin/python scripts/export_fixture.py /tmp/risk-minute-python-envelope.json
.venv/bin/python -m build --no-isolation --outdir /tmp/be-data-risk-minute-dist
.venv/bin/python scripts/verify_package.py /tmp/be-data-risk-minute-dist/be_data_risk-0.1.1-py3-none-any.whl
```

wheel 仅带运行代码与 schema/Lua，不带文档、测试、fixture、工具。sdist 带当前测试及默认预览工具。实际验证与未验范围集中在 `docs/verification.md`。
