# be-data-risk

Python只读采集 Nginx JSON 日志，按当前 schemaVersion=1 将聚合批次原子写入 Redis。Java 负责 Geo 离线查询与 typed 归档；Python不加载MMDB、不直连MySQL。跨语言算法、HLL、24桶、整数微秒、canonical/checksum保持。

## 配置和启动

要求 Python >=3.11。Debian 使用 Python3.13 时先安装对应 `python3.13-venv`，再创建虚拟环境。

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-runtime.txt
cp .env.example .env.prod
.venv/bin/python -m risk --config .env.prod
```

编辑私有配置后再启动；私有文件被Git忽略，不提交真实值。`--config`显式选文件，不读取进程环境覆盖，不执行shell或展开变量。`--once`只处理当前完整行并退出，末段仍提交；`--check-file`仅校验指定合成样本，不产生持久检查点。生产systemd模板见 `deploy/systemd/be-data-risk.service`，安装/启动及日志目录由运维核实，本仓不自动操作服务。

`.env`只支持单行赋值、注释、单/双引号；含空格或`#`应加引号，布尔值用true/false。当前字段见`.env.example`：

| 字段 | 用途 |
|---|---|
| REDIS_URL/PORT/DB/USERNAME/PASSWORD | 主机名及连接项；密码自动URL编码，必须与Java风控同实例同DB |
| SOURCE_ID/SOURCE_LOG_PATH | 稳定源别名及实际日志绝对路径 |
| SOURCES | 多日志源JSON数组，每项alias/path；替代单源SOURCE_LOG_PATH，不能同填 |
| HMAC_KEY | 至少32 UTF8字节的随机文本，直接写私有文件；同日保持不变，不作hex/base64解码 |
| GEO_SERVICE_URL/GEO_SERVICE_TOKEN | 固定Java Geo地址及必填专用令牌；URL留空则仅用有效共享缓存，失败UNKNOWN照计 |
| TRUSTED_PROXIES/DIRECT_PEER_TRUSTED | 可信代理CIDR或已由Nginx规范化的直连来源信任 |
| MAX_LINE_BYTES/POLL_MILLIS | 默认65536字节、200毫秒 |
| PATH_RULES | 可选分组JSON数组，仅pattern/template，不能覆盖自动分类或绕过脱敏 |

多源示例（只展示结构，替换实际路径）：

```dotenv
SOURCES='[{"alias":"nginx_access","path":"/path/to/access.log"},{"alias":"other_access","path":"/path/to/other.log"}]'
PATH_RULES='[{"pattern":"/api/items/[0-9]+","template":"/api/items/{id}"}]'
```

也支持`examples/config.example.json`当前配置模型；`sources`支持多源，`redisUrl`可使用完整redis/rediss/unix URI。未知字段与重复/冲突赋值直接拒绝，不自动回退其他Redis或忽略错误字段。HMAC未填时不生成SOURCE，可信请求计KEY_UNAVAILABLE；同日日密钥冲突明确停止。

## Geo 和 Nginx 来源

接口部署于`vita-scheduler`；当前本机端口19004，服务器以实际`vita.http-port`为准。同机直连示例：

```dotenv
GEO_SERVICE_URL=http://127.0.0.1:19004/scheduler/api/internal/risk/geo/resolve-batch
GEO_SERVICE_TOKEN='在私有文件填专用随机令牌'
```

令牌对应Java的`vita.risk.geo.internal-token`，通过X-Risk-Geo-Token发送，服务端空/缺失/错误令牌拒绝，正确令牌不限制来源或转发头。URL只来自运维配置，允许固定公网IP，仍限定HTTP/HTTPS、IP字面量、精确Geo endpoint（部署有`/stock`前缀时加该前缀）、无URL凭据/query/fragment；禁重定向和环境代理，不从日志/响应中选择目的地。

来源链：客户端→雷池HTTPS443→本机Nginx HTTP18080→Spring Boot。按`examples/nginx-waf-realip.conf.example`核实RealIP指令，继续记录`$remote_addr`。Nginx已规范化真实IP时`DIRECT_PEER_TRUSTED=true`、`TRUSTED_PROXIES=`，Python不再从不可信XFF提取。其他部署需按实际代理链配置，不可全信任客户端转发头。样例不自动修改Nginx。

每最多100条完整日志预取后规范去重，短Redis客户端与Java同实例同DB，整体300ms涵盖cache/内部HTTP/best-effort metrics。control/cacheVersion/providerSetVersion按当前schema校验，过期/故障内部补查，失败UNKNOWN不丢请求。非公网INTERNAL、不可信UNKNOWN，不进入定位查询。单一在途worker，慢滴有绝对截止，迟到结果不会改已聚合记录。

## 统计和持久检查点

每有效请求各生成一份COUNTER与GEO_COUNTER，可按完全相同维度聚合，禁止相加当总量。GEO只透传Java已验证字段；非CN城市字段为空。HLL只合并同日同keyId寄存器，不加和各单元估算。SSE按日志结束时间计连接持续时长，不推断在线人数/消息量。最终HTTP状态与上游失败尝试分别统计。

读取游标可在内存前进，持久检查点只随原子批次发布前进；10秒/500记录/1MiB限制，日切/轮转前提交。结果不确定时重试同ID同正文；半行不推进，租约/检查点冲突停止对应源。正常启动不扫描全库布局；源或Redis启动失败非零退出，运行中的可恢复Redis故障明确记录并重试。

路径严格UTF8、最多两轮解码、NFC、512码点上限；敏感标签/密码/Token/身份证等定向脱敏，保留普通IP、省市和ISP。不保存完整请求明细、查询参数、请求体、Authorization/Cookie/完整UA或异常原文。所有合法请求都计数，无规则也保留规范路径；不合规路径固定安全值并计质量。

## 初始化和从日志头重建

重建脚本只交付，不由本任务执行。先明确数据库和Redis实例，停止风控采集与归档写入；Java重建当前统计、异常、归档和路径字典表，保留服务器目标配置、权限及其他业务。Java开发会话正在实施合一SQL/清理工具，其新回归待完成，本Python工具只清Redis。

使用现有私有配置，给出**无凭据**且scheme/主机/端口/DB与其一致的显式目标。默认预览：

```sh
.venv/bin/python tools/rebuild_redis.py --config /path/to/.env.prod --target 'redis://HOST:6379/2'
```

确认采集和归档写均已停、目标无误后，才显式执行：

```sh
.venv/bin/python tools/rebuild_redis.py --config /path/to/.env.prod --target 'redis://HOST:6379/2' --execute --writers-stopped
```

工具只SCAN并分批UNLINK `risk:v1:*`、`geoip:v1:*`，包括检查点；禁止FLUSHDB，不碰其他namespace。`--batch-size`默认100、最大1000，`--max-scan-calls`默认10000，总扫描达上限或Redis故障明确失败，可能已完成的删除不回滚，保持停写后可重新预览和执行。执行后补扫描直到为空；预览scanEntries是扫描条目数，SCAN可能重复，不承诺唯一键精确计数。日志只输出模式/前缀/数量，不输出键名、值、URL或凭据。

再按先Java、后Python启动。清检查点后FileTailer从**当前配置的现有日志文件头**读取，新代次不改日志；不存在的历史文件不补造。重启根据已发布检查点继续，已计请求不重复。原始日志/MMDB不修改。本仓库从未对现有Redis或MySQL执行重建。

## 权威资产与验证

工作区根`docs/risk-v1/`及两个基础黄金样例是唯一风险权威源，`sha256.json`区分runtime/test；Geo源由Java维护。`scripts/sync_assets.py`只按实际消费需要复制：运行包为schema+三份Lua，测试输入放`tests/resources`并核对SHA。Python不携带无用的Geo字典，不修改Java源。发行wheel不带fixtures、文档或重建工具；源码sdist含测试资源及当前重建脚本，纯fixtures只在tests目录。

```sh
.venv/bin/python scripts/sync_assets.py
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m build --no-isolation --outdir /tmp/be-data-risk-dist
.venv/bin/python scripts/verify_package.py /tmp/be-data-risk-dist/be_data_risk-0.1.1-py3-none-any.whl
```

当前真实验证与未验项集中在`docs/verification.md`。不把fake验证、复用Java合成响应或Python打包通过称为生产/真实MySQL验收。
