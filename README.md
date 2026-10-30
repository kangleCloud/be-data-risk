# be-data-risk

独立 Python Nginx 只读采集服务：文件增量读取 → Redis `risk:v1:` 日期不可变批次。统一 **V1**，无版本开关、行情式手动采集模式或 HTTP 业务接口。Python 不连接 MySQL，不修改行情任务；Java 负责只读归档和落库核验后的精确清理。

当前冻结标识 **risk-v1-20261028-immutable-r1**。`risk/assets/risk-v1/` 与根共享资产同字节，运行校验 SHA；只读取包内资源，不读取父目录。统计记录字段、历史 fixtures、recordId、HLL、Decimal HALF_UP、直方图和 checksum 保持；pathTemplate 增量支持规范中文与路径隐私 marker。当前实现没有全局 revision、活动/封存批次或 SEAL/CLEAN 脚本。

## 安装和验证

要求 Python >=3.11；实际验证环境 Python 3.14.5。必需依赖 redis/jsonschema，可选 maxminddb；运行和完整测试固定依赖分别为 `requirements-runtime.txt`、`requirements-test.txt`。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q risk tests scripts
.venv/bin/python -m risk --check-file examples/sanitized.jsonl
```

测试以 fakeredis/Lupa 执行同字节共享 Lua，未连接现有服务。构建 `.venv/bin/python -m build`；随后 `.venv/bin/python scripts/verify_package.py` 验证最新 wheel 可脱离父目录运行。发布包版本0.1.1，`schemaVersion`和命名空间始终为1。systemd/Nginx示例没有部署。

## 配置和服务入口

支持显式加载 `.env.dev`、`.env.prod`、`.env` 或原 JSON 配置。按 `be-data-analysis` 的分组风格使用：

```sh
cp .env.example .env.dev
# 编辑 .env.dev，填写日志源、密钥文件及实际 Redis 连接
.venv/bin/python -m risk --config .env.dev
```

`.env.example` 分为 Redis、日志源、隐私、可信代理、文件读取和可选分组。Redis 使用 `REDIS_URL`（仅主机名）、`REDIS_PASSWORD`、`REDIS_PORT`、`REDIS_DB` 分开配置，默认 `localhost:6379/2`；密码由程序自动 URL 编码，可选 `REDIS_USERNAME` 支持 ACL。日志路径默认空，启动前会拒绝空来源，不连接Redis。单源使用 `SOURCE_ID` + `SOURCE_LOG_PATH`，可信代理用逗号分隔的 `TRUSTED_PROXIES`。

只支持单行赋值、注释、单/双引号，不执行shell、不插值、不自动从进程环境覆盖文件；布尔值为 `true/false`。含空格或 `#` 的字符串必须加引号。由 `--config` 选文件，不添加 `APP_ENV`。`.env`/`.env.dev`/`.env.prod`均被Git忽略，不覆盖已有私有文件。迁移工具同样支持 `--config .env.dev`。

原 `RISK_*` 命名和JSON配置继续兼容；需 `rediss://`/`unix://` 或完整URI时使用原 `RISK_REDIS_URL`，不能与分开的 `REDIS_*` 同填。同一项新旧名字冲突时明确拒绝。多源仍可使用 `RISK_SOURCES` JSON数组替代单源路径；高级 `PATH_RULES` 仍用单引号包裹JSON。


复制 `examples/config.example.json` 为 Git 忽略的 `config.local.json`。默认源列表和 Redis 地址为空，不自动连接任何服务器。按已核实的配置填写：

| 配置 | 含义 |
| --- | --- |
| sources | `{alias,path}`；稳定的非敏感别名与实际绝对日志路径 |
| redisUrl | 明确指定单实例 Redis 连接，支持 redis/rediss/unix；与行情键以 namespace 隔离 |
| hmacKeyFile | 本机至少32字节随机密钥文件，读取完整原始字节；不输出/上传/写Redis |
| geoDatabase | 获许可的本地 MaxMind 库；缺失或无法加载返回未知并固定告警，不查询外网 |
| trustedProxies | 经核实的可信代理 CIDR，默认空 |
| directPeerTrusted | 是否明确允许采信 remote_addr，默认false |
| pathRules | 全匹配规则 `{pattern,template,requestType}`，仅可选分组，支持NFC中文且<=512码点；requestType不覆盖固定分类 |
| maxLineBytes | 默认65536；超长行有界内存扫描到LF，只计INVALID_JSON |
| pollMillis | 默认200，允许10..10000；空闲等待还会缩短到缓冲/续租/心跳最近期限 |

源别名只能含字母、数字、下划线、连字符，最长80。所有实例对同一实际源必须用同一别名，不把同一个文件换别名重新采集；配置拒绝重复别名、解析后路径与已存在的同inode文件。不要在模板或别名放私密数据。

```sh
.venv/bin/python -m risk --config config.local.json
.venv/bin/python -m risk --config config.local.json --once
```

正常运行持续采集；已有 `--once` 仅用于本地/隔离验收，处理当前完整行后提交缓冲退出，不创建业务API或jobId。SIGTERM/SIGINT停止读取后尽力提交剩余缓冲，租约或Redis不可用则不冒充成功；以token比较释放lease。Redis暂时不可用保留待提交段重试，其他协议冲突安全停止，不重造批次盲试。

专用用户只读日志；私有配置和密钥仅服务用户可读。模板所有生产用户/目录/配置路径保持占位，需运维核实systemd隔离可见性。未配置密钥时不生成SOURCE，可信IP计KEY_UNAVAILABLE，批次keyId固定unavailable；同日启用/换key将明确冲突，不能静默改变。

## systemd 生产配置

文件：`deploy/systemd/be-data-risk.service`，按所提供的be-data-analysis服务配置生成。项目目录为 `/data/content/be-data-risk`，日志为 `/data/logs/be-data-risk/service.log`；这两个路径按参考目录替换项目名，部署前需在目标机确认。

服务使用root用户、网络就绪后启动、失败5秒重启，SIGTERM停止最多等待60秒。入口为 `.venv/bin/python -m risk --config /data/content/be-data-risk/.env.prod`；本项目通过显式配置文件选生产环境，不设置APP_ENV。保留Python无缓冲输出与统一文件日志。

安装前准备项目 `.venv`/依赖、填写 `.env.prod` 的真实Redis/日志源/密钥路径，并创建可写的 `/data/logs/be-data-risk` 目录；systemd不会替你创建该父目录。源日志只读、私有配置与密钥权限需核实。此文件仅生成，未复制到 `/etc/systemd/system`、未启动或部署；本机没有systemd-analyze，目标Linux上需执行 `systemd-analyze verify deploy/systemd/be-data-risk.service` 核验。

## 不可变发布与恢复

- 每源内存聚合，最长10秒。每批最多500个不同记录、整个canonical envelope最多1048576字节。添加下一行会越界时先发布现有段；单行无法装入则RECORD_TOO_LARGE，停在其之前的持久检查点，不截断或丢行。相同维度在本段精确整数累加/HLL逐位max，不读取旧批次合并。
- 日期或文件代次变化前发布旧段。内存FileTailer游标与已持久化checkpoint分开：崩溃丢弃内存段，从原Redis检查点重读。代次变化单独发布检查点转换，允许0记录空批次，checksum为sha256(empty)。
- 获得源30秒lease，每10秒按token续租。发布Lua只检查本源lease/预期checkpoint/日keyId，不做全局CAS。续租丢失停止提交并丢弃易失游标，其他检查点冲突停源。
- 一个有界publish.lua原子发布String envelope、days/pending索引、日keyId、checkpoint及单调心跳。先验证全部类型/参数再首写，不依赖运行错误回滚。批次SET NX，成功后不修改。原始记录完整语义/canonical/checksum在生产者与Java验证，Lua做有界形状/参数/唯一有序ID检查。
- Redis结果不明保留同Publication（同UUID、字节、参数）。重试发现检查点已经等于目标则ALREADY_COMMITTED，不累加；即使Java已归档删除payload，也不会重建已清理批次。
- `days` Set永久记录日期；`pending:{date}` Set列批次；`batch:{date}:{uuid}` String为完整envelope。checkpoint与日keyId Hash不随归档删除。全部使用risk:v1前缀，无数据TTL，只有lease有TTL，无FLUSHDB/通配删除。
- Java仅在MySQL事务提交和核验后用普通MULTI/EXEC进行精确DEL+SREM；不删days/检查点/日keyId。Python没有归档调度或封存业务。
- generation继续为设备/inode/随机UUID，不含路径；offset为字节十进制字符串。重启可在同目录找回改名旧inode；半行不推进持久位置。截断切代次并计SOURCE_TRUNCATED，轮转残留半行计INVALID_JSON。
- 初次打不开、路径消失、轮转目标不可读明确SOURCE_UNAVAILABLE，旧inode找不到明确CHECKPOINT_FILE_UNAVAILABLE，不继续伪装无流量心跳。可读EOF才可空闲心跳；每10秒发送，lastEventTime与成功发布段原子更新。

copytruncate快速回涨、inode复用、旧文件提前删除/压缩、切换后旧句柄继续写入存在文件系统窗口；需核实logrotate/reopen和保留周期。未做生产吞吐压测，单线程文件IO可能受存储延迟影响；10秒为调度缓冲上限，不是硬实时保证。

## 从原可变布局切换

只有V1，已有 `risk:v1:checkpoints` **原键原值直接复用**，绝不复制到别的版本、清空、重置或从起点读。

1. 停旧Python，等待30秒源lease释放/到期，禁止强删活动lease。
2. 旧Java排空全部旧批次（含当前日切换窗口）；确认directory空且没有旧ACTIVE/孤立meta/records。停旧协议写者，新旧不能混跑。
3. 仅将旧active里的date:keyId显式迁入day-key-ids。工具校验全量源快照、目标冲突及checkpoint原值；Lua只写日keyId，不写检查点，不删除旧数据。
4. 新服务启动遇未排空批次、旧lease或未迁移keyId，明确MIGRATION_REQUIRED，文件尚不读取。正常同实现多实例仍按源lease竞争。无旧数据的新环境可直接启动。

```sh
# 默认只输出数量和DRY_RUN，无Redis写入；必须由运维选定实际连接。
.venv/bin/python -m risk.migrate --config config.local.json
# 仅在停旧写者、旧批次排空和dry-run核验后显式执行：
.venv/bin/python -m risk.migrate --config config.local.json --execute
```

本轮只在fakeredis验证工具和恢复，没有执行任何真实迁移。脚本幂等，仅同值或缺项可通过；目标不同、源变化、租约未退出、旧活动批次仍在时拒绝。

## 隐私和统计

严格UTF8/JSON，不修补非法转义，拒绝重复键/NaN。兼容@timestamp/time_iso8601，同存需同一时刻，统一上海日期。缺失/`-`为未知；非法数字为null且计INVALID_NUMBER，秒到微秒Decimal HALF_UP不经float。

所有合法请求均计数，无需pathRules；普通未知路径保留可区分的脱敏结构，不再归UNMATCHED或报UNMATCHED_PATH。路径先去query/fragment，最多两轮严格百分号解码、NFC；敏感字段值、邮箱/手机/IP/UUID/JWT/长随机串用既有日密钥的独立risk-path-v1用途HMAC脱敏，缺密钥固定marker加KEY_UNAVAILABLE。完整路径最多512 Unicode码点，超长保留脱敏前缀和全路径摘要。旧规则只作可选分组，模板也再次脱敏，不能过滤计数或泄露原值。固定分类优先RISK_INTERNAL→三条已知SSE→STATIC→API→PAGE→OTHER；API自动识别四模块/admin/api、/app/api、/openapi/api、/scheduler/api及/stock部署前缀，并覆盖现有Python /internal路由；不合规路径用固定安全路径且仍计数。历史UNMATCHED仍可读取。没有可信规则时IP未知；可信链从右往左判断，不信任假代理头。IP只在内存用于日HMAC/p12 HLL及离线地域，内网INTERNAL，无库/无条目UNKNOWN。

不持久化Token/Cookie/Authorization/密码/请求体/查询参数/Referer/完整UA/IP/原异常正文。坏行只输出固定原因、源别名、代次、首偏移与该段数量。Redis只存schema聚合，无逐请求明细。304正常，499单列；最终HTTP错误与上游失败尝试分别计。SSE使用日志结束时间与连接持续时间独立分布，不推断在线人数/消息量。来源仅同日同keyId合并HLL，不能加和单元估算或跨日union。

`examples/nginx-risk.conf.example` 使用escape=json并保留真实路径占位；Nginx本地日志本身仍受服务器原权限/保留策略管理。验证及未实测边界见 `docs/verification.md`。

2026-10-30路径增量：精确算法和66个跨语言样例在包内 `risk/assets/risk-v1/{protocol.md,path-fixtures.json}`。启发式无法识别任意伪装成普通文字的秘密，不宣称绝对隐私保证。Java须先支持新路径schema/Unicode/canonical样例，再允许实际接入；本轮仅离线，不启动实际collector。
