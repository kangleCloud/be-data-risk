# 当前 API 分钟统计验证

以下为历史验证记录；资源持久化、待处理队列和缺口状态已由 Redis 最新值契约取代，独立连接测试功能已移除。当前行为以本文件最后一节和根共享契约为准。

2026-11-06 用户要求取消后端接口的监控过滤。风控管理接口和内部 Geo 接口均纳入 API 计数；内部 Geo 请求本身不发起 Geo 查询，防止递归。页面、静态资源和已知 SSE 仍过滤。本次完整离线测试 121 项通过；此前下列 2026-11-03 测试数量和样例指标仅对应当时结果，当前样例已重新生成。根共享契约中的原排除规则待主控同步更新。

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

## 2026-11-16 V2 首期 Python 采集端离线验证

本轮按根 `docs/risk-monitor-v1-contract.md` 在 `be-data-risk` 内实施 V2 首期 Python 侧；未修改根 docs、其他仓库、私有 `.env`、密钥、凭证或 known_hosts，未连接网络、真实 Redis/MySQL/SSH，未部署或清理线上数据。

### 实际覆盖

- V2 全 HTTP：API/PAGE/STATIC/OTHER、SSE 归 OTHER、内部 Geo 不递归、`sourceId`/`targetId`/`requestType`、V2 键、500行/1MiB/V2 发布校验与 V1 共用租约/检查点。
- 切换：V1 pending 非空时停写退出；排空后 V2 从原检查点续读，不重读旧行；失败不删除 V1 pending、批次或检查点；旧/新生产者不能并行持同一 source 租约。
- 配置：空 Hash 有效；十进制版本单调；同版本不同正文冲突；非法/Redis 不可用保留最近配置并标 stale；热加载在本地源映射变化时先 flush 再安全重启。
- 资源：本机/远程探针注入；首次 CPU/网络、计数器回退、机器重启均为 null 加固定原因；同 ID 同正文原子写入幂等、不同正文冲突、无 TTL；Redis 不可用保留样本 ID/正文且不补造期间周期。
- SSH/连接测试：允许列表整体匹配、固定主机公钥、密钥缺失/权限/hashed/wildcard/指纹异常失败；固定参数和常量命令、超时/输出上限/非零退出明确失败；异步截止、TIMED_OUT 不被迟到成功覆盖、结果 5 分钟过期、配置版本绑定、结果不可覆盖和不确定正文重试。
- 入口：设置 `COLLECTOR_ID` 自动进入 monitor；未设置保持 V1；`--monitor --once` 可在离线 fake Redis 下结束。

### 命令与结果

- `.venv/bin/python -m unittest discover -s tests`：**157 项通过**。
- `.venv/bin/python -m compileall -q risk`：通过。
- `git diff --check`：通过。
- `scripts/export_fixture.py` 仍可用合成日志驱动实际 V1 Collector/RedisStore/Lua 生成样例。
- 已用 `/tmp/risk-v2-dist` 构建 wheel/sdist，并由 `scripts/verify_package.py` 验证 wheel 运行资产、当前 V1 样例、schema SHA 与 CLI；该构建目录和日志在 `/tmp`，不进入仓库。

### 待协调

未冻结的错误码、`unavailableReasons`、资源数值精度、SSH 允许列表 JSON、LOCAL 连接测试语义、Python 配置过期/资源缺口上报键、V2 清理方案和交付确认语义仍待主控协调，详见 `docs/risk-monitor-python.md`。本仓库只提出本地实现与合成样例，不自行改变跨端协议。

## 2026-11-17 V2 接管与离线核查

Codex 经用户授权接管余额不足的 OpenCode 会话 `ses_e1c706381ffe6hOGKof1c6lWTJ`，保留原分支和全部未提交修改。Redis 配置 Hash 缺失或空 payload 不再被当成有效空配置；只有带版本的完整空 targets 快照有效，配置回退和同版本不同内容继续拒绝。

资源采样使用有界工作线程，不在日志、配置与连接测试轮询线程等待慢 SSH；受限线程池不会因已超时但仍在运行的连接任务不断扩大队列。资源发布失败保留原 ID/正文并有界退避，Redis 故障恢复诊断带可能的缺口起点与恢复时间。连接测试派发前和完成时核对配置版本、目标启用及采集器归属。LOCAL 目标允许只采集资源，不绑定日志源。

资源 `unavailableReasons` 按根契约为分组到固定原因码的对象；`examples/risk-monitor.samples.json` 已同步。CPU 总计不重复累计 guest 时间，本机根分区已用字节采用 `f_bfree`。合成日志通过实际 Collector、Lua 与 fake Redis 生成 `/tmp/risk-monitor-producer.json`，含 API/PAGE/STATIC/OTHER 四种类别及首次采样的资源对象；此文件供 Java 实际解析验证，不代表已完成跨端联调。

本轮最后一次完整离线测试 166 项通过（`/tmp/risk-codex-test.log`）；compileall、git diff --check、无网络构建与隔离 wheel 检查通过。测试使用 fake Redis、模拟进程和临时合成文件；未连接现有 Redis/MySQL/Nginx/SSH、未部署、未提交。具体连接测试 failureCode、Python 状态/缺口向 Java 的交付键、旧 pending 数据跨进程切换和生产运维步骤仍需主控与 Java 协调及隔离联调，stderr 诊断不等同管理端状态交付。

## 2026-11-17 单一协议及无版本键

用户更正后只保留 schemaVersion=2 的访问、监控配置、资源和连接测试运行逻辑；Geo HTTP 语义维持 Java 所需的既有格式。固定 Redis 键去除版本命名空间，Geo 控制、结果和指标同步为 `geoip:control`、`geoip:result:*`、`geoip:metrics:*`。旧批次不消费、不双写，日志读取仍使用目标映射与原子检查点。动态 ID 和 cacheVersion 不静默改写，动态值中若含 v1/v2 将原样出现在 key 中。

旧统计允许清除，但旧检查点和配置默认受保护。切换操作草案：停止旧生产者和消费者；人工核实 Redis 目标；执行 `tools/rebuild_redis.py` 只读预览；对比旧 `risk:v1:checkpoints` 与新 `risk:checkpoints`，若存在同源不同值冲突则停止，不能覆盖；经人工审批后对缺失源逐项迁移，已存在且相同的检查点保持不变；迁移中断应可重复核对，旧检查点保留。旧统计清理按预览范围另外确认，Geo 和旧配置不默认删除。迁移和清理必须在隔离环境验证、经授权后另行执行，本次脚本没有执行入口，未连接生产 Redis。

本轮全量离线测试 152 项通过，覆盖无版本固定键、全 HTTP、配置 schemaVersion=2、资源对象与连接测试、临时 fake Redis 原子发布、轮转和幂等；`/tmp/risk-unversioned-producer.json` 由真实 Collector 和合成日志产出。Python syntax、wheel 隔离验证及 diff 检查结果以交付报告为准；Java 实际消费与生产迁移未验。本节之前的 V1/V2 并行验证记录为历史结果，不代表当前运行方式。

## 2026-11-17 Redis 自由文本键段编码

按根契约，sourceId、collectorId 和 Geo cacheVersion 进入 Redis key 前转换为 UTF-8 字节的大写十六进制；原始身份仍写入 envelope、资源/连接测试报文和检查点 Hash 字段。日志租约与资源发布 Lua 独立按原始入参生成同一键段并验证，固定日期、UUID、数值和 IP 不编码。来源及采集器身份最大 80 字节，Python 当前要求 Geo cacheVersion 最大 256 字节；该上限须与 Java 协调统一。

新增 4 项离线测试，覆盖 v1/v2 身份、中文 cacheVersion、长度边界、Lua 拒绝未编码键及业务身份不变。本轮完整回归 156 项通过，语法、wheel 隔离及 diff 检查通过；重新生成 `/tmp/risk-unversioned-producer.json`。Java 实际解析及生产 Geo 缓存切换未验，不将 fake Redis 成功当作跨端验收。本节之前“动态值原样出现在 key”仅为历史状态。

## 2026-11-19 单协议清理复核

运行入口、发布和聚合仅保留当前协议；移除无效的排空等待参数、测试中未使用的旧采集实例和双轨命名。当前资源位于 `risk/assets/risk`、`risk/assets/monitor`，测试样例为 `examples/risk-monitor.samples.json`。保留仍使用的 Geo 资源、真实接口路径及只读迁移预览中的旧键；本文件此前记录的旧入口和历史发布方式仅作为历史记录。

Python 离线 unittest 156 项通过，compileall 和 diff 检查通过；使用本机已有 setuptools 构建 wheel 和 sdist，wheel 隔离资产、schema、样例和 CLI 检查通过。实际 Collector、Lua 和 fake Redis 产生的 `/tmp/risk-unversioned-producer.json` 含 3 批、17 次合成请求，SHA-256 为 `53a2b2bb2da346fcc260dbcd99d6e37d0760e81a9ba758354546b98c1c385830`，与 Java 测试资源字节一致。Java 的实际 Mapper/H2 导入该样例测试曾运行 1 项通过；随后另一组 Java 测试在 testCompile 阶段因其他测试所需包不可用而失败，Java 工作树仍在并行开发，后续须由 Java 会话在隔离环境重跑。生产 Redis、MySQL、SSH、迁移和部署均未操作。

具体连接测试失败码、配置过期与采集缺口向 Java 的状态交付、旧检查点迁移及生产切换仍须跨端协调或隔离联调；stderr 诊断不是管理端状态交付，也不能将本机 H2 测试视作完整联调验收。

## 2026-11-19 采集器状态与所有权离线验证

按根共享契约增加采集器 Redis 租约及递增 epoch、每 10 秒续租与状态刷新，状态和日志、资源、连接结果实际发布由 Lua 原子校验租约。状态区分已应用与已观察配置版本，报告可能交付缺口；多目标还有待交付项时不提前标记恢复。普通日志来源只给出 UNKNOWN/null 覆盖。失租或续租结果无法确认时停止提交，资源 SSH 在途结果不能越过 Lua 栅栏。

Python 离线 unittest 166 项通过，含真实 fake Redis/Lua 的采集器竞争、epoch 栅栏、旧采集器日志/资源/连接结果拒绝、配置失效上报及多目标缺口恢复；compileall、diff 检查、wheel/sdist 构建和 wheel 隔离验证通过。状态样例由 `scripts/export_collector_status.py` 驱动真实 MonitorRuntime 及 fake Redis 导出至 `/tmp/risk-collector-status.json`，包含 Java 快照形状及 UNKNOWN 水位；访问批次样例 `/tmp/risk-unversioned-producer.json` 由实际 Collector 导出。请 Java 会话在其隔离环境消费该状态样例并验证状态过期；本轮未运行 Java Maven，不能将 Python 校验称作完整跨端验收。

Redis 断开期间不能即时上报状态，续租无法确认时进程停止，进程或 Redis 丢失后的未知缺口不能恢复为完整历史。未连接生产环境，未部署、提交或执行生产迁移与清理。

## 2026-11-19 Redis 资源最新值

按最新根契约，资源仅覆盖写入 `risk:monitor:resource:current:{targetId}`；Lua 同时校验采集器租约、epoch 和当前配置版本，以 Redis TIME 写入 `writtenAtMillis` 并按周期设置 TTL。移除资源 sampleId、pending 集合、回执、样本重试、退役样本及资源缺口状态；资源写入失败只输出固定诊断，下一周期重新采样。采集器状态保留配置及来源覆盖，普通 Nginx 水位仍为 UNKNOWN。旧有日志检查点与批次回执保护保留。

离线 unittest 165 项通过，覆盖最新值覆盖和过期、采集器失租、配置版本失效、旧在途结果丢弃、单目标写入失败不阻塞其他目标及下周期重新采样；compileall、diff 检查、wheel/sdist 构建和 wheel 隔离验证通过。真实 ResourceScheduler 与 fake Redis/Lua 产物为 `/tmp/risk-resource-current.json`；实际 MonitorRuntime 状态为 `/tmp/risk-collector-status.json`。Java 旧状态校验器曾要求资源缺口字段，需由 Java 会话同步移除并消费新样例；Python 离线通过不能替代跨端验收。本轮未运行 Java Maven，未连接或更改生产环境，未提交或部署。

## 2026-11-19 移除独立连接测试

移除采集器的独立连接测试命令消费、结果发布、对应 schema/Lua、示例与专用测试；不影响 LOCAL/REMOTE 资源采集。SSH 执行器仅接受固定资源探测命令，允许列表、密钥权限、known_hosts、主机公钥、超时和输出上限校验继续保留。历史记录中有关连接测试的描述不再代表当前功能。

离线 unittest 156 项通过；compileall、diff 检查、wheel/sdist 构建和 wheel 隔离验证通过。另检查 wheel 与 sdist 均不含已移除的连接测试模块和协议资源。未使用真实 SSH、Redis 或生产数据，未提交、部署或修改已有暂存内容。

## 2026-11-19 本机环境配置远程服务器

远程服务器的主机、端口、账号和密码由私有 `.env` 的 `SSH_SERVERS` 列表提供，不再读取 SSH 绑定 JSON。Python 按主机、端口和账号匹配 Java 下发的监控目标；密码只通过文件描述符交给本机 `sshpass`，不写入命令参数、Redis 或诊断。继续使用服务用户 `known_hosts` 强制校验远程主机公钥；首次使用需运维核实公钥并安装 `sshpass`。现有 Java 目标协议仍含不存密码的 `credentialAlias`，Python 不再按该别名匹配。

本机离线测试验证列表解析、敏感信息不出现在对象表示和错误信息、密码文件描述符传递、固定命令、主机密钥校验选项及超时/输出上限；未连接真实远程 SSH，目标环境的 `sshpass` 与主机密钥需部署时确认。
