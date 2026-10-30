# risk-v1-20261028-immutable-r1 共享存储协议

根 Redis/风控优化实施契约是需求门槛。记录沿用 v1，不修改 HTTP 或 MySQL schema。本目录由风控 Python 单一维护，Java 同字节复制；本目录 sha256.json 是发布资产校验表（不包含自身）。只有单实例 Redis，不支持跨槽 Cluster。无全局 revision、活动/封存状态或 Java 写脚本。

## 精确键

`risk:v1:days` Set 永久日期目录；`risk:v1:pending:{YYYY-MM-DD}` Set 待归档小写 UUID；`risk:v1:batch:{YYYY-MM-DD}:{uuid}` String 不可变 envelope。`risk:v1:checkpoints` Hash 为 sourceId -> canonical `{generation,offset}`；`risk:v1:day-key-ids` Hash 为日期 -> keyId。`risk:v1:lease:{sourceId}` String 随机 token，唯一有 TTL 的数据键（30000 ms）。`risk:v1:heartbeat` Hash 为 collectorHeartbeatAt/lastEventTime，ISO 毫秒 +08:00 且单调。

sourceId、keyId 均 `[A-Za-z0-9_-]{1,80}`。generation 为 `[A-Za-z0-9_.:-]{1,128}`，不含路径；offset 为无前导零的非负十进制字符串，最长20位。同代次偏移不得倒退。Python generation 继续使用 device:inode:UUID，迁移保留原值，不重建。

## envelope

精确字段为 `schemaVersion`（数值1）、`batchId`、`businessDate`、`keyId`、`createdAt`、`recordCount`（十进制字符串）、`checksum`（小写 SHA256）、`records`（对象数组）。按 kind/recordId 升序排序 records；每条保持 v1 canonical，checksum 对这些记录加末尾 LF 计算。整个 envelope 排序键、ASCII 转义、紧凑 JSON、无 float。最多1048576个 UTF8字节、最多500个不同记录，允许0条（空 checksum=SHA256(empty)，用于只有代次变化的连续区间）。记录日期必须等于 envelope 日期；SOURCE keyId 必须等于 envelope keyId。字段和语义由 envelope.schema.json、record.schema.json 及消费者共同验证。

每批只对应一个源的一段连续检查点；源/起止检查点只出现在原子调用参数，不加入 envelope 字段。缓冲每源最多10秒；在添加下一行会超500条或1MiB前先提交当前段，再处理该行。日期或代次切换前提交旧段。单行自身聚合不能装入时固定 RECORD_TOO_LARGE，保留持久检查点不丢行。内存读取游标不能冒充持久检查点。

## publish.lua

KEYS固定7项：days、该日pending、该日该批batch、checkpoints、day-key-ids、该源lease、heartbeat。

ARGV固定9项：batchId、businessDate、sourceId、leaseToken、expectedCheckpoint（缺失空串）、newCheckpoint、完整canonical envelope、now、lastEventTime（该段无有效事件为空串）。now 和非空lastEventTime必须 ISO毫秒+08:00；envelope.createdAt=now。一个已冻结待提交段重试必须保留全部参数及同批ID/字节；Java可在返回前已归档并清理，恢复不能依赖payload仍存在。

顺序：完整验证参数、键名/类型、envelope边界及基本结构、租约、检查点及日keyId后，再 SET NX batch、SADD days/pending、HSET day-key/checkpoint、单调心跳。Lua是隔离执行，不假设运行错误回滚；所有可能类型/参数拒绝必须先于首写。recordId/checksum/canonical字节的完整密码学/shape校验由生产者和Java完成，Lua验证尺寸、计数、唯一有序ID、记录日期/种类/schemaVersion及SOURCE keyId，不实现另一套SHA256。

返回值：`OK`、`ALREADY_COMMITTED`、`INVALID_ARGUMENT`、`WRONG_TYPE`、`LEASE_LOST`、`CHECKPOINT_CONFLICT`、`KEY_ID_CONFLICT`、`BATCH_CONFLICT`。本源checkpoint已等于newCheckpoint返回ALREADY_COMMITTED（若残存payload不等于重试字节则BATCH_CONFLICT）；不会重建被Java清理的payload/index。其他检查点冲突停止该源，不重试另造批次。新发布若batchKey已存在而checkpoint尚未提交，拒绝BATCH_CONFLICT，不覆盖。正常OK的所有数据与checkpoint原子可见。索引与未归档payload/checkpoint无TTL，日keyId归档不删除。

lease.lua：KEYS本源lease，ARGV operation(RENEW/RELEASE)、sourceId、token、固定30000；获取用SET NX PX30000，续租每10秒，校验token后续期/释放。返回OK/INVALID_ARGUMENT/WRONG_TYPE/LEASE_LOST。续租失败停止提交并丢弃只在内存的段，从持久检查点恢复。

heartbeat.lua：KEYS仅heartbeat，ARGV now,lastEventTime（可空），返回OK/INVALID_ARGUMENT/WRONG_TYPE，两个时刻单调更新。publish本身同样更新时刻，空闲仍10秒心跳。

## 切换和迁移

只有V1，不存在版本开关/双写/运行回退/手动业务。旧 Java 先排空 directory 指向的全部旧批次（含当前日），停旧 Python 并等待源租约退出。原 risk:v1:checkpoints 和 risk:v1:lease:{sourceId}/heartbeat 原位复用，不复制、不重置检查点。旧 batch:{uuid}:meta/records 与新 batch:{date}:{uuid} 不冲突；启动时旧directory/ACTIVE/孤立旧batch未清空一律 MIGRATION_REQUIRED。

原active的date:keyId必须显式迁入day-key-ids，后者同日保持稳定，不自动从头读或覆盖。`python -m risk.migrate --config PRIVATE` 默认dry-run；仅 `--execute` 调用 migrate.lua。KEYS固定四项：checkpoints、active、directory、day-key-ids。ARGV为canonical计划 `{checkpoints:{source:exactValue},dayKeyIds:{date:keyId}}`，检查点仅用于原值快照校验，脚本绝不写它。检查directory为空、active只有date:keyId、源检查点/日keyId仍与计划一致、目标无冲突后，仅HSET缺失/同值日keyId。返回OK/INVALID_ARGUMENT/WRONG_TYPE/MIGRATION_REQUIRED/MIGRATION_SOURCE_CHANGED/MIGRATION_CONFLICT。执行前后工具还检查旧batch与租约；必须停旧写者，这不是在线迁移锁。

新采集器的随机lease token以immutable-前缀标记本实现（非模式开关）；旧无前缀token存在时阻止启动。迁移工具要求所有源lease退出；新采集器之间正常按源竞争lease。共享脚本接受任意非空owner token，前缀只用于本实现的离线切换识别，不改变键或请求协议。

Java归档只读批次，事务提交并核验后MULTI/EXEC执行DEL精确batch、SREM该date pending；不删days/checkpoints/day-key-ids。不用封存或Redis归档锁。查询按batchId跨Redis/DB去重并核对count/checksum；pending有ID而payload缺失时需DB确认，不能静默漏计。

## 路径增量契约 risk-path-v1-20261030-r1

本段取代旧“未知路径UNMATCHED”的生产规则，不改字段名pathTemplate/记录schemaVersion/批次协议/HTTP。所有JSON合法、时间合法的请求（含404）必须计数，pathRules不存在或不匹配都不能过滤。旧UNMATCHED/UNMATCHED_PATH只兼容历史；新普通未知路径保留可区分的脱敏结构，不生成UNMATCHED_PATH。

### 规范化和不合规输入（先于规则）

1. uri必须是以`/`开头的Unicode字符串。原输入严格UTF8不超过16384字节；拒绝未配对surrogate。先截去原始字符串中最早的`?`或`#`及之后内容，保留路径。输入上限在截query前检查，超限不持久化原值。
2. 百分号严格解码最多2轮：每轮每个`%`必须紧跟2个ASCII hex；将百分号字节及其他字符UTF8字节合并，以严格UTF8解码，不将`+`改空格。结果仍含`%`时进行第二轮，第二轮后还含任何`%`一律不合规（包含需第三轮解码和编码的字面百分号）。每轮UTF8长度仍不得超过16384。解码出的`/`成为分段界限。原始及每轮字符均拒绝Unicode类别Cc/Cf/Cs/Zl/Zp，禁止控制/双向与隐藏格式字符。
3. Unicode NFC（不做NFKC/大小写折叠），再次截最早`?/#`，折叠连续`/`，保留单个末尾`/`。不解析`.`/`..`、不改变普通大小写。拒绝反斜杠、ASCII尖括号/双引号/反引号以及原始大括号`{}`（防伪造脱敏marker）。其他可见Unicode标量包括中文/emoji允许；不从字符串中提取主机或访问外部服务。
4. 不合规/缺失uri统一输出`/__invalid_path__`、OTHER、质量UNMATCHED_PATH；仍有COUNTER。不输出不合规输入的HMAC或原片段。正常未知路径没有质量故障。

### 分段敏感检测（顺序固定）

分隔符为规范化后的`/`。敏感字段集合（ASCII部分按lowercase匹配、中文原字）为password/passwd/pwd/token/access_token/refresh_token/secret/authorization/cookie/密码/令牌。

- 一个segment完全等于敏感字段时，保留字段名；紧随的非空segment整体为敏感值，替换，不再解析其结构。
- segment中以`=`或`:`分隔时，以这些字符的首次出现拆成field/value；field在集合中时保留field+分隔符，value整体替换（空值也替换）。其他位置匹配以下启发式时，整个segment替换。
- 邮箱：segment任意位置匹配`[^/\s@]+@[^/\s@]+\.[^/\s@]+`（Unicode空白语义）；手机号：任意位置匹配ASCII数字串、两端不能相邻ASCII数字，值为可选`+86`/`86`后`1[3-9][0-9]{9}`；UUID：任意位置ASCII hex的8-4-4-4-12，不要求版本位；JWT：任意位置三个以`.`分隔且各至少8位的`[A-Za-z0-9_-]`片段。
- 保持原不持久化完整IP的边界：整个segment为合法IPv4/IPv6（可带一对方括号），或首次`=`后的完整值为合法IP时，整个segment摘要化；仅做字面IP解析，不查询DNS。
- 长随机串：segment任意位置存在连续至少24个`[A-Za-z0-9_-]`，且该串同时含ASCII字母和数字，或该串本身是至少24位hex（全数字也算）。不按熵/语言猜测；不满足hex条件的纯长英文、纯中文不因此认定随机。启发式命中时摘要整个segment，不保留邮箱/号码等局部文本。

### 摘要与长度

使用现有日密钥，但独立用途：`HMAC-SHA256(key, UTF8("risk-path-v1\n" + businessDate + "\nsegment\n" + NFC(normalizedValue)))`，输出完整64位小写hex。`segment`是ASCII字面量，不是路径位置；value是被替换值的完整规范化字符串，不trim/不改大小写。marker为`{redacted:<hex>}`。无密钥为固定`{redacted}`，计一次KEY_UNAVAILABLE（与来源HLL缺key原因去重），不得回退明文。普通无需摘要的路径不因路径功能缺key而告警。

脱敏后路径最多512 Unicode码点（不是UTF16长度/UTF8字节）。超长时输出：脱敏路径的前`512 - suffix码点数`个码点 + `/{path:<hex>}`；摘要输入改为`"risk-path-v1\n" + businessDate + "\npath\n" + redactedFullPath`（截短前已经逐段脱敏的完整规范路径，含首尾slash与marker，不含query/fragment；不使用原始秘密）。无密钥suffix为`/{path:redacted}`并KEY_UNAVAILABLE。截取前缀仅来自已经脱敏的结果；如果切点落在本实现生成的`{redacted...}`marker内部，退到该marker开头再加suffix，允许结果少于512。不得在marker中间留下半个摘要。全路径HMAC也仅保留64hex，不落原长路径。

### 旧规则和分类

分类看规范化原路径、先于可选分组，大小写敏感且路径边界必须`/`或末尾：

1. RISK_INTERNAL：`/admin/api/risk`、`/stock/admin/api/risk`及其后续路径。
2. SSE：三条精确基路由`/market/dashboard/stream`、`/stock-monitor/v1/stream`、`/etf-monitor/v1/stream`；各允许无前缀、`/openapi/api`、`/stock/openapi/api`三种部署形式。不靠后缀stream/SSE字样猜测。
3. STATIC：`/assets`、`/static`及其子路径，或最后segment后缀忽略大小写为css/js/mjs/map/png/jpg/jpeg/gif/svg/ico/webp/avif/woff/woff2/ttf/eot/txt/xml/pdf/mp4/webm。
4. API：`/api`、`/admin/api`、`/app/api`、`/openapi/api`、`/scheduler/api`及`/stock`加这些前缀；或`/internal`、`/market`、`/stock-monitor`、`/etf-monitor`及子路径。`/internal`来自实际Python jobs/stock-monitor/etf-monitor路由，仅分类现有请求，不新增接口或业务模式。
5. PAGE：`/`、末尾`/`、末segment无`.`、或后缀html/htm；其余OTHER。

可选pathRules只作静态模板分组：只匹配已规范化路径、从不丢弃请求，旧requestType配置字段保留可读但不参与上述分类。RISK_INTERNAL/SSE不分组；原路径发生敏感替换或长度缩减时也不分组。普通路径按配置顺序首个fullmatch取静态template（不展开捕获组）；template最多512码点，可含规范中文及完整占位符`{[A-Za-z_][A-Za-z0-9_]*}`，只能是整个segment。template本身再次按相同隐私流程规范化/敏感检测，完整占位符作为受信静态片段保留；字段后的占位符仍按敏感值摘要。配置模板含query/fragment/百分号、非法字符或需缩短时拒绝配置；不能用规则原文绕过脱敏。历史template=UNMATCHED只视为不分组。

持久化接收端：pathTemplate允许旧UNMATCHED或`/`开头、NFC、<=512码点的可见Unicode路径（控制类别、反斜杠、尖括号、双引号、反引号、query/fragment/百分号禁用）；大括号只能是上述完整占位符或合法redacted/path marker，不接受散落大括号。其他维度保持原严格ASCII/枚举约束。启发式不能识别任意伪装成普通文字的秘密，不宣称绝对保证。Java必须先支持本段schema/Unicode/canonical字节与集中path-fixtures.json，再真实接入；本轮仅离线。
