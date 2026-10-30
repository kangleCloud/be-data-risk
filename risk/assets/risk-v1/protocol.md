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
