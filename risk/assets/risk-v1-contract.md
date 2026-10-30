# Risk V1 wire protocol（主控已核对冻结）

当前冻结标识：`risk-v1-20261028-immutable-r1`。存储由旧可变批次简化为日期不可变批次，统一V1；不新增V2或风控手动模式。本版已核对精确键、脚本参数、API、SSE 独立耗时、HALF_UP 微秒转换及模板化隐私边界。实现修复不得自行变更字段或编码；不兼容调整须先由主控同步三个会话。

共同语义以 `risk-v1-implementation-contract.md` 为准。本文件补充精确 wire 结构；禁止自行更名。2026-10-27首期后端基线 SHA：27870eb777ab1dffefcf66d9548850c9c610517c；此为历史依据，不代表当前工作树状态。本轮保留已有修改与私有配置。

## 编码与记录

UTF8 严格 JSON，schemaVersion 为数值 1，其余累计值、微秒、字节、revision 均十进制字符串。耗时Decimal秒乘1000000后HALF_UP四舍五入为整数微秒；负数及非法数字为null并计质量。UUID 小写标准形式。时间 ISO 毫秒 +08:00。canonical 使用 ASCII 转义、字典序键、紧凑分隔、不含浮点；按 kind、recordId 排序，每条含末尾 LF，SHA256 小写 hex。空批次为 sha256(empty)。recordId=SHA256(canonical(dimensions))，不同 kind 的 dimensions 不得完全相同：所有 dimensions 必须另带 `kind` 字段。

COUNTER：`{schemaVersion,kind:"COUNTER",recordId,dimensions:{kind:"COUNTER",businessDate,minuteAt,regionCode,requestType,method,pathTemplate,status},requestCount,bytesSum,bytesValidCount,durationValidCount,durationSumMicros,histogram,upstreamFailureCount}`。histogram 24项，末项 overflow，上界见 fixtures。所有类型均保留合法request_time耗时分桶，SSE记录连接结束的持续时间；REST聚合只选择API，SSE单独计算连接时长P95。
SOURCE：`{schemaVersion,kind:"SOURCE",recordId,dimensions:{kind:"SOURCE",businessDate,regionCode,requestType},registersBase64,keyId}`。HLL p12，4096字节，寄存器0..53，标准base64 padding；只有同日同keyId可merge；绝不加和 cell 估算数。
EXCEPTION：`{schemaVersion,kind:"EXCEPTION",recordId,dimensions:{kind:"EXCEPTION",businessDate,minuteAt,regionCode,requestType,pathTemplate,status,reasonCode},count,firstAt,lastAt}`。
QUALITY：`{schemaVersion,kind:"QUALITY",recordId,dimensions:{kind:"QUALITY",businessDate,regionCode:"UNKNOWN",requestType:"OTHER",reasonCode,sourceId},count}`。不保存原文。UNKNOWN与INTERNAL独立；regionCode省份 CN-xx、国家ISO两位。reasonCode允许：INVALID_JSON、INVALID_TIME、INVALID_NUMBER、UNMATCHED_PATH、UNTRUSTED_IP、GEO_UNAVAILABLE、HTTP_5XX、HTTP_4XX、CLIENT_ABORT、UPSTREAM_FAILURE、SOURCE_TRUNCATED、KEY_UNAVAILABLE。不得存任意异常文本。

## Redis standalone：日期不可变批次

精确键、envelope、Python原子提交、Java读取归档与旧检查点切换，以 [当前实施契约](redis-risk-implementation-contract.md) 为唯一依据。统一 `risk:v1:`，记录 `schemaVersion=1`；不得引用旧全局revision、ACTIVE/SEALED、SEAL/CLEAN协议。当前历史格式仍按上述统计记录定义校验。

- Python有界聚合，最长10秒，最多500条记录且完整envelope不超过1MiB；日期/文件代次切换先提交。
- 批次发布后不可变，检查点与批次/索引同次原子提交；只校验本源租约/检查点/日keyId，无全局revision。
- Java每日北京时间01:00归档昨天及更早批次，启动及每5分钟补跑；先事务落库再核验，最后普通Redis事务精确DEL+SREM。
- Java查询先Redis后MySQL按batchId去重，无查询CAS；索引缺payload需核对MySQL，不能伪造零值。
- 三张MySQL表、唯一批次/记录约束、失败分类、manifest核验及提交后恢复继续保留。manifest的redisKeys只含本次不可变批次精确Key。
- 旧checkpoint原键原值沿用；旧directory/活动批次必须先排空，旧日keyId显式迁移，禁止重头读取或新旧并跑。

## HTTP（实际路由 /admin/api/risk；生产外部 /stock/admin/api/risk）

Controller映射 `/risk`，沿用admin应用已有context-path `/admin/api`，禁止重复前缀。GET dashboard、interfaces/page、exceptions/page、archives/page。CommonResult `{code,success,msg,content}`，分页content `{list,total}`；total沿项目number，业务count一律string。参数 startDate/endDate 缺省各为今日；闭区间最多31天，拒绝未来/逆序；regionCode/requestType可空；pageNum默认1，pageSize默认10最大100。requestType枚举 API/STATIC/PAGE/SSE/RISK_INTERNAL/OTHER。全部需system:risk:view；exceptions还需system:risk:exception:view，archives还需system:risk:archive:view，AND逻辑。dashboard不携带异常/归档详情。

所有dashboard分组先按日期/地域/requestType过滤COUNTER；interfaces默认只API，显式非API筛选返回该类型但SSE行的REST耗时为null，SSE P95独立正常返回。异常同筛选；归档只按日期（region/type不适用，不影响批次信息）。dashboard：

```
{metrics:{requestCount,apiCount,httpErrorCount,httpErrorRate,restP95Micros,restP95Overflow,sseP95Micros,sseP95Overflow,sseEndedCount,clientAbortCount,upstreamFailureCount},
 trend:[{minuteAt,requestCount,apiCount,httpErrorCount}],
 dailySources:[{businessDate,sourceCount,approximate:true}],
 regions:[{regionCode,requestCount}],requestTypes:[{requestType,requestCount}],statuses:[{status,requestCount}],
 topInterfaces:[{pathTemplate,method,requestType,requestCount,httpErrorCount,clientAbortCount,restP95Micros,restP95Overflow,sseP95Micros,sseP95Overflow}],
 quality:[{reasonCode,count}],
 metadata:{generatedAt,dataUpdatedAt,collectorHeartbeatAt,lastEventTime,lagSeconds,completeness,warnings}}
```

clientAbortCount独立统计最终HTTP499；httpErrorCount仅最终HTTP400..599但排除499（304正常），前端Tips明确HTTP错误率不含499，httpErrorRate为十进制字符串（0..1，小数6位）；分母0返回null。REST P95仅API有效耗时，SSE P95只选SSE有效连接时长。普通API行的sseP95Micros为null，SSE行的restP95Micros为null；无样本null，overflow为true时null。dailySources同日所选region/type HLL逐位max。requestCount含所有有效请求类型，sseEndedCount仅SSE结束记录。topInterfaces按requestCount降序、pathTemplate/method升序取前10。interfaces分页同topInterfaces字段。exceptions分页每项 `{id,minuteAt,regionCode,requestType,pathTemplate,status,reasonCode,count,firstAt,lastAt}`，按lastAt倒序；跨批次同维度合并。archives分页每项 `{id,batchId,businessDate,state,recordCount,checksum,committedAt,cleanedAt,failureCode}`，日期/ID倒序。

metadata所有时刻可null，lagSeconds可null否则十进制字符串，按collectorHeartbeatAt到generatedAt的秒差，非lastEventTime。completeness READY/EMPTY/PARTIAL/UNAVAILABLE；禁用/硬失败走失败响应，不返回伪造UNAVAILABLE数据。有效数据且心跳正常READY，无记录且正常心跳EMPTY，缺失心跳或超30秒PARTIAL。warnings固定码 COLLECTOR_OFFLINE/HEARTBEAT_MISSING/GEO_UNAVAILABLE/QUALITY_ISSUES。dataUpdatedAt为最大批次updatedAt（已归档取保存值），lastEventTime独立。quality不受region/type过滤以免掩盖采集失败，仅日期范围过滤。

fixtures文件提供共同规范字节/checksum/HLL/耗时/UNKNOWN/无权限形状，不作为真实采集数据。上线前置沿实施契约，不执行生产迁移或服务连接。

## 协议资产校验

`risk-v1/record.schema.json` 为严格记录形状；schema之外仍校验recordId、canonical字节、分桶和HLL语义。`risk-v1/sha256.json` 记录当前共享源SHA256。Java Jar内 `risk/` 携带同字节Lua/schema/fixtures，测试逐字节核对。Python独立仓库同样携带固定副本；运行时均不读父目录docs。

当前提交、租约、心跳脚本及批次fixtures以 `risk-v1/sha256.json` 固定的共享资产为准，打包副本须逐字节一致。风控Python维护共享写入资产，Java只读统计并在落库核验后用普通Redis事务清理，不执行提交或封存Lua。检查点只有generation/offset，generation不透明、无文件路径，禁止同代offset倒退。

日志时间兼容 `@timestamp` 与 `time_iso8601`，均接受带明确偏移的ISO8601（例如 `2026-10-26T12:00:00+08:00`）。两字段同时存在必须表示同一瞬间；非法或冲突映射固定INVALID_TIME。解析细分失败映射现有固定QUALITY枚举，不添加wire原因码。
