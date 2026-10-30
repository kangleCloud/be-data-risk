# 2026-10-28 V1不可变批次本轮验证

需求：根 `docs/redis-risk-implementation-contract.md` 与 `docs/risk-v1-contract.md`；共享标识risk-v1-20261028-immutable-r1。本轮基线 `immutable-baseline.json` 已记录已有文件SHA/状态，保护此前所有业务修改；只修改本仓库和授权独占的根risk-v1共享资产，没有改Java、行情Python、Vue或私有配置。无提交、部署、SQL、现有服务访问或Review。

## 当前结果

- `.venv/bin/python -m unittest discover -s tests -q`：**118 tests，本轮完整运行全部通过**。这是当前新实现测试数量，不是沿用旧报告的93项。
- `.venv/bin/python -m compileall -q risk tests scripts`：通过。
- fakeredis 2.40.0/Lupa 2.8实际执行publish/lease/heartbeat/migrate原始共享Lua，非Python重写脚本结果；Python 3.14.5，redis6.4.0/jsonschema4.26.0/maxminddb3.2.0，项目`.venv`。
- `python -m risk --config ... --once`与SIGTERM服务入口在fake连接下执行，退出提交剩余缓冲，释放所属lease；异常日志不暴露原值。
- 显式迁移工具默认dry-run无写入、execute仅复制旧日keyId、原checkpoint DUMP字节未变、重复执行幂等、源变化/目标冲突/旧批次/旧lease拒绝；恢复实测从旧文件offset只读剩余一行，未从头重计。没有执行真实迁移。

## 覆盖范围

10秒截止与空闲等待不越过期限；500不同记录真实边界、完整1MiB真实编码边界、单行超限停在持久检查点之前；内存游标与持久checkpoint分离、同维度段内累加；日期切换与文件代次先提交旧段；空代次转换批次。

崩溃未发布段重读、已发布重启不重计、失败保留同UUID/字节、丢响应确认ALREADY_COMMITTED、Java普通事务清理后丢响应不重建payload；lease竞争/续租失败/所属释放、checkpoint冲突停源、同日日keyId冲突、独立源互不使用全局revision。

Lua在首写前拒绝错误末尾键类型、错误键名、后续非法记录、错误数量/顺序/重复ID、空对象冒充数组、超500条/1MiB、额外envelope/检查点字段、offset前导零/倒退、租约丢失、日keyId与批次冲突。未归档数据无TTL，只有lease TTL；不创建旧revision/active/directory，未写行情键。

严格JSON/隐私/数值未知/时间兼容、原HLL/hash/分桶/canonical/checksum统计fixture保留；新增同日迟到/次日/重复来源合并/质量/空批次共享fixture。半行、轮转、截断、源不可读不发健康空态心跳的回归均保留。

## 临时跨语言产物

`/tmp/risk-v1-immutable-python-export.json`：真实Collector+FileTailer+fakeredis/Lupa产生4个不可变批次（同日首次、同日迟到、次日、轮转空批次），记录数14/4/2/0，各自canonical、count、checksum已重新读取验证；原首次批次字节保持不变。文件标fixture，无原始日志、IP或密钥。

手工预期与产物核对：请求10、API6、499为1、HTTP错误1、上游失败尝试2；REST P95桶上界50000微秒、SSE P95桶上界120000000微秒；INVALID_JSON=1；2026-10-27来源并集3（两批2和3不能加成5），2026-10-28来源1，跨日独立。包含API200/502/499、STATIC304、SSE200的60/61秒、RISK_INTERNAL、非法JSON。供Java/H2消费，不声称已由本Python会话验证数据库事务。

## 打包与交付检查

- `PYTHONPATH=/opt/homebrew/lib/python3.14/site-packages .venv/bin/python -m build --no-isolation`：成功生成 `dist/be_data_risk-0.1.1.tar.gz` 和 `dist/be_data_risk-0.1.1-py3-none-any.whl`；使用此前已存在的本机setuptools/wheel构建工具，没有下载新依赖。
- `.venv/bin/python scripts/verify_package.py`：临时目录解包、`-I`隔离路径下校验包内SHA、原统计fixture、新envelope fixture、CLI入口，脱离父目录运行通过。
- wheel内容核对：包含当前publish/migrate/lease/heartbeat及schema/SHA同字节副本；无旧mutate.lua。构建前清理本项目生成的build缓存，避免已删除脚本被误带入。
- 根共享目录与包资源文件集合和逐字节/SHA校验全部通过；原record.schema.json与risk-v1-fixtures.json的SHA与本轮执行前基线相同。
- 共享SHA清单文件自身SHA256：`c1149a9c5bce3bc76279e4176aaaf5a7733c384a87829cbeeaf235db6d4c5a67`。
- `git diff --check`通过；因仓库仍是新文件未提交，额外扫描全部待跟踪文本尾随空白通过。
- 全源码/资源/脚本/测试/文档命名空间检索通过：统一V1，无并行版本资产、版本开关或风控手动业务。运行只读包内资产。

## 未实测

未连接真实Redis Server/主从故障转移/持久化/内存压力，fakeredis不能替代线上验收。没有Python端MySQL依赖；Java事务回滚/提交后中断/清理失败/并发归档/Redis-DB查询过渡由Java验收。本轮未替代其测试结果。

真实Nginx版本/日志路径/代理链/轮转、服务器权限/systemd、地域库内容与许可、生产吞吐仍未核实。copytruncate快速回涨、inode复用、旧文件提前删除压缩、切换后旧句柄写入有文件系统窗口；旧inode找不到会失败，不能静默忽略。单线程IO受宿主机存储延迟影响，10秒是缓冲调度期限，不是硬实时系统。
