# 2026-10-27 完整离线验证

范围仅 `be-data-risk`。无其他仓库业务修改，无提交、部署、生产 Redis/MySQL/Nginx 访问。执行前规则 SHA 与原工作树见 baseline.json；其他开发会话同期会改动其负责仓库，不能把其变化归入本项目。

## 环境与依赖

Python 3.14.5，项目 `.venv`。实际安装 redis 6.4.0、fakeredis 2.40.0、Lupa 2.8、jsonschema 4.26.0、maxminddb 3.2.0；完整固定版本见 requirements-test.txt。fakeredis 是内存实例，通过 Lupa 执行原始共享 Lua，不是生产 Redis、也不是以 Python 仿写 Lua 结果。

构建工具 setuptools 下载两次遭遇 TLS 失败；最终从本机已有 `/opt/homebrew/lib/python3.14/site-packages` 提供 setuptools/wheel，以项目 `.venv` Python 成功构建。没有为此降级 TLS 或修改系统环境。

## 通过结果

- `.venv/bin/python -m unittest discover -s tests -q`：**93 tests 全部通过**。
- `.venv/bin/python -m compileall -q risk tests scripts`：通过。
- `.venv/bin/python -m risk --check-file examples/sanitized.jsonl`：accepted=2，UNMATCHED_PATH=2、UNTRUSTED_IP=2；符合未配置模板及信任规则的真实默认语义，不是实测流量。
- `PYTHONPATH=/opt/homebrew/lib/python3.14/site-packages .venv/bin/python -m build --no-isolation`：sdist + wheel 成功。
- `.venv/bin/python scripts/verify_package.py`：在临时目录解包 wheel，使用 `-I` 隔离工作目录，验证 SHA、fixtures checksum 和 `python -m risk` 对应入口；无父目录 docs，运行通过。
- 项目内共享资产与根 docs 逐字节比较：通过。运行时只读取项目包资产，不读取根 docs。最后同步根契约关于“可共用实例、namespace隔离”的说明，未变更任何协议字段或脚本。
- `git diff --check` 与全项目文本尾随空白扫描：通过。仓库为全新未提交文件，额外扫描补充 diff-check 对 untracked 文件的覆盖空白。

## 覆盖的行为

严格JSON/非法转义/重复键/数字字符串/Decimal HALF_UP、别名时间冲突、受控模板/内置风控路径优先、未知来源/假代理、隐私持久化检查、离线地域适配器、共享HMAC hash/HLL合并/Base64/桶边界/P95/canonical字节及checksum。

真实共享 Lua 下的 APPEND 与 checkpoint 原子更新；错误键类型、后续非法 replacement、错误/倒退 checkpoint、超过500条输入、源lease丢失、日keyId变更、revision竞争、禁止替换行情键等全部在写前拒绝。

Redis故障前不推进、提交后响应丢失重试及重启不重计、同源双读防护、lease更换、其他来源并发累加重算、SEAL穿插APPEND、迟到新批次、CLEAN后checkpoint与日keyId保留、同日连续最小行段跨日期偏移顺序。

半行与重启、重命名轮转与重启按inode找回、截断切代次/固定质量、大行固定质量；初次打不开、路径在预检后消失、运行中路径消失、新轮转目标不可读均不更新健康心跳；正常可读EOF刷新心跳且不伪造lastEventTime。

服务 `run(..., once=True)`、`python -m risk` 对应 main 配置模式、空闲heartbeat不变统计revision、heartbeat时间不倒退、新事件不等待10秒才更新lastEventTime、可选地域库不可用时UNKNOWN回退、SIGTERM优雅关闭/lease释放/信号处理恢复、私有错误固定停止码。

## 实测边界

未连接真实 Redis Server，未验证 Redis 持久化/故障转移/服务器内存压力；fakeredis/Lupa 不能替代上线真实Redis验收。Python不负责MySQL归档，因此测试只模拟Java SEAL/CLEAN协议，不声称验证MySQL事务、DDL或真实跨服务归档。没有运行Java构建或真实前端联调。

真实服务器权限、Nginx版本/escape=json可用性、真实日志路径/可信代理链/轮转策略、地域数据库内容及许可、systemd部署均未提供或未实测。离线Geo适配器测试使用受控返回值，没有把它当实际地域库结果。

copytruncate快速回涨、inode复用、轮转旧文件提前删除和切换后旧句柄继续写入仍有文件系统窗口；旧inode缺失时明确失败，不静默跳过。每条完整行一次有界APPEND，尚未做高吞吐压测。lastEventTime由提交后的独立heartbeat维护，提交后进程立刻崩溃可能暂缺最后事件时刻；采集健康度始终依据collectorHeartbeatAt，而非lastEventTime。
