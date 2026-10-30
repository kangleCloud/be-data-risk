# 2026-10-30 路径计数与隐私增量验证

范围：仅be-data-risk及授权独占的根docs/risk-v1共享资产。执行前工作树干净；源/资源/测试/示例SHA及私有值摘要基线见 `path-baseline-20261030.json`（不记录私有值正文）。未改Java、行情Python或Vue，未提交/部署/SQL/Review，未连接现有Redis/MySQL/Nginx，也没有启动实际collector。

## 当前验证

- `.venv/bin/python -m unittest discover -s tests -q`：**132 tests，本轮完整运行通过**，其中集中路径fixture有66个subcase。未把历史118项当成本轮结果。
- `.venv/bin/python -m compileall -q risk tests scripts`：通过。
- 新旧fixture实际由 `Draft202012Validator + FormatChecker` 验证：旧统计记录1、新路径记录66、不可变批次中的记录10，合计 **77份记录全部通过**；`check_schema`通过。额外正反例检查中文/emoji的512码点、合法marker/占位符、错误大小写hex、短摘要、散落大括号、控制字符、requestType/method/regionCode/status大小写。NFC及完整marker位置边界仍另做语义验证，不能仅靠JSON Schema推断。
- 本轮无pathRules的Collector+fakeredis/Lupa回归：新API/404/中文/编码/动态路径/三条SSE的9种部署形式/风控自身全部计数，敏感值不出现在事件、聚合、Redis envelope或诊断日志。
- 路径新规则覆盖敏感字段及中文字段、邮箱/手机号/IP/UUID/JWT/24字符随机边界、现有日key独立HMAC、两轮解码/NFC、无key安全marker、Unicode/非BMP码点上限、超长HMAC使用截短前已逐段脱敏路径、禁止截断marker；旧分组模板再次脱敏且不覆盖固定分类，不展开捕获组。
- 来源可信代理、离线地域/HLL、10秒/500记录/真实1MiB、原子checkpoint、租约、半行/轮转/重启/丢响应/归档清理后恢复、迁移dry-run与原位续读测试继续通过；未改这些运行协议。
- `.venv/bin/python -m risk --check-file examples/sanitized.jsonl`：accepted=2，仅UNTRUSTED_IP=2；不再将普通未知路径记UNMATCHED_PATH。

## 共享资产与冻结后变化

路径语义位于根 `docs/risk-v1/protocol.md` 的 `risk-path-v1-20261030-r1` 节；pathTemplate字段/schemaVersion=1/批次键和其他维度不变，历史UNMATCHED仍可读。record.schema增量允许NFC中文及marker并限制512码点；其他维度仍严格ASCII/枚举。schema按冻结语义收紧marker字面量与C1控制字符，并非另选路径规则。

集中 `path-fixtures.json` 从首次报告57增加为59（补充IPv4/IPv6字面量保护），再按主控许可增加7份实际入口兼容样例到 **66**：/app/api、/scheduler/api及/stock形式，以及本项目实际/internal jobs/stock-monitor/etf-monitor接口。原三条SSE、其余已冻语义不扩展。源路由核对来自4模块application.yml与行情Python APIRouter，只读未改其他仓库。

最终SHA256：

| 文件 | SHA256 |
| --- | --- |
| path-fixtures.json | 99599afbf58de6ac0cc7c6360a7a68bfee562873ad4d8e1dfafc43218dfc4cc7 |
| sha256.json自身 | 8ec5e67800a9dfdaff0c4b3ea373a16b6a8596757318672e665e7b829e67fe91 |

Java需按最终同字节资产验证Unicode码点/canonical/recordId/checksum，支持新路径后才允许实际接入。样例输入与key均为明确合成，不使用真实秘密；输出counter、recordId与checksum由真实Python生产者路径构造。

## 打包与检查

根共享资产与包内资源文件集合/字节/SHA、语法、git diff-check均通过；新增文本尾随空白扫描通过。既有发布/checkpoint/lease/迁移/算法文件SHA与执行前基线一致，私有值摘要未变。

`PYTHONPATH=/opt/homebrew/lib/python3.14/site-packages .venv/bin/python -m build --no-isolation --outdir /tmp/risk-path-20261030-dist` 成功生成sdist与wheel，未下载依赖、未覆盖原dist包。`.venv/bin/python scripts/verify_package.py /tmp/risk-path-20261030-dist/be_data_risk-0.1.1-py3-none-any.whl`通过：无父目录docs的临时目录、`-I`隔离路径、包内SHA、新旧fixture/schema/checksum及CLI入口验证成功。

## 未真实验收项

未访问真实Redis Server/MySQL/H2/Nginx/地域库，不替代Java归档事务和跨语言验收；fake Redis/Lupa仅证明隔离原始Lua回归。没修改服务器Nginx，示例保留现有escape=json+$uri，只补字段与源日志隐私说明；不存在需要删除的白名单map。

未做生产吞吐/服务器权限/真实日志轮转/systemd验收；copytruncate等既有文件系统窗口不变。启发式无法识别任意伪装成普通文字的秘密，不作绝对保证。主控须在Java支持最终schema/fixture后再安排实际接入。
