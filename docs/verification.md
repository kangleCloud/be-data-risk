# 当前Python风控清理与重建验证（2026-11-02）

范围仅be-data-risk与获分配单写的根docs/risk-v1及风险契约。Java会话已确认Default并正在实施，其本轮新回归、运行测试资源最终核对、统一SQL重建及整体联调待完成，不能据Python通过宣布跨端完成。

## 当前交付

- 删除risk/migrate.py、启动guard/checked_migration/旧布局扫描、源及运行migrate.lua、迁移CLI和专用测试。租约为随机UUID，不再带切换识别前缀。源/Redis启动失败明确非零退出，由CLI单次输出安全错误码；运行中Redis临时故障继续明确记录并重试。
- 配置只保留当前规范：SOURCES为多源数组，单源SOURCE_LOG_PATH与其互斥；PATH_RULES仅pattern/template；JSON当前模型继续支持多源与完整redis/rediss/unix URI。删除RISK_*别名、外置Geo库配置、UNMATCHED路径容忍和未使用增强质量枚举，不增加兼容分支。当前schema边界、源信任、Token/固定目的地/300ms/慢滴保护保持。HMAC依现行约定直接填写，未恢复文件别名。
- 根risk-v1清单按runtime/test分类。runtime为record/envelope schema及lease/publish/heartbeat Lua；6份测试输入在tests/resources。路径fixture仅删分组输入中无用requestType，71份expected输出均与基线原样一致；基本/跨日/Geo fixture字节也保持。UNMATCHED和未使用质量枚举从当前接收schema移除，其余wire、HLL、canonical、checksum及聚合字段不变。
- Java Geo权威源已冻结为runtime/test分组，sync_assets.py只接受此一个当前格式，无flat回退。Python按实际需要派生消费清单：control/result schema用于Python运行，fixtures用于测试；Java最终runtime4/test5清单中control也是运行资源。schema/字典/黄金内容未变，Java权威源未由Python修改。
- tools/rebuild_redis.py默认预览。必须指定与私有配置scheme/主机/端口/DB相符的无凭据--target；执行必须--execute --writers-stopped。只SCAN两固定前缀并有界UNLINK，补扫描确认清空，总扫描上限；不使用FLUSHDB，不输出keys/values/URL。含认证/多义DB/无DB/零端口目标在连接前拒绝，不能被redis-py默认端口回退掩盖。
- README合并当前配置、启动和初始化重建说明；docs只保留此份真实验证。原过程基线/诊断/旧指南先归档/tmp后移出仓库。重建必须先停采集和归档写、重建当前4表及仅两个Redis前缀、保留服务器目标/权限/其他业务/日志/MMDB、先Java后Python，从配置的现有文件头重建，无日志不补造。本仓库只交付工具，不执行实际清理。

## 实际验证与产物

- 本轮完整unittest离线回归175项通过（/tmp/risk-cleanup-tests.log）；新增停写/目标/预览/精确前缀/有界删除/重复执行、当前Collector重建后重启不重复、HLL/24桶正确、startup不做SCAN且新错误不被吞等用例。随后补充工具多义DB与零端口边界，8项工具定向复核通过（/tmp/risk-cleanup-rebuild-tests.log），未因无关Java等待重复全套。
- fakeredis/Lupa实际执行三份当前共享Lua；原Redis失败、结果不确定幂等、半行、轮转、重启检查点等回归继续通过。重建测试只用fake Redis，日志为临时合成文件；断言日志字节及其他namespace保持不变。
- wheel/sdist构建成功，位于/tmp/be-data-risk-cleanup-dist。scripts/verify_package.py在临时目录隔离加载wheel，以外部tests/resources消费全部黄金样例，不依赖父docs。wheel资产集合与源码精确一致，无fixture、文档、迁移模块或管理工具；sdist当前管理工具可交付，纯fixtures仅在tests/resources，risk/assets仅runtime。
- 复用此前已完成的同wire Java实际Service输出/tmp/geo-policy-java-response.json，非本轮Java新运行。当前Producer生成/tmp/risk-cleanup-python-envelope.json，与既有/tmp/geo-policy-python-envelope.json完整字节相同：11条记录、COUNTER/GEO_COUNTER各4请求，含SOURCE/HLL/24桶；HLL与可信规范地址独立计算一致。checksum=b0a35205be16624e1a33a15c97a57b8f1ce587329be723548cb0ff7bcb2c335d。
- compileall、git diff --check通过。当前私有.env逐文件SHA与/tmp基线一致；仅核对键名，未发现待清理的退役键，未输出或改任何值。样例改为当前规范单名，未知字段拒绝，不静默连接其他Redis。

## 文件和行数（本轮基线范围）

运行Python代码1999→1859行（-140），运行资产26→9文件。基线范围删除36个路径、修改21、新增13（测试样例多为从运行区移动，权威源保留）；详单/tmp/risk-cleanup-summary-20261102.json。当前关键文件行数：service.py 322、config.py 182、paths.py 221、protocol.py 118；rebuild_redis.py 118、sync_assets.py 50、verify_package.py 60、test_rebuild.py 110。最终打包重建后若仅工具校验行数变动，以源码及/tmp统计为准。

删除清单：迁移Python/Lua/测试3项及对应包内Lua；旧字段专用测试test_geo_no_policy.py；16份旧docs基线/重复契约/历史验证诊断；运行区纯fixtures/合成响应/协议文档移出，Python未引用Geo字典/schema/sample消费副本移除。没有删除根黄金样例、Java权威字典或当前业务算法。

风险清单已冻结，根与消费副本SHA256=37444ce40ee3d64508c77c918860768239d99c561db589c677b7661c179106f9；Java正在按runtime/test整理消费，其新回归与同步待完成。根schema边界/配置输入整理后，统计golden输出和聚合checksum保持。

保护基线/tmp/risk-cleanup-baseline-20261102.json，执行前归档/tmp/risk-pre-cleanup-20261102.tar.gz（未包含私有.env），当前代码变更与删除可追溯。

未运行现有Redis、MySQL或实际collector；未停/启实际服务、未执行SQL或重置数据、未网络定位/下载库、未提交/部署/Review。独立隔离MySQL实例未提供，因此MySQL真实验收未完成；Java正在实施整体清理/消费同步/统一重建SQL，Java新回归与跨端联调待完成。不得把fake、同wire复用产物或175个Python用例称为本轮Java新验证或生产端到端。

## Java最终分组清单同步

Geo权威源现仅runtime/test格式，源清单SHA256=b26599a183b4ecdd7fbc7f518242e6cabaa9e42d20c69cf099a348cd86b6819d。已按唯一目标格式更新sync_assets.py，开发工具不保留flat回退；runtime/test选中内容与源逐字节一致，运行及测试SHA校验通过。完成定向资产检查、wheel/sdist重建、隔离包验证、脚本语法及diff检查，未重复175全量。风险源清单SHA不变。Java四模块首次编译通过为主控提供状态，本仓不将其计作Python验证；Java本轮实际新Service输出及互验尚待就绪。

## 本轮Java实际新Service输出互验

读取本机合成`/tmp/risk-slim-java-response.json`，使用当前Producer及离线fakeredis stub生成`/tmp/risk-slim-python-envelope.json`，不是复用上一轮响应。Java源文件原文字节未改，各结果按当前schema验证；测试epoch=max(resolvedAt)+1秒，stub只按实际可信公网请求筛选原始行，Producer实际拿到的结果与Java各字段完全一致。非公网/不可信不发起定位查询。

导出11条记录，COUNTER/GEO_COUNTER各4请求。HLL合并寄存器与独立按可信规范IP/同日同key计算一致（生成脚本内断言），SOURCE均为4096寄存器；COUNTER全部24桶、有效耗时数量及整数微秒和一致。完整envelope/canonical/checksum校验通过，checksum=`b0a35205be16624e1a33a15c97a57b8f1ce587329be723548cb0ff7bcb2c335d`。Geo源最终runtime4/test5清单SHA256=c3c00dc21339a959b6a9653559c315c297e9b5e86f43d37191e0736c72b77839，选中schema/fixtures的内容未变。

此次仅离线合成输入消费和文档更新，未发送网络请求、连接现有服务或执行重建，未修改Java响应；未重复175项全套。Java侧新的整体验证仍由Java会话提供，本互验不代表真实MySQL或生产环境验收。
