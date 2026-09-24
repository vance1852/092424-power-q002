# 电厂调度与能源分析与机组分析准入服务

本项目是一套可直接运行的 Python 服务端系统，用于记录电力市场基准电价、电厂与变电站设施、送出线路、燃料批次、发电计划和负荷情景，并保留机组巡检传感器统计分析准入流程。系统面向电价连续波动、关键送电送出线路恢复、电量调度和现场设备验证同时发生的运营环境，让调度、风险和审计人员在同一个 SQLite 数据库中获得可追溯结论。

供应调度子域提供以下能力：

- 电力市场基准电价按结算日和来源修订登记，历史版本不会被覆盖；
- 电厂、储罐、终端与储能站设施建档，送出线路保存日能力、在途时间和损耗规则；
- 送出线路停运或降容事件按 UTC 时间区间生效，日分配会计算实际可用能力；
- 燃料批次保留电源类型、牌号、数量、单位成本和接收时间，可计算加权燃料库存成本；
- 交易方提名支持载荷级幂等、优先级分配、燃料库存扣减和在途交接；
- 负荷情景保存电价变化、送出线路能力变化和需求变化，审批后产生可重放的确定性结果；
- 关键写操作进入哈希串联审计日志，可离线验证事件顺序和内容完整性。

机组分析准入子域位于 `plant_science` 包，负责机组巡检传感器的设备构建登记、不可变校准协议、测点分片导入、异常测点复核、统计任务租约、分析准入决定和审计报告。该子域不连接传感器硬件，只处理已经结构化的校准记录。

## 目录

- `src/power_dispatch/`：电价、设施、送出线路、燃料库存、提名、负荷情景、HTTP API 与离线验收；
- `src/plant_science/`：机组巡检传感器校准与统计分析准入；
- `fixtures/`：机组分析准入演示协议和结构化测点；
- `tests/`：核心规则、错误边界、API 和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 无第三方运行依赖

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试使用内存数据库和临时目录，不访问公网，也不会启动常驻服务。

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m power_dispatch.acceptance --workspace .
```

该命令会在内存数据库中登记六个结算日的峰谷电价，创建电厂、终端和送出线路，完成燃料库存入账、提名分配、送电及负荷情景分析，最后输出一行 JSON。成功时退出码为 `0` 且 `status` 为 `ok`。

机组分析准入子域也保留独立验收入口：

```bash
PYTHONPATH=src python3 -m plant_science.acceptance --workspace .
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m power_dispatch.api --database power_dispatch.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查为 `GET /health`，无需登录。其他所有接口必须携带登录令牌：先由 `POST /auth/login`（提交 `user_id`/`password`）换取令牌，再在请求头携带 `Authorization: Bearer <token>`；自报的 `X-Actor-Id` 不再生效。

账号开通走受保护的身份流程：

1. 首次部署用 `--bootstrap-admin` 离线引导唯一一位管理员（口令经 `--bootstrap-password` 或 `POWER_DISPATCH_ADMIN_PASSWORD` 提供，PBKDF2 加盐存储）：
   ```bash
   PYTHONPATH=src python3 -m power_dispatch.api --database power_dispatch.sqlite3 \
       --bootstrap-admin root --bootstrap-password '强口令'
   ```
2. 只有已启用的 `admin` 角色可以 `POST /users` 邀请账号（须设初始口令），未登录返回 401，非管理员返回 403。邀请支持 `Idempotency-Key` 请求头，重复请求只创建一个账号；同键不同内容返回 409。
3. `POST /users/{id}/role`、`POST /users/{id}/deactivate`、`POST /users/{id}/activate` 仅限管理员，且不能对自己执行；角色变更、停用、重新启用均写入 SHA-256 哈希链审计（`GET /audit/chain` 可校验）。
4. 停用时该用户全部未失效会话立即吊销，旧令牌的下一次请求即返回 401；`POST /auth/logout` 可主动注销。

其余接口覆盖电价、设施、送出线路、停运事件、燃料批次、提名、能力分配、送电、负荷情景和审计链，按 planner/dispatcher/risk/auditor 角色权限放行。服务重启后，SQLite 中的业务状态、账号、会话和历史版本会继续保留。
