# 后端 API 说明

所有接口挂在 `/api` 前缀下，请求和响应均为 JSON（pcap 上传除外）。
本文档与 `app/api/routes.py` 保持同步，修改路由时请一并更新。

## 约定

### 待实现模块的响应

抓包、离线分析等模块尚未实现，对应接口统一返回 `501`，
响应体带结构化错误信息，前端据此渲染"模块待实现"提示：

```json
{
  "detail": {
    "code": "not_implemented",
    "module": "live_capture",
    "message": "实时抓包模块尚未实现，暂时无法列出网卡"
  }
}
```

其他错误（参数校验、上游服务失败等）沿用 FastAPI 默认的
`{"detail": "..."}` 格式，状态码为 400 / 404 / 502 等。

### 模块名

`module` 字段与 `/api/status` 返回的模块键一致：
`database`、`rule_engine`、`risk_score`、`behavior_detector`、
`packet_parser`、`live_capture`、`pcap_analyzer`、`ai_analyzer`、`ai_report`。

## 接口总览

| 方法 | 路径 | 说明 | 状态 |
| --- | --- | --- | --- |
| GET | `/api/status` | 服务与模块状态 | 可用 |
| GET | `/api/config` | 读取运行配置 | 可用 |
| POST | `/api/config` | 保存运行配置 | 可用 |
| POST | `/api/llm/models` | 拉取大模型列表 | 可用 |
| POST | `/api/llm/test` | 测试大模型连通 | 可用 |
| GET | `/api/capture/interfaces` | 列出可监听网卡 | 待实现 |
| POST | `/api/capture/start` | 启动抓包任务 | 待实现 |
| POST | `/api/capture/stop` | 停止抓包任务 | 待实现 |
| POST | `/api/pcap/analyze` | 上传并分析 pcap | 待实现 |
| GET | `/api/reports` | 报告列表（可筛选） | 可用 |
| GET | `/api/reports/{report_id}` | 报告详情 | 可用 |
| POST | `/api/reports/generate` | 生成评测报告 | 可用 |
| POST | `/api/tasks` | 创建分析任务 | 可用 |
| GET | `/api/tasks` | 任务列表 | 可用 |
| PATCH | `/api/tasks/{task_id}` | 更新任务 | 可用 |
| POST | `/api/alerts` | 写入告警 | 可用 |
| GET | `/api/alerts` | 告警列表（可筛选） | 可用 |
| GET | `/api/alerts/{alert_id}` | 告警详情 | 可用 |
| GET | `/api/stats` | 统计汇总 | 可用 |
| POST | `/api/dev/reset-database` | 清空测试数据 | 可用 |

## 状态与配置

### GET /api/status

返回服务信息、各模块就绪情况和大模型配置摘要。WebUI 每 15 秒轮询一次。
模块就绪情况按实现文件是否存在自动检测，新模块落地后无需修改此接口。

```json
{
  "status": "ok",
  "service": "ai-ids-infra",
  "version": "0.1.0",
  "server": { "configured_port": 8000 },
  "modules": {
    "database": { "ready": true },
    "rule_engine": { "ready": true, "rule_count": 33, "rule_files": 6 },
    "risk_score": { "ready": true },
    "live_capture": { "ready": false, "reason": "实时抓包模块尚未实现" }
  },
  "llm": {
    "base_url": "https://api.example.com/v1",
    "model": "some-model",
    "temperature": 0.2,
    "has_api_key": true
  }
}
```

### GET /api/config

返回运行配置。访问密钥不回传原文，只回传 `has_api_key`。

```json
{
  "server": { "port": 8000 },
  "llm": {
    "base_url": "https://api.example.com/v1",
    "model": "some-model",
    "temperature": 0.2,
    "has_api_key": true
  }
}
```

### POST /api/config

保存运行配置，字段全部可选，只更新传入的项。配置存在 SQLite 的
`settings` 表里，不使用 .env 或其他配置文件。

- `llm.api_key` 传空或缺省时保留已保存的密钥。
- `server.port` 修改后需重启服务进程才会生效。

```json
{
  "server": { "port": 8080 },
  "llm": {
    "base_url": "https://api.example.com/v1",
    "api_key": "sk-...",
    "model": "some-model",
    "temperature": 0.2
  }
}
```

响应与 `GET /api/config` 相同。

### POST /api/llm/models

按 OpenAI 兼容协议请求 `{base_url}/models`，返回模型 ID 列表。
`api_key` 留空且 `base_url` 与已保存配置一致时，使用已保存的密钥。

```json
{ "base_url": "https://api.example.com/v1", "api_key": "" }
```

```json
{ "models": ["model-a", "model-b"] }
```

上游服务不可达或返回错误时响应 `502`，`detail` 为可读的错误说明。

### POST /api/llm/test

向所选模型发送一条测试消息（`{base_url}/chat/completions`），
返回回复内容和耗时，用于确认接入参数可用。

```json
{
  "base_url": "https://api.example.com/v1",
  "api_key": "",
  "model": "some-model",
  "temperature": 0.2
}
```

```json
{ "message": "……", "elapsed_ms": 832.5 }
```

## 实时抓包（待实现）

模块文件：`app/capture/live_capture.py`。以下接口目前均返回 501。

### GET /api/capture/interfaces

列出本机可监听的网卡。预期响应：

```json
{ "interfaces": [{ "name": "eth0", "description": "..." }] }
```

### POST /api/capture/start

启动抓包任务，创建 `capture` 类型的分析任务并返回任务信息。

```json
{
  "interface": "eth0",
  "target_type": "ip",
  "target": "192.168.1.10",
  "port": 80
}
```

`target_type` 取值 `ip` 或 `domain`，域名会先解析为 IP 再过滤流量。

### POST /api/capture/stop

```json
{ "task_id": 3 }
```

## pcap 离线分析（待实现）

模块文件：`app/capture/pcap_analyzer.py`。

### POST /api/pcap/analyze

以 `multipart/form-data` 上传 pcap 文件（字段名 `file`），
创建 `pcap` 类型的分析任务，解析 HTTP 请求并执行规则检测。
预期响应包含任务 ID 与解析统计。目前返回 501。

## AI 辅助研判

模块文件：`app/ai/request_analyzer.py`。规则检测评分为 20 至 69 分时自动调用；
AI 判定恶意才生成告警，判定正常仍保留研判记录，调用失败或输出非法时记录为待人工复核。
行为检测告警和 70 分以上的规则告警不调用 AI。

### GET /api/ai/reviews

查询 AI 研判记录，按创建时间倒序。查询参数（均可选）：`task_id`、`status`、
`judgement`、`limit`（默认 100，最大 500）、`offset`。

`judgement` 为 `malicious`、`benign` 或 `manual_review`；调用失败时 `status`
为 `pending_review`，并在 `reason` 中保存失败原因。

### GET /api/ai/reviews/{review_id}

查询单条研判详情，包含请求摘要、原始评分、命中规则、AI 结论、攻击类型、
置信度、理由及关联告警 ID。记录不存在时返回 404。

## AI 评测报告

模块文件：`app/ai/report_generator.py`。生成报告前需在系统配置页
保存大模型接入参数（服务地址、访问密钥、模型），否则返回 400。

### GET /api/reports

历史报告列表，按创建时间倒序。查询参数（均可选）：`task_id`、
`limit`（默认 100，最大 500）、`offset`。

```json
{
  "items": [
    {
      "id": 1,
      "task_id": 3,
      "status": "done",
      "model": "some-model",
      "prompt_version": "v1",
      "summary": "本次任务共分析 86 条 HTTP 请求，生成 12 条告警。",
      "risk_assessment": "告警集中在 SQL 注入和敏感文件探测，整体风险等级为 high。",
      "key_findings": ["192.168.1.20 在短时间内多次访问敏感路径"],
      "recommendations": ["对登录接口增加参数化查询和访问频率限制"],
      "error_message": "",
      "created_at": "2026-07-14T13:20:41"
    }
  ]
}
```

`status` 为 `done` 或 `failed`。生成失败的报告正文字段为空，
`error_message` 记录失败原因。

### GET /api/reports/{report_id}

单份报告详情，字段同上。报告不存在时返回 404。

### POST /api/reports/generate

对指定分析任务汇总告警统计和典型告警，调用大模型生成评测报告。
生成过程是同步的，耗时取决于模型服务。

```json
{ "task_id": 3 }
```

成功时返回报告对象，字段同 `GET /api/reports/{report_id}`。

- 任务不存在时返回 404；
- 大模型接入参数未配置时返回 400；
- 模型调用失败或输出无法解析时返回 502，同时保存一条
  `status` 为 `failed` 的报告，`error_message` 记录失败原因。

## 分析任务

任务由抓包和离线分析模块创建，接口已可用，供模块落地后复用。

### POST /api/tasks

```json
{ "task_type": "pcap", "target": "sample_http_attack.pcap", "status": "pending" }
```

```json
{
  "id": 1,
  "task_type": "pcap",
  "target": "sample_http_attack.pcap",
  "status": "pending",
  "packet_count": 0,
  "http_count": 0,
  "alert_count": 0,
  "created_at": "2026-07-14T13:17:26",
  "finished_at": null
}
```

### GET /api/tasks

查询参数：`limit`（默认 100，最大 500）、`offset`。
响应 `{ "items": [任务对象] }`，按创建时间倒序。

### PATCH /api/tasks/{task_id}

更新任务进度，字段全部可选：`status`、`packet_count`、`http_count`、
`alert_count`；`finished` 传 `true` 时写入结束时间。任务不存在时返回 404。

## 告警

### POST /api/alerts

写入一条告警，检测链路打通后由检测模块调用。`task_id` 可为空；
指定的任务不存在时返回 404。

```json
{
  "task_id": 1,
  "src_ip": "192.168.1.20",
  "dst_ip": "192.168.1.10",
  "src_port": 53421,
  "dst_port": 80,
  "method": "GET",
  "path": "/login",
  "query": "username=admin' or '1'='1",
  "attack_type": "SQL Injection",
  "risk_level": "high",
  "score": 85,
  "matched_rules": ["SQL-001"],
  "ai_judgement": "malicious",
  "ai_confidence": 0.87,
  "ai_reason": "请求参数组合具有明确的 SQL 注入意图",
  "reason": "命中 SQL 注入规则"
}
```

### GET /api/alerts

查询参数（均可选）：`attack_type`、`risk_level`、`src_ip`、`task_id`、
`limit`（默认 100，最大 500）、`offset`。
响应 `{ "items": [告警对象] }`，按创建时间倒序。

### GET /api/alerts/{alert_id}

单条告警详情，包含命中规则、检测原因和 AI 研判字段。不存在时返回 404。

## 统计

### GET /api/stats

从任务和告警表实时计算，供总览页展示。

```json
{
  "total_alerts": 12,
  "total_tasks": 3,
  "attack_type_distribution": { "SQL Injection": 8, "XSS": 4 },
  "risk_level_distribution": { "high": 6, "medium": 4, "low": 2 },
  "top_source_ips": [{ "src_ip": "192.168.1.20", "count": 9 }],
  "task_status_distribution": { "finished": 2, "running": 1 },
  "recent_alerts": ["最近 10 条告警对象"]
}
```

## 开发辅助

### POST /api/dev/reset-database

清空 `tasks`、`alerts` 和 `reports` 表并重置自增 ID，
保留表结构和运行配置。必须显式传 `{"confirm": true}`，否则返回 400。

```json
{ "status": "reset", "deleted_alerts": 12, "deleted_tasks": 3, "deleted_reports": 2 }
```
