# SOC Agent 系统架构

> 本文档描述 SOC Multi-Agent 系统的整体架构、模块划分、数据流。

## 📑 目录

- [1. 系统概览](#1-系统概览)
- [2. 模块划分](#2-模块划分)
- [3. 数据流](#3-数据流)
- [4. 数据库结构](#4-数据库结构)
- [5. 接口规范](#5-接口规范)
- [6. 部署架构](#6-部署架构)

---

## 1. 系统概览

SOC Multi-Agent 系统基于 **DeepSeek V3** 多 Agent 协同架构，自动化完成安全告警从接收到处置的全流程：

```
┌─────────────────────────────────────────────────────────────────┐
│  告警源 (Splunk/ELK/Osquery)                                   │
│  ↓                                                              │
│  Phase 1: TriageAgent 告警智能分流                              │
│  - 风险评分（0-100）                                            │
│  - 自动分类（brute_force / C2 / sqli / priv_esc / etc）         │
│  - 优先级排序（P1/P2/P3/P4）                                    │
│  ↓                                                              │
│  Phase 2: HuntingAgent 主动威胁狩猎                            │
│  - 攻击链还原（MITRE ATT&CK）                                  │
│  - IOC 查询生成（SIEM/EDR）                                     │
│  ↓                                                              │
│  Phase 3: ResponseAgent 应急响应处置                            │
│  - 自动化遏制（隔离/封禁）                                      │
│  - 证据保全                                                     │
│  - Playbook 执行                                                │
│  ↓                                                              │
│  Phase 4: VulnAgent 漏洞智能评估                                │
│  - CVSS 调整（环境因子）                                        │
│  - 修复优先级                                                   │
│  - 修复建议生成                                                 │
│  ↓                                                              │
│  输出: Playbook + 报告 + 自动处置（需人工确认）                  │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 模块划分

```
soc-agent/
├── core/                       # 核心库
│   ├── agent_base.py          # Agent 基类
│   ├── llm_client.py          # DeepSeek API 客户端
│   ├── notification.py        # 多通道通知（飞书/企微/邮件/Slack/Webhook）
│   ├── crewai_bridge.py       # CrewAI 多 Agent 引擎包装（可选）
│   ├── dynamic_agent.py       # 动态 Agent 配置
│   ├── plugin_manager.py      # 插件化（Agent/Source/Notifier）
│   ├── task_pipeline.py       # 任务编排
│   ├── scan_scheduler.py      # 扫描调度
│   ├── scanner.py             # 扫描器基础
│   ├── web_vuln_scanner.py    # Web 漏洞扫描
│   ├── data_source.py         # 数据源抽象
│   └── report_generator.py    # 报告生成
│
├── agents/                     # 4 个业务 Agent
│   ├── triage_agent.py
│   ├── hunting_agent.py
│   ├── response_agent.py
│   └── vuln_agent.py
│
├── web/admin/                  # Admin 控制台（Flask）
│   ├── app.py                 # Flask 主应用
│   ├── auth.py                # JWT + bcrypt + RBAC
│   ├── db.py                  # SQLite 封装
│   ├── metrics.py             # Prometheus /metrics
│   └── api/                   # REST API 蓝模块
│       ├── incidents.py
│       ├── playbooks.py
│       ├── ...
│
├── edr/                        # Osquery EDR 探针管理
│   └── app.py
│
├── playbooks/                  # YAML Playbook
│   ├── brute_force.yml
│   ├── sql_injection.yml
│   └── priv_esc.yml
│
├── tests/                      # 单元测试
│   ├── test_core.py           # auth/db 核心
│   ├── test_api.py            # REST API
│   ├── test_notification.py   # 通知模块
│   └── ...
│
├── deploy/                     # 部署
│   ├── soc-admin.service      # systemd 单元
│   └── nginx.conf             # 反代配置
│
└── docs/                       # 文档
    ├── OPERATIONS.md          # 运维手册
    └── ARCHITECTURE.md        # 本文档
```

## 3. 数据流

### 告警处理流（Phase 1-4）

```
SIEM/ELK → data_source.py → triage_agent.py
                              ├─ 风险评分 → incidents 表 (priority 字段)
                              └─ 自动分类 → alert_type 字段
                                           ↓
                                  hunting_agent.py
                                       ├─ IOC 查询（生成 SIEM 查询语句）
                                       ├─ 攻击链还原（保存到 hunt_results 表）
                                       └─ 未发现 ⚠️ 时退出
                                                       ↓
                                              response_agent.py
                                                   ├─ 生成 Playbook（写入 playbooks 表）
                                                   ├─ 遏制动作（IP 拉黑/账号禁用）
                                                   └─ 证据保全
                                                                 ↓
                                                        vuln_agent.py
                                                              ├─ 关联漏洞库（NVD/CNVD）
                                                              ├─ CVSS 调整
                                                              └─ 修复优先级
                                                                          ↓
                                                                  输出报告
```

### Admin 控制台流

```
浏览器 → Nginx (443) → Gunicorn (8889) → Flask app
                                              ├── before_request (add_request_id)
                                              ├── middleware (速率限制/鉴权)
                                              ├── api/incidents.py:list
                                              ├── after_request (metrics + log)
                                              └── Prometheus /metrics
```

## 4. 数据库结构

### 主要表（14 张）

| 表 | 用途 |
|---|---|
| `users` | 管理员账号 |
| `roles` | RBAC 角色 |
| `data_sources` | SIEM/ELK 数据源 |
| `playbooks` | YAML 形式处置剧本 |
| `targets` / `target_assets` | 资产清单 |
| `incidents` | 告警事件 |
| `audit_logs` | 审计日志（90 天保留）|
| `scan_tasks` / `scan_results` | 漏洞扫描 |
| `agents_registry` | Agent 配置 |
| `notifications` / `notification_channels` | 通知 |
| `tenants` | 多租户 |
| `scan_whitelist` | 扫描白名单 |
| `settings` | 配置中心（运行时配置）|

完整 schema 见 `web/admin/db.py` 的 `init_db()` 函数。

## 5. 接口规范

### URL 约定

| 前缀 | 用途 |
|---|---|
| `/api/auth/*` | 认证（登录/登出）|
| `/api/admin/*` | 管理 API（需鉴权）|
| `/api/version` | 版本信息（公开）|
| `/api/docs` | Swagger UI 文档（公开）|
| `/health` | 健康检查（公开）|
| `/metrics` | Prometheus 指标（公开）|

### 鉴权方式

1. **Session Cookie**: 浏览器登录后自动设置
2. **JWT Bearer Token**: API 调用方使用
   ```
   Authorization: Bearer <jwt-token>
   ```

### 标准响应

```json
{
  "success": true,
  "data": {...},
  "error": null,
  "timestamp": "2026-07-20T16:30:00Z"
}
```

错误响应:
```json
{
  "success": false,
  "error": "权限不足",
  "code": 403
}
```

### 速率限制

- 登录: 5 次/分钟
- API 总: 100 次/分钟（默认）
- 大文件导出: 10 次/小时

## 6. 部署架构

### 容器化

```dockerfile
FROM python:3.13-slim
# 多阶段构建: builder + runtime
# 最终镜像仅含运行依赖
```

### 健康检查

Liveness: `GET /health`
Readiness: 数据库连接测试

### 配置注入

- 环境变量: `.env` 文件
- Docker: 环境变量直接传入
- Kubernetes: ConfigMap + Secret

---

## 联系

详见 [OPERATIONS.md](OPERATIONS.md)
