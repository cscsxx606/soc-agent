# AegisGuard 系统架构

> v2.0 · 2026-07-20 · 三层架构重构版

## 🎯 设计原则

1. **Defense in Depth** —— 任何一层失守，下一层补救
2. **零信任 AI** —— 所有 LLM 输入/输出/工具调用都强制审计
3. **兼容演进** —— 不破坏现有 110 个测试，渐进式迁移
4. **可解释优先** —— 每个 AI 决策都可追溯、可审计、可证明

---

## 🏛️ 整体架构（3 层）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AegisGuard Platform                            │
│                                                                         │
│  ┌─────────────────────────┬─────────────────────────┬────────────────┐ │
│  │  LAYER 1 · AI for Sec   │  LAYER 2 · Sec for AI   │ LAYER 3 · Ops  │ │
│  │  ─────────────────────  │  ─────────────────────  │ ────────────── │ │
│  │  让 AI 把安全做对        │  让 AI 不出事            │ 让 AI 可信     │ │
│  │                         │                         │                │ │
│  │  ▸ Triage Agent         │  ▸ PromptGuard          │ ▸ Explainability│ │
│  │  ▸ Hunting Agent        │  ▸ Tool ACL             │ ▸ Audit Chain  │ │
│  │  ▸ Response Agent       │  ▸ Model Quota          │ ▸ Compliance   │ │
│  │  ▸ Vuln Agent           │  ▸ RAG Firewall         │ ▸ SOC Copilot  │ │
│  │  ▸ SOC Copilot (Phase5) │  ▸ Agent Monitor        │ ▸ Reports      │ │
│  └─────────────────────────┴─────────────────────────┴────────────────┘ │
│                                  │                                       │
│                                  ▼                                       │
│                       ┌─────────────────────┐                            │
│                       │  Foundation Layer    │                            │
│                       │  ───────────────     │                            │
│                       │  · SQLite + WAL      │                            │
│                       │  · Flask + Gunicorn  │                            │
│                       │  · Prometheus        │                            │
│                       │  · DeepSeek / Kimi   │                            │
│                       └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 目录结构

```
aegisguard/                                     ← 项目根
├── aegis/                                      ← 新品牌化包（v2.0+）
│   ├── __init__.py                             ← 顶层入口
│   ├── _compat.py                              ← 兼容旧 import
│   ├── ai_for_sec/                             ← Layer 1
│   │   ├── __init__.py
│   │   ├── core/                               ← AI 引擎基础（指向旧 core/）
│   │   ├── agents/                             ← 4 个业务 Agent
│   │   └── copilot/                            ← Phase 5+ SOC Copilot
│   ├── sec_for_ai/                             ← Layer 2 ⭐ 差异化
│   │   ├── __init__.py
│   │   ├── guard/                              ← PromptGuard
│   │   ├── tool_acl/                           ← Agent RBAC
│   │   ├── model_acl/                          ← Token 配额
│   │   ├── rag_firewall/                       ← RAG 数据防护
│   │   └── monitor/                            ← Agent 异常检测
│   ├── ops_trust/                              ← Layer 3
│   │   ├── __init__.py
│   │   ├── explainability/                     ← XAI 决策解释
│   │   ├── audit_chain/                        ← Hash 链审计
│   │   ├── compliance/                         ← 合规报告
│   │   └── reports/                            ← 报告生成
│   └── aegisguard/                             ← 公开 API
│       └── __init__.py                         ← 顶层 import
│
├── core/                                       ← 旧位置（保留兼容）
│   ├── agent_base.py                           ← BaseAgent 基类
│   ├── llm_client.py                           ← DeepSeek 客户端
│   ├── notification.py                         ← 多通道通知
│   ├── data_source.py                          ← SIEM 接入
│   ├── task_pipeline.py                        ← 任务编排
│   ├── guard.py                                ← 🆕 PromptGuard 实现
│   ├── tool_acl.py                             ← 🆕 Tool ACL
│   ├── model_acl.py                            ← 🆕 Model 配额
│   ├── explainability.py                       ← 🆕 XAI
│   └── audit_chain.py                          ← 🆕 审计链
│
├── agents/                                     ← 旧位置（保留兼容）
│   ├── triage_agent.py
│   ├── hunting_agent.py
│   ├── response_agent.py
│   └── vuln_agent.py
│
├── web/                                        ← Admin Web + EDR
│   ├── admin/
│   │   ├── app.py                              ← Flask 主应用
│   │   ├── auth.py                             ← JWT + bcrypt
│   │   ├── db.py                               ← SQLite 封装
│   │   ├── metrics.py                          ← Prometheus
│   │   └── api/                                ← 96 个 API 端点
│   │       ├── incidents.py
│   │       ├── decision_explain.py             ← 🆕 Phase 5
│   │       └── compliance.py                   ← 🆕 Phase 5
│   └── edr/
│       └── app.py
│
├── playbooks/                                  ← YAML 剧本库
│   ├── brute_force.yml
│   ├── sql_injection.yml
│   └── priv_esc.yml
│
├── tests/                                      ← 110 个测试
│   ├── test_api.py                             ← 73 测试
│   ├── test_core.py                            ← 17 测试
│   ├── test_notification.py                    ← 13 测试
│   ├── test_triage_agent.py                    ← 24 测试
│   ├── test_guard.py                           ← 🆕 Phase 5
│   ├── test_tool_acl.py                        ← 🆕 Phase 5
│   └── test_explainability.py                  ← 🆕 Phase 5
│
├── docs/                                       ← 文档
│   ├── ARCHITECTURE.md                         ← 本文件
│   ├── OPERATIONS.md                           ← 运维 SOP
│   ├── SECURITY_MODEL.md                       ← 🆕 Phase 5 威胁建模
│   └── COMPLIANCE_MAPPING.md                   ← 🆕 Phase 5 合规对照
│
├── deploy/                                     ← 部署
│   ├── soc-admin.service                       ← systemd
│   ├── soc-edr.service                         ← systemd
│   └── helm/                                   ← 🆕 Phase 7 K8s
│
├── config/                                     ← 配置
│   └── .env.example                            ← 模板
│
├── data/                                       ← SQLite 数据库
├── logs/                                       ← Gunicorn 日志
├── reports/                                    ← 生成报告
└── Makefile                                    ← 一键操作
```

---

## 🔀 数据流（5 个核心流）

### 1. 告警处理流（Layer 1）

```
SIEM/ELK → DataSource → Layer1.TriageAgent
                                   │
                                   ├─ PromptGuard 检查输入 (Layer 2)
                                   ├─ Tool ACL 检查 (Layer 2)
                                   ├─ Model Quota 检查 (Layer 2)
                                   │
                                   ▼
                            AI 分析 / 规则 fallback
                                   │
                                   ▼
                            Layer3.DecisionExplainer
                            决策可解释报告
                                   │
                                   ▼
                            AuditChain 记录 (Hash 链)
                                   │
                                   ▼
                            incidents 表 (WAL 模式)
```

### 2. AI 调用保护流（Layer 2）

```
User Input (alert/raw_log/operator_cmd)
       │
       ▼
PromptGuard.sanitize()             ← 检测 prompt 注入
       │
       ├─ safe: pass through
       └─ unsafe: log + reject + alert
       │
       ▼
Agent.execute(input)               ← 调用 Agent
       │
       ▼
ToolACL.check_permission()         ← 每次 tool 调用前
       │
       ├─ allow: execute
       └─ deny: log + raise
       │
       ▼
ModelACL.check_quota()             ← 每次 LLM 调用前
       │
       ├─ ok: call LLM
       └─ over: stop + alert
       │
       ▼
AgentMonitor.watch()               ← 记录行为 / 检测异常
       │
       ▼
Output → RAGFirewall.redact()      ← 输出前 redact PII/secret
       │
       ▼
最终返回
```

### 3. 决策可解释流（Layer 3）

```
AI Decision (e.g. triage_result)
       │
       ▼
DecisionExplainer.explain(decision_id)
       │
       ├─ 拉 incident + ai_analysis + enrichment
       ├─ 拉 audit_chain 同时间段记录
       ├─ LLM 生成人类可读解释
       │
       ▼
ExplanationReport {
  summary: "P1 优先级，因为..."
  evidence: [...]      ← 决策依据
  reasoning: "..."     ← 推理链
  alternative_actions: [...]  ← 备选方案
  confidence: 0.85
  audit_trail: [...]   ← hash 链验证
}
```

### 4. 审计流（Layer 3）

```
任意操作 (Agent/User/Admin)
       │
       ▼
AuditChain.log(actor, action, params, result)
       │
       ├─ 计算 prev_hash + sha256(current)
       ├─ 写入 audit_chain 表
       │
       ▼
定时 verify_chain()                ← 完整性扫描
       │
       └─ 不一致 → 立即告警
```

### 5. 合规报告流（Layer 3）

```
ISO 27001 / SOC 2 / GDPR 报告
       │
       ▼
ComplianceReporter.generate(framework)
       │
       ├─ 拉 audit_chain (完整性证据)
       ├─ 拉 decision_explanations (AI 决策证据)
       ├─ 拉 model_usage (token 配额证据)
       ├─ 拉 prompt_injection_events (攻击面证据)
       │
       ▼
结构化报告 (PDF/HTML/JSON)
       │
       ▼
人工 CISO 签字 + 提交审计
```

---

## 🔐 安全模型

### Layer 2 防护层级（由外到内）

```
┌──────────────────────────────────────────────────┐
│  L1: 边界         PromptGuard 输入净化           │
├──────────────────────────────────────────────────┤
│  L2: 准入         Agent 调用前 ACL check         │
├──────────────────────────────────────────────────┤
│  L3: 配额         Model Quota 防爆账单           │
├──────────────────────────────────────────────────┤
│  L4: 行为         Agent Monitor 异常检测         │
├──────────────────────────────────────────────────┤
│  L5: 输出         RAG Firewall 输出 redact       │
└──────────────────────────────────────────────────┘
```

任何一层失守，下一层都会捕获并触发告警。

---

## 🗃️ 数据库 Schema (16+ 表)

### 业务表
- `users` / `roles` - RBAC 用户与角色
- `data_sources` - SIEM 数据源
- `playbooks` - YAML 剧本
- `target_assets` - 资产清单
- `incidents` - 告警事件

### Layer 2 安全表（Phase 5+）
- `prompt_injection_events` - 注入攻击记录
- `agent_behavior_anomalies` - Agent 异常行为
- `model_usage` - 模型调用配额
- `tool_acl_violations` - 越权调用

### Layer 3 可信表（Phase 5+）
- `decision_explanations` - 决策解释
- `audit_chain` - Hash 链审计
- `compliance_reports` - 合规报告

完整 schema 见 `web/admin/db.py::init_db()`

---

## 🚀 部署架构

### 单机部署（小规模）
```
┌──────────────────────────────────┐
│  ECS (4C8G+)                     │
│  ┌─────────────────────────────┐ │
│  │  Nginx (SSL)                │ │
│  │  Gunicorn (4 worker + gevent)│ │
│  │  · Admin Web :8889          │ │
│  │  · EDR       :9000          │ │
│  │  SQLite WAL                  │ │
│  │  /metrics → Prometheus      │ │
│  └─────────────────────────────┘ │
└──────────────────────────────────┘
```

### 高可用（Phase 7 K8s）
```
                    ┌────────────────┐
                    │  Ingress Nginx │
                    └─────┬──────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
       ┌──────────┐ ┌──────────┐ ┌──────────┐
       │ admin-1  │ │ admin-2  │ │ admin-3  │
       └──────────┘ └──────────┘ └──────────┘
              │           │           │
              └───────────┼───────────┘
                          ▼
                  ┌──────────────┐
                  │  PostgreSQL  │
                  │  (HA Cluster)│
                  └──────────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │  Prometheus  │
                  │  + Grafana   │
                  └──────────────┘
```

---

## 🔄 兼容性策略

### 旧 `import` 仍然工作 ✅

```python
# 旧的（保留 100% 兼容）
from core.agent_base import BaseAgent
from agents.triage_agent import AlertTriageAgent
from core.notification import Notifier

# 新的（推荐）
from aegis.aegisguard import AlertTriageAgent, Notifier
from aegis.ai_for_sec.core.agent_base import BaseAgent

# 公开 API（最稳定）
from aegisguard import AlertTriageAgent, PromptGuard
```

### 迁移时间表

| 阶段 | 操作 |
|---|---|
| v1.0 (现在) | 引入 `aegis/` 软链接，老路径保留 |
| v1.5 (Phase 5+) | 物理迁移 `core/guard.py` → `aegis/sec_for_ai/guard.py` |
| v2.0 (Phase 7+) | 完全废弃 `core/`, `agents/` 顶层包 |

110 个测试会持续验证旧 import 路径工作。

---

## 📊 关键指标

| 指标 | 目标 |
|---|---|
| API P99 延迟 | < 500ms |
| AI Agent 决策延迟 | < 5s |
| 告警处理吞吐 | > 100 events/s |
| 模型调用超时 | < 30s |
| 决策可解释覆盖 | 100% |
| Prompt 注入检测率 | > 95% |
| Tool ACL 拦截率 | 100% (永不允许) |

---

## 📚 进一步阅读

- [OPERATIONS.md](OPERATIONS.md) - 运维 SOP
- [SECURITY_MODEL.md](SECURITY_MODEL.md) - 威胁建模（Phase 5+）
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) - 合规对照表（Phase 5+）

---

_版本: v2.0 · 2026-07-20_
_与代码同步: `aegis/` 三层架构引入_