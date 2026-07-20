# AegisGuard · AI SOC Operations Platform

> **让企业放心用 AI 做安全。**
> 全球首个面向 AI SOC Agent 的合规与安全护栏，让 LLM 驱动的安全运营既高效又可信。

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-110%20passing-brightgreen.svg)](tests/)
[![Code](https://img.shields.io/badge/code-12K%20lines-blue.svg)](core/)
[![Security](https://img.shields.io/badge/AI--Safe-Layer--2-red.svg)](aegis/sec_for_ai/)

[English](README.en.md) | [中文](README.md) | [日本語](README.ja.md)

---

## 🎯 我们的使命

传统 SOC 平台 (Splunk / Elastic / Sentinel) 是「用规则做安全」。
下一代 SOC 是「用 AI 做安全」。

**但 AI 做安全会出问题**：

| 风险 | 后果 |
|---|---|
| 🚨 Prompt 注入 | 攻击者通过告警内容劫持 LLM，让 SOC 做出错误决策 |
| 🔓 Tool 滥用 | AI Agent 误删数据库 / 暴露用户 / 误封 IP |
| 💸 模型跑飞账单 | 一个 agent 异常调用导致 $10K 月账单 |
| 📉 决策黑盒 | AI 决策没有可解释证据，GDPR / SOC 2 不合规 |
| 🤖 Agent 越权 | Triage Agent 居然能改用户表 |

**AegisGuard 解决这 5 个问题**。

---

## 🏛️ 三层架构

```
┌────────────────────────────────────────────────────────────────────┐
│                       AegisGuard Platform                          │
│                                                                    │
│  ┌────────────────────┬────────────────────┬────────────────────┐  │
│  │  LAYER 1           │  LAYER 2           │  LAYER 3           │  │
│  │  AI for Security   │  Security for AI   │  Ops & Trust       │  │
│  │  (用 AI 做事)       │  (护 AI 不出事)     │  (合规可信)        │  │
│  ├────────────────────┼────────────────────┼────────────────────┤  │
│  │ ✅ Triage Agent   │ 🆕 PromptGuard    │ 🆕 Explainable AI │  │
│  │ ✅ Hunting Agent   │ 🆕 Tool ACL       │ 🆕 Audit Chain    │  │
│  │ ✅ Response Agent  │ 🆕 Model Quota    │ 🆕 Compliance     │  │
│  │ ✅ Vuln Agent      │ 🆕 RAG Firewall   │ 🆕 SOC Copilot    │  │
│  │ 🆕 SOC Copilot    │ 🆕 Agent Monitor  │    Reports         │  │
│  └────────────────────┴────────────────────┴────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🧱 核心模块

### Layer 1 · AI for Security

| 模块 | 说明 | 状态 |
|---|---|---|
| `agents/triage_agent.py` | Phase 1: 告警智能分流 + 风险评分 | ✅ Done |
| `agents/hunting_agent.py` | Phase 2: 威胁狩猎 + MITRE 映射 | ✅ Done |
| `agents/response_agent.py` | Phase 3: 应急响应 + 自动化遏制 | ✅ Done |
| `agents/vuln_agent.py` | Phase 4: 漏洞评估 + 修复优先级 | ✅ Done |
| `core/soc_copilot.py` | SOC 分析师实时 AI 助手 | 🆕 Next |

### Layer 2 · Security for AI ⭐ 差异化护城河

| 模块 | 说明 | 状态 |
|---|---|---|
| `core/guard.py` | **Prompt 注入防护层** | 🆕 Next |
| `core/tool_acl.py` | **Agent 工具调用 RBAC** | 🆕 Next |
| `core/model_acl.py` | **模型调用配额 (防爆账单)** | 🆕 Next |
| `core/rag_firewall.py` | **RAG 数据泄露防护** | 🆕 Next |
| `core/agent_monitor.py` | **Agent 行为异常检测 (UEBA for AI)** | 🆕 Next |

### Layer 3 · Ops & Trust

| 模块 | 说明 | 状态 |
|---|---|---|
| `core/explainability.py` | **AI 决策可解释 (XAI)** | 🆕 Next |
| `core/audit_chain.py` | **Hash 链式审计 (不可篡改)** | 🆕 Next |
| `web/admin/api/decision_explain.py` | 决策解释 API | 🆕 Next |
| `web/admin/api/compliance.py` | 合规报告导出 | 🆕 Next |

---

## 🚀 快速开始

### 安装

```bash
# 1. 克隆
git clone https://github.com/cscsxx606/aegisguard.git
cd aegisguard

# 2. 创建虚拟环境
python3.11 -m venv .venv
source .venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置
cp config/.env.example config/.env
# 编辑 .env 填入 API keys

# 5. 启动
make web       # Admin Web  http://localhost:8889
make edr       # EDR 探针  http://localhost:9000
make test      # 跑测试 (110 个用例)
```

### 第一次使用

```python
from aegis.sec_for_ai.guard import PromptGuard
from aegis.ai_for_sec.agents.triage_agent import AlertTriageAgent

# 1. 用 PromptGuard 包装用户输入
guard = PromptGuard()
safe_input = guard.sanitize(user_input)

# 2. 跑 AI Agent（自动 ACL + 配额）
triage = AlertTriageAgent()
results = triage.execute([alert])

# 3. 解释 AI 决策（合规审计）
from aegis.ops_trust.explainability import DecisionExplainer
explainer = DecisionExplainer()
explanation = explainer.explain_incident_triage(results[0]['id'])
```

---

## 📊 项目数据

| 指标 | 数值 |
|---|---|
| 代码行数 | 12,457 |
| 测试用例 | 110 ✅ |
| API 端点 | 96 |
| Agent | 4 (Triage/Hunting/Response/Vuln) |
| Core 模块 | 12+ |
| 文档 | OPERATIONS + ARCHITECTURE + 三语 README |

---

## 🤝 参与贡献

欢迎 PR 和 Issue！

```bash
# 跑测试
make test

# 跑 lint（待加）
make lint

# 查看 Roadmap
cat ROADMAP.md
```

---

## 📜 许可证

[MIT](LICENSE) - 商业 / 私人 / 学术免费使用

---

## 🛣️ 路线图

- [x] Phase 1: AI Agent 基础（Triage/Hunting/Response/Vuln）
- [x] Phase 2: 工程化（Makefile/.env.example/服务加固）
- [x] Phase 3: 可观测性（Prometheus + 系统监控）
- [x] Phase 4: 文档化（OPERATIONS + ARCHITECTURE）
- [ ] **Phase 5 (现在)**: Layer 2 安全护栏（PromptGuard/ToolACL/ModelQuota）
- [ ] Phase 6: SOC Copilot UI + 决策可解释
- [ ] Phase 7: 私有化部署 Helm Chart
- [ ] Phase 8: ISO 27001 / SOC 2 合规认证

---

## 📞 联系我们

- 📧 Email: hello@aegisguard.ai
- 🐦 Twitter: [@aegisguard](https://twitter.com/aegisguard)
- 💬 Discord: [discord.gg/aegisguard](https://discord.gg/aegisguard)
- 🌐 官网: https://aegisguard.ai

---

_版本: v1.0 · 2026-07-20 · 第一次品牌化发布_