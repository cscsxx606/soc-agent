---
id: soc-multi-agent
name: SOC Multi-Agent 智能体系统
description: >
  MUST USE when user wants to do 网络安全分析/SOC告警处理/威胁狩猎/应急响应/漏洞评估.
  
  本系统基于 DeepSeek V4 Flash 构建多 Agent 协同架构，包含 4 个阶段：
  1. 告警智能分流（Alert Triage）- 风险评分 + 自动分类
  2. 主动威胁狩猎（Threat Hunting）- 攻击链还原 + IOC 查询
  3. 应急响应处置（Incident Response）- 自动化遏制 + 证据保全
  4. 漏洞智能评估（Vulnerability Assessment）- CVSS 调整 + 修复建议
  
  触发关键词：SOC/告警/alert/安全事件/应急响应/incident/威胁狩猎/hunt/漏洞/vulnerability

metadata:
  author: SOC-Agent Team
  version: 2.0
  model: deepseek-ai/DeepSeek-V3
  openclaw:
    homepage: ~/.openclaw/workspace/soc-agent
---

# SOC Multi-Agent System

网络安全运营智能体系统。基于多 Agent 协同架构，自动化完成安全告警从接收到处置的全流程。

## 项目位置

```
~/.openclaw/workspace/soc-agent/
├── core/                    # 核心模块
│   ├── llm_client.py       # DeepSeek V4 Flash 客户端
│   └── agent_base.py       # Agent 基类
├── agents/                  # 4 个 Agent
│   ├── triage_agent.py     # Phase 1: 告警分流
│   ├── hunting_agent.py    # Phase 2: 威胁狩猎
│   ├── response_agent.py   # Phase 3: 应急响应
│   └── vuln_agent.py       # Phase 4: 漏洞评估
├── orchestrator.py          # 多 Agent 编排器
├── main.py                  # 命令行入口
└── web/
    └── app.py              # Flask Web 控制台
```

## 快速使用

### 命令行模式

```bash
cd ~/.openclaw/workspace/soc-agent

# 运行完整流水线（4 个 Phase）
source ../soc-agent-env/bin/activate
python3 main.py

# 仅运行告警分流
python3 main.py --phase triage

# 仅运行漏洞评估
python3 main.py --phase vuln

# 使用自定义告警文件
python3 main.py --input /path/to/alerts.json
```

### Web 控制台

```bash
source ../soc-agent-env/bin/activate
python3 web/app.py --port 8888

# 浏览器访问 http://localhost:8888
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/` | Web 控制台主面板 |
| GET  | `/api/stats` | 获取统计信息 |
| GET  | `/api/alerts` | 获取已分流告警 |
| POST | `/api/demo` | 加载演示数据 |
| POST | `/api/alerts/triage` | 执行告警分流 |
| POST | `/api/hunt` | 执行威胁狩猎 |
| POST | `/api/respond` | 执行应急响应 |
| POST | `/api/vuln/scan` | 执行漏洞评估 |
| POST | `/api/pipeline/full` | 运行完整流水线 |

## 告警数据格式

```json
{
  "id": "ALERT-2026-001",
  "timestamp": "2026-07-16T09:15:00Z",
  "source_ip": "203.0.113.45",
  "dest_ip": "10.0.0.50",
  "alert_type": "brute_force_ssh",
  "severity": "high",
  "description": "SSH 暴力破解",
  "raw_log": "原始日志",
  "asset_info": {
    "hostname": "server-01",
    "role": "web-server",
    "criticality": "high",
    "owner": "ops-team"
  }
}
```

## 能力边界

### ✅ 能做
- 告警批量处理（分流、评分、分类）
- 威胁狩猎查询生成（SIEM/EDR 查询语句）
- 应急响应方案制定（遏制、根除、恢复）
- 漏洞扫描结果分析、修复建议生成
- 自动生成 playbook 处置动作

### ❌ 不能做
- 真实执行 EDR/防火墙 API 调用（需要二次集成）
- 接入真实 SIEM/Splunk/ELK（需要数据源对接）
- 大规模自动化处置（默认 ENABLE_AUTO_RESPONSE=false）
- 替换真实 SOC 分析师决策（高危操作需要人工确认）

## 适用场景

| 场景 | 推荐使用 |
|------|----------|
| 中小互联网公司 SOC 建设 | ✅ |
| 制造业/金融业安全运营 | ✅ |
| 红蓝攻防演练支持 | ✅ |
| 安全运营外包服务 | ✅ |
| 大型 SOC（>10 人团队） | 需深度定制 |