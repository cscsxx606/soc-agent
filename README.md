# SOC Multi-Agent System

基于 **DeepSeek V4 Flash** 的网络安全运营多智能体系统，自动化完成告警从接收到处置的全流程。

---

## 🎯 4 个 Agent 阶段

| 阶段 | Agent | 功能 |
|------|-------|------|
| Phase 1 | **TriageAgent** 告警智能分流 | 风险评分 + 自动分类 + 优先级排序 |
| Phase 2 | **HuntingAgent** 主动威胁狩猎 | 攻击链还原 + SIEM/EDR 查询语句生成 |
| Phase 3 | **ResponseAgent** 应急响应处置 | 自动化遏制 + 证据保全 + playbook |
| Phase 4 | **VulnAgent** 漏洞智能评估 | CVSS 调整 + 修复优先级 + 修复建议 |

---

## 🚀 快速开始

### 1. 命令行模式（推荐用于测试）

```bash
cd ~/.openclaw/workspace/soc-agent
source ../soc-agent-env/bin/activate

# 运行完整流水线
python3 start.py full

# 仅运行告警分流
python3 start.py cli --phase triage

# 仅运行漏洞评估
python3 start.py cli --phase vuln
```

### 2. Web 控制台模式（推荐用于演示）

```bash
cd ~/.openclaw/workspace/soc-agent
source ../soc-agent-env/bin/activate
python3 start.py web --port 8888

# 浏览器访问 http://localhost:8888
```

Web 控制台功能：
- 📊 实时统计面板
- 📋 告警列表（自动刷新）
- 🔍 一键威胁狩猎
- 🚨 一键应急响应
- 🛡️ 漏洞扫描评估
- 📝 实时执行日志

---

## 📁 项目结构

```
soc-agent/
├── config/
│   └── .env                    # DeepSeek API 配置
├── core/
│   ├── llm_client.py           # DeepSeek V4 Flash 客户端
│   └── agent_base.py           # Agent 基类
├── agents/
│   ├── triage_agent.py         # 告警分流 Agent
│   ├── hunting_agent.py        # 威胁狩猎 Agent
│   ├── response_agent.py       # 应急响应 Agent
│   └── vuln_agent.py           # 漏洞评估 Agent
├── playbooks/
│   ├── brute_force.yml         # SSH 暴力破解预案
│   ├── sql_injection.yml       # SQL 注入预案
│   └── privilege_escalation.yml # 权限提升预案
├── web/
│   └── app.py                  # Flask Web 控制台
├── data/
│   └── sample_alerts.json      # 示例告警
├── orchestrator.py             # 多 Agent 编排器
├── main.py                     # CLI 入口
├── requirements.txt          # 依赖清单（含 gunicorn, gevent, crewai）
├── Dockerfile                # 容器构建文件
├── docker-compose.yml        # 一键部署（SOC后台 + EDR探针）
├── start.py                  # 本地启动脚本
├── edr/
│   ├── app.py                # Osquery EDR 探针管理服务（端口9000）
│   ├── enroll_secret          # 探针注册密钥
│   └── DEPLOY.md             # EDR 探针部署指南
├── SKILL.md                    # OpenClaw 技能描述
└── README.md                   # 本文件
```

---

## 🔌 API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/` | Web 控制台 |
| GET  | `/api/stats` | 系统统计 |
| GET  | `/api/alerts` | 告警列表 |
| POST | `/api/demo` | 加载演示告警 |
| POST | `/api/alerts/triage` | 告警分流 |
| POST | `/api/hunt` | 威胁狩猎 |
| POST | `/api/respond` | 应急响应 |
| POST | `/api/vuln/scan` | 漏洞评估 |
| POST | `/api/pipeline/full` | 完整流水线 |

### API 调用示例

```bash
# 加载演示数据
curl -X POST http://localhost:8888/api/demo

# 查看统计
curl http://localhost:8888/api/stats

# 漏洞评估
curl -X POST http://localhost:8888/api/vuln/scan
```

---

## 📊 已验证的真实运行结果

```
Phase 1: 告警分流
✓ ALERT-2026-001: SSH暴力破解 → server-01 → 85分 → P1
✓ ALERT-2026-002: C2通信 → workstation-03 → 75分 → P2
✓ ALERT-2026-003: 异常DNS查询 → db-server-02 → 65分 → P2
✓ ALERT-2026-004: SQL Injection → web-server-prod → 95分 → P1
✓ ALERT-2026-005: 权限提升 → app-server-03 → 75分 → P2

Phase 2: 威胁狩猎
✓ 3 个高危告警全部完成狩猎，发现 10+ 攻击链线索

Phase 3: 应急响应
✓ 3 个高危告警生成完整响应方案，含 9 个处置动作

Phase 4: 漏洞评估
✓ 5 个真实漏洞分析：CVE-2024-21762 (Fortinet, P1) / CVE-2024-3400 (PAN-OS, P1)
```

---

## ⚙️ 配置说明

`config/.env`:
```bash
API_KEY=your-deepseek-api-key
BASE_URL=https://api.siliconflow.cn/v1
MODEL=deepseek-ai/DeepSeek-V3

ENABLE_AUTO_RESPONSE=false  # 自动处置开关（默认关闭）
```

---

## 🔄 下一步可扩展方向

1. **对接真实数据源**：Splunk API、ELK、Wazuh、阿里云日志服务
2. **真实 API 集成**：EDR（青藤/亚信）、防火墙（深信服/天融信）
3. **多租户支持**：按团队/客户隔离告警
4. **强化学习优化**：基于人工反馈调整风险评分模型
5. **威胁情报集成**：微步在线、VirusTotal、AlienVault OTX

---

## 📄 License

MIT License