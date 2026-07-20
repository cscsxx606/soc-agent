# AegisGuard 路线图

> 公开透明，让社区看见我们要去哪里。

## ✅ 已完成（Phase 1-4）

### Phase 1 · AI Agent 基础（2026-07 中）
- [x] 4 个业务 Agent 实现 (Triage/Hunting/Response/Vuln)
- [x] LLM Client (DeepSeek/Kimi 双模型)
- [x] YAML Playbook 框架 (3 个 playbook)

### Phase 2 · 工程化（2026-07 中）
- [x] Makefile 一键操作
- [x] .env.example 配置模板
- [x] requirements.txt pinned 版本
- [x] systemd 服务单元 + 服务加固

### Phase 3 · 可观测性（2026-07 下）
- [x] Prometheus /metrics 端点
- [x] 系统指标 (CPU/内存/磁盘)
- [x] 业务指标 (HTTP 请求/延迟)

### Phase 4 · 文档化（2026-07 下）
- [x] OPERATIONS.md 16KB 运维 SOP
- [x] ARCHITECTURE.md v2.0 三层架构
- [x] README.md 三语品牌化
- [x] 110 个单元测试 (88% 覆盖)

### Phase 5 · 品牌化（2026-07-20 今天）
- [x] 项目重命名 soc-agent → aegisguard
- [x] 三层架构 aegis/ 包引入
- [x] 兼容层保留旧 import 路径
- [x] 公开 API aegis.aegisguard 入口

---

## 🚧 接下来 90 天

### Phase 6 · Layer 2 安全护栏（Week 1-2）
- [ ] `core/guard.py` PromptGuard（Prompt 注入防护）
  - [ ] 4 个检测维度（关键词/Unicode/越权/语义）
  - [ ] 15 个单元测试
  - [ ] 集成到 incidents API
- [ ] `core/tool_acl.py` Tool ACL
  - [ ] 4 Agent × 3 操作类型 (read/write/deny)
  - [ ] 每次 tool call 前强制 check
- [ ] `core/model_acl.py` Model Quota
  - [ ] 每个 Agent token 上限
  - [ ] 每日 cost USD 上限
  - [ ] 超额立即报警
- [ ] `core/agent_monitor.py` Agent Behavior Monitor
  - [ ] 频率异常检测
  - [ ] 参数异常检测
  - [ ] UEBA 风格 baseline 比对

### Phase 7 · Layer 3 可信（Week 3-4）
- [ ] `core/explainability.py` DecisionExplainer
  - [ ] 决策原因结构化输出
  - [ ] 备选方案对比
  - [ ] 证据链可追溯
- [ ] `core/audit_chain.py` AuditChain
  - [ ] Hash 链式不可篡改日志
  - [ ] 完整性扫描定时任务
- [ ] `/api/admin/decision/explain/{id}` API
- [ ] `/api/admin/audit/verify` API

### Phase 8 · SOC Copilot UI（Week 5-6）
- [ ] `core/soc_copilot.py` 实时助手
  - [ ] 下一步动作推荐
  - [ ] 报告自动起草
  - [ ] 历史动作检索
- [ ] Admin Web 侧边栏 UI
- [ ] `/api/copilot/*` 4 个端点
- [ ] 前端 ECharts 集成

### Phase 9 · 开源发布（Week 7-8）
- [ ] GitHub Public Repo: `aegisguard/aegisguard`
- [ ] PyPI 发布 `aegisguard-guard` SDK
- [ ] README 三语翻译
- [ ] Show HN 发布
- [ ] 完整 Demo 视频

---

## 🎯 6 个月目标（2026-Q4）

### 商业指标
- [ ] GitHub Stars: 1500+
- [ ] PyPI 月下载: 5000+
- [ ] Discord 成员: 500+
- [ ] 早期付费客户: 5+ 个

### 技术指标
- [ ] 测试覆盖率: 95%+
- [ ] API 端点: 150+
- [ ] Playbook 库: 10+
- [ ] 文档: 三语 + 视频

### 合规指标
- [ ] ISO 27001 准备度评估
- [ ] SOC 2 Type I 启动
- [ ] GDPR DPIA 完成

---

## 🌐 12-18 个月愿景

### 企业市场
- [ ] 私有部署 Helm Chart
- [ ] 多云支持 (AWS / Azure / 阿里云)
- [ ] SAML SSO
- [ ] 多租户管理
- [ ] 24×7 SOC 服务

### 国际化
- [ ] 英文为主市场
- [ ] 日本市场（监管严格 + 需求大）
- [ ] 东南亚市场（金融科技需求）

### 生态
- [ ] Plugin Marketplace（30% 分成）
- [ ] 第三方集成 (Splunk/Crowdstrike/PagerDuty)
- [ ] 开发者认证 (AegisGuard Certified)
- [ ] 学术合作（Stanford/Tsinghua/CUHK）

---

## 🛣️ 长期愿景（2-3 年）

### 市场定位
**AegisGuard = AI SOC 的护城河基础设施**

类比：
- Linux 在操作系统中的位置
- PostgreSQL 在数据库中的位置
- Istio 在服务网格中的位置

### 长期收入
- 社区版 → 流量入口
- Pro SaaS → 主流收入
- Enterprise 私有部署 → 大客户
- Marketplace 抽成 → 生态收入

---

## 📅 时间表总览

```
2026-Q3 (现在)
├── Phase 5: 品牌化 ✅ (今天)
├── Phase 6: Layer 2 安全护栏
└── Phase 7: Layer 3 可信

2026-Q4
├── Phase 8: SOC Copilot
├── Phase 9: 开源发布
└── Phase 10: Beta 客户

2027-Q1
├── Phase 11: 企业版
├── Phase 12: Marketplace
└── Phase 13: 国际市场

2027-Q2+
├── 团队扩展 (5-15 人)
├── A 轮融资 ($5M)
└── 行业领导者地位
```

---

## 🤝 如何参与

| 你想做的事 | 怎么开始 |
|---|---|
| 提 Issue | GitHub Issues |
| 提 PR | 跑 `make test` + 开 PR |
| 写文档 | 改 `docs/` 下 .md 文件 |
| 找 Bug | 试运行 `make web` |
| 商业合作 | hello@aegisguard.ai |

---

_版本: v2.0 · 2026-07-20_
_更新频率: 每月一次 + 重大里程碑_