#!/usr/bin/env python3
"""
SOC Agent API 文档生成器
访问 http://localhost:8889/api/docs 查看 API 文档
"""

import json
from flask import jsonify


def register(app):

    @app.route('/api/docs')
    def api_docs():
        """Swagger UI 风格的 API 文档页面"""
        return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>SOC API 文档</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, 'PingFang SC', sans-serif; background: #0a0e1a; color: #e0e6ed; }}
.header {{ background: #131825; border-bottom: 1px solid #2a3147; padding: 20px 40px; }}
.header h1 {{ background: linear-gradient(135deg, #00d4ff, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 24px; }}
.header p {{ color: #8a93a8; font-size: 13px; margin-top: 4px; }}
.header .meta {{ color: #4a5568; font-size: 12px; margin-top: 2px; }}
.container {{ max-width: 1000px; margin: 20px auto; padding: 0 20px; }}
.card {{ background: #131825; border: 1px solid #2a3147; border-radius: 10px; margin-bottom: 15px; overflow: hidden; }}
.card-header {{ padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
.card-header:hover {{ background: rgba(0,212,255,0.03); }}
.card-header .method {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; color: white; min-width: 55px; text-align: center; }}
.method-get {{ background: #10b981; }}
.method-post {{ background: #6366f1; }}
.method-delete {{ background: #ef4444; }}
.card-header .path {{ font-family: monospace; font-size: 14px; color: #00d4ff; margin-left: 10px; flex: 1; }}
.card-header .summary {{ font-size: 13px; color: #8a93a8; }}
.card-body {{ padding: 0 20px 20px; display: none; }}
.card-body.open {{ display: block; }}
.card-body pre {{ background: #0a0e1a; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; color: #ffa502; }}
.card-body .tag {{ display: inline-block; background: #2a3147; color: #8a93a8; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; }}
h3 {{ color: #00d4ff; font-size: 14px; margin: 15px 0 8px; }}
p {{ font-size: 13px; color: #8a93a8; margin: 4px 0; }}
code {{ background: #0a0e1a; padding: 1px 5px; border-radius: 3px; font-size: 12px; color: #ffa502; }}
</style>
</head>
<body>
<div class="header">
    <h1>🛡️ SOC Agent API 文档</h1>
    <p>SOC Multi-Agent System · REST API v1 · Build 2026-07-20</p>
    <div class="meta">
        Agent: SOC Multi-Agent System · 版本: 2.1.0 · 接口基础路径: <code>/api/v1/admin/</code>
    </div>
</div>
<div class="container" id="api-list"></div>

<script>
const spec = {json.dumps(API_SPEC, ensure_ascii=False, indent=2)};

function escapeHtml(s) {{
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function render() {{
    const container = document.getElementById('api-list');
    const categories = {{}};
    for (const [path, item] of Object.entries(spec)) {{
        const cat = item.category || '其他';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push({{...item, path}});
    }}
    let html = '';
    for (const [cat, items] of Object.entries(categories)) {{
        html += `<h2 style="color:#00d4ff;font-size:18px;margin:30px 0 15px;">${{cat}}</h2>`;
        for (const item of items) {{
            const methodClass = 'method-' + item.method.toLowerCase();
            const id = 'api-' + item.path.replace(/[\\/<>]/g, '_');
            html += `<div class="card">
                <div class="card-header" onclick="toggle('${{id}}')">
                    <div>
                        <span class="method ${{methodClass}}">${{item.method}}</span>
                        <span class="path">${{escapeHtml(item.path)}}</span>
                    </div>
                    <span class="summary">${{escapeHtml(item.summary)}}</span>
                </div>
                <div class="card-body" id="${{id}}">
                    <p><strong>描述:</strong> ${{escapeHtml(item.description)}}</p>`;
            if (item.auth) html += `<p><span class="tag">🔒 ${{item.auth}}</span></p>`;
            if (item.params && item.params.length) {{
                html += `<h3>📥 请求参数</h3><pre>${{escapeHtml(JSON.stringify(item.params, null, 2))}}</pre>`;
            }}
            if (item.response) {{
                html += `<h3>📤 响应示例</h3><pre>${{escapeHtml(JSON.stringify(item.response, null, 2))}}</pre>`;
            }}
            html += `</div></div>`;
        }}
    }}
    container.innerHTML = html;
}}

function toggle(id) {{
    const el = document.getElementById(id);
    el.classList.toggle('open');
}}

document.addEventListener('DOMContentLoaded', render);
</script>
</body>
</html>
"""


# API 规格定义
API_SPEC = {
    # ====== 认证 ======
    "/api/auth/login": {
        "method": "POST",
        "category": "🔐 认证",
        "summary": "用户登录",
        "description": "使用用户名和密码登录，返回 JWT token",
        "auth": "无需鉴权（速率限制 5次/分钟）",
        "params": {"username": "string 必填", "password": "string 必填"},
        "response": {"success": True, "token": "jwt_token", "user": {"username": "admin", "full_name": "系统管理员", "role": "admin"}}
    },
    "/api/auth/logout": {
        "method": "POST",
        "category": "🔐 认证",
        "summary": "用户登出",
        "description": "清除当前会话",
        "auth": "登录后"
    },
    # ====== 系统 ======
    "/api/version": {
        "method": "GET",
        "category": "⚙️ 系统",
        "summary": "API 版本信息",
        "description": "返回系统版本号和构建信息",
        "auth": "无需鉴权",
        "response": {"version": "v1", "api_base": "/api/v1/admin/", "agent": "SOC Multi-Agent System", "version_full": "2.1.0", "build_date": "2026-07-20"}
    },
    "/health": {
        "method": "GET",
        "category": "⚙️ 系统",
        "summary": "健康检查",
        "description": "检查数据库连接状态（负载均衡探针用）",
        "auth": "无需鉴权",
        "response": {"status": "ok", "db": "ok", "service": "soc-admin"}
    },
    # ====== 仪表盘 ======
    "/api/admin/stats": {
        "method": "GET",
        "category": "📊 仪表盘",
        "summary": "系统统计概览",
        "description": "返回数据源、Playbook、资产、审计日志数量",
        "auth": "登录后",
        "response": {"success": True, "data": {"sources": 0, "sources_enabled": 0, "playbooks": 0, "assets": 4, "audits": 175}}
    },
    "/api/admin/dashboard/charts": {
        "method": "GET",
        "category": "📊 仪表盘",
        "summary": "仪表盘图表数据",
        "description": "返回 8 张图表的实时数据（趋势/优先级/攻击类型/Agent 性能等）",
        "auth": "登录后",
        "response": {"success": True, "hunts_done": 0, "resolved": 0, "charts": {"alert_trend_24h": {}, "priority_distribution": [], "attack_type_top10": [], "severity_distribution": [], "agent_performance": {}, "source_ip_top": [], "response_actions": {}, "vuln_distribution": []}}
    },
    # ====== 告警 ======
    "/api/admin/incidents/list": {
        "method": "GET",
        "category": "🚨 告警",
        "summary": "告警事件列表",
        "description": "分页查询告警事件，支持按优先级/严重级别/状态筛选",
        "auth": "登录后",
        "params": {"priority": "string? P1|P2|P3|P4", "severity": "string? critical|high|medium|low", "status": "string? open|investigating|contained|closed", "limit": "int? 默认200", "offset": "int? 默认0"},
        "response": {"success": True, "total": 237, "stats": {"P1": 61, "P2": 99, "P3": 38, "P4": 39, "total": 237}, "incidents": []}
    },
    "/api/admin/incidents/export": {
        "method": "POST",
        "category": "🚨 告警",
        "summary": "导出告警到 CSV",
        "description": "按条件导出告警事件到 CSV 格式",
        "auth": "登录后",
        "params": {"start_date": "string?", "end_date": "string?", "priority": "string?"},
        "response": {"success": True, "csv": "CSV 内容", "count": 237}
    },
    # ====== 用户 ======
    "/api/admin/users/list": {
        "method": "GET",
        "category": "👤 用户管理",
        "summary": "用户列表",
        "description": "列出所有用户（仅 admin 角色可访问）",
        "auth": "role: admin",
        "response": {"success": True, "users": [{"id": 1, "username": "admin", "role": "admin", "is_active": 1}]}
    },
    "/api/admin/users/create": {
        "method": "POST",
        "category": "👤 用户管理",
        "summary": "创建用户",
        "description": "创建新用户（密码至少 8 位，必须含字母+数字）",
        "auth": "role: admin",
        "params": {"username": "string 必填", "password": "string 必填, 8位+字母数字", "role": "string? admin|analyst|auditor|viewer", "email": "string?", "full_name": "string?"}
    },
    # ====== 数据源 ======
    "/api/admin/sources/list": {
        "method": "GET",
        "category": "📡 数据源",
        "summary": "数据源列表",
        "description": "列出所有已配置的数据源",
        "auth": "登录后"
    },
    # ====== Playbooks ======
    "/api/admin/playbooks/list": {
        "method": "GET",
        "category": "📋 Playbooks",
        "summary": "Playbook 列表",
        "description": "列出所有应急响应预案",
        "auth": "登录后"
    },
    # ====== 扫描 ======
    "/api/admin/scans/stats": {
        "method": "GET",
        "category": "🔍 资产扫描",
        "summary": "扫描统计",
        "description": "返回扫描任务统计和工具可用性",
        "auth": "登录后"
    },
    "/api/admin/scans/whitelist/list": {
        "method": "GET",
        "category": "🔍 资产扫描",
        "summary": "扫描白名单列表",
        "description": "列出所有授权的扫描目标白名单",
        "auth": "登录后"
    },
    # ====== 审计 ======
    "/api/admin/audit/list": {
        "method": "GET",
        "category": "📝 审计日志",
        "summary": "审计日志列表",
        "description": "分页查询操作审计日志",
        "auth": "role: admin|auditor",
        "params": {"username": "string?", "module": "string?", "action": "string?", "result": "string?", "limit": "int? 默认100", "offset": "int? 默认0"}
    },
    # ====== Agent ======
    "/api/admin/agents/registry/list": {
        "method": "GET",
        "category": "🤖 Agent 商店",
        "summary": "Agent 模板列表",
        "description": "列出所有注册的 Agent（内置+自定义）",
        "auth": "登录后"
    },
    "/api/admin/agents/registry/categories": {
        "method": "GET",
        "category": "🤖 Agent 商店",
        "summary": "Agent 分类",
        "description": "返回支持的 Agent 分类列表"
    },
    # ====== 管线 ======
    "/api/admin/pipelines/list": {
        "method": "GET",
        "category": "🔧 任务管线",
        "summary": "管线列表",
        "description": "列出所有预设的任务管线（AI 协作流程）",
        "auth": "登录后"
    },
    # ====== 品牌 ======
    "/api/admin/branding/get": {
        "method": "GET",
        "category": "🎨 品牌配置",
        "summary": "获取品牌配置",
        "description": "返回站点名称/Logo/主题色等品牌信息"
    },
    # ====== 租户 ======
    "/api/admin/tenants/list": {
        "method": "GET",
        "category": "🏢 租户管理",
        "summary": "租户列表",
        "description": "列出所有租户（多租户管理）",
        "auth": "role: admin"
    },

    # ====== Phase 6: Copilot（公开） ======

    "/api/copilot/suggest": {
        "method": "GET",
        "category": "🤖 Copilot",
        "summary": "下一步操作推荐",
        "description": "根据最新 Incident 推荐 SOC 分析师下一步操作",
        "auth": "auth required",
        "params": ["incident_id (optional)"]
    },
    "/api/copilot/explain/<id>": {
        "method": "GET",
        "category": "🤖 Copilot",
        "summary": "AI 决策解释",
        "description": "解释某条 Incident 的 AI 分流决策",
        "auth": "auth required"
    },
    "/api/copilot/report/<id>": {
        "method": "GET",
        "category": "🤖 Copilot",
        "summary": "事件报告初稿",
        "description": "自动生成 Incident 调查事件报告初稿",
        "auth": "auth required"
    },
    "/api/copilot/trend": {
        "method": "GET",
        "category": "🤖 Copilot",
        "summary": "告警趋势分析",
        "description": "最近 100 条告警的趋势分析（P1 突增检测等）",
        "auth": "auth required"
    }
}
