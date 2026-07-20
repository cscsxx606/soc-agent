#!/usr/bin/env python3
"""
扫描报告生成器
- HTML 单文件报告（专业 SOC 风，浏览器可打印 PDF）
- ZIP 打包（HTML + 原始 JSON + 截图说明）
"""

import os
import json
import zipfile
import io
from datetime import datetime
from typing import Dict, List, Any, Optional


# 风险等级 → 颜色
RISK_COLOR = {
    'critical': '#dc2626',
    'high': '#ea580c',
    'medium': '#f59e0b',
    'low': '#10b981'
}

RISK_BADGE = {
    'critical': '🔴 严重',
    'high': '🟠 高危',
    'medium': '🟡 中危',
    'low': '🟢 低危'
}

SEVERITY_BADGE = {
    'critical': '🔴 严重',
    'high': '🟠 高危',
    'medium': '🟡 中危',
    'low': '🔵 低危'
}


class ReportGenerator:
    """生成 SOC 风格的扫描报告"""

    def __init__(self, brand: str = 'SOC Agent', version: str = '1.0.0'):
        self.brand = brand
        self.version = version

    def generate_html(self, scan_result: Dict[str, Any],
                       extra: Dict[str, Any] = None) -> str:
        """生成 HTML 报告"""
        extra = extra or {}
        risk = scan_result.get('risk_score', 0)
        if risk >= 60:
            level = 'critical'
        elif risk >= 30:
            level = 'high'
        elif risk >= 10:
            level = 'medium'
        else:
            level = 'low'
        risk_color = RISK_COLOR[level]
        risk_text = RISK_BADGE[level]

        ports = scan_result.get('ports_open', [])
        services = scan_result.get('services', [])
        web_findings = scan_result.get('web_findings', [])
        recs = scan_result.get('recommendations', [])
        hostname = scan_result.get('hostname', '-')
        ip = scan_result.get('ip_address', '-')
        criticality = scan_result.get('criticality', 'medium')
        owner = scan_result.get('owner', 'unknown')
        scan_start = scan_result.get('scan_start', '-')
        scan_end = scan_result.get('scan_end', '-')
        duration = scan_result.get('scan_duration', 0)
        task_id = scan_result.get('task_id', '-')
        scan_backend = scan_result.get('scan_backend', 'python-builtin')

        # 端口表格
        ports_rows = ''
        for p in ports:
            banner_short = (p.get('banner') or '').replace('<', '&lt;')[:80]
            ports_rows += f"""
            <tr>
                <td><strong>{p['port']}</strong></td>
                <td><span class="service-badge">{p['service']}</span></td>
                <td><span class="status-open">{p['state']}</span></td>
                <td>{p.get('response_time_ms', 0)}ms</td>
                <td><code>{banner_short or '-'}</code></td>
            </tr>
            """

        # HTTP 服务
        services_html = ''
        if services:
            for s in services:
                tech_stack = ', '.join(s.get('tech_stack', []))
                paths = s.get('paths_found', {})
                paths_html = ''
                if paths:
                    path_rows = ''
                    for path, info in paths.items():
                        path_rows += f"<tr><td><code>{path}</code></td><td>{info['label']}</td><td>HTTP {info['status']}</td></tr>"
                    paths_html = f"""
                    <table class="sub-table">
                        <thead><tr><th>路径</th><th>类型</th><th>状态</th></tr></thead>
                        <tbody>{path_rows}</tbody>
                    </table>
                    """
                services_html += f"""
                <div class="service-card">
                    <div class="service-header">
                        <strong>{s.get('url', '-')}</strong>
                        <span class="badge badge-{('success' if s.get('status_code', 0) < 400 else 'danger')}">HTTP {s.get('status_code', '?')}</span>
                        <span class="badge badge-info">{s.get('scheme', '-').upper()}</span>
                    </div>
                    <div class="service-meta">
                        <div><strong>📄 标题:</strong> {s.get('title') or '(无)'}</div>
                        <div><strong>🛠 技术栈:</strong> {tech_stack or 'unknown'}</div>
                        <div><strong>📦 Server:</strong> {s.get('server') or '-'}</div>
                        <div><strong>⚡ Powered-By:</strong> {s.get('powered_by') or '-'}</div>
                        <div><strong>📏 Content-Length:</strong> {s.get('content_length', 0)} bytes</div>
                    </div>
                    {paths_html}
                </div>
                """

        # Web 漏洞
        web_html = ''
        if web_findings:
            for w in web_findings:
                wf = w.get('findings', [])
                findings_html = ''
                if wf:
                    for f in wf:
                        sev = f.get('severity', 'low')
                        findings_html += f"""
                        <div class="finding finding-{sev}">
                            <div class="finding-header">
                                <span class="badge badge-{('danger' if sev in ('critical','high') else 'warning')}">{SEVERITY_BADGE.get(sev, sev)}</span>
                                <strong>{f.get('type', '?')}</strong>
                            </div>
                            <div class="finding-body">
                                {self._render_finding_details(f)}
                                <div class="recommendation">
                                    <strong>💡 建议:</strong> {f.get('recommendation', '-')}
                                </div>
                            </div>
                        </div>
                        """
                web_html += f"""
                <div class="web-card">
                    <div class="web-header">
                        <strong>🌐 {w.get('url', '-')}</strong>
                        <span class="badge badge-{('danger' if w.get('risk_level') in ('critical','high') else 'warning')}">
                            {RISK_BADGE.get(w.get('risk_level', ''), w.get('risk_level', ''))} ({w.get('risk_score', 0)})
                        </span>
                    </div>
                    {findings_html or '<div style="color:#94a3b8;">未发现漏洞</div>'}
                </div>
                """

        # 推荐项
        recs_html = ''
        if recs:
            for rec in recs:
                recs_html += f"<li>{rec}</li>"
        else:
            recs_html = "<li>未发现明显风险</li>"

        # 统计
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for w in web_findings:
            for f in w.get('findings', []):
                sev = f.get('severity', 'low')
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

        gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>扫描报告 - {hostname}</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
    margin: 0; padding: 40px;
    background: #f1f5f9; color: #1e293b;
    line-height: 1.6;
}}
.report {{
    max-width: 1100px; margin: 0 auto;
    background: white; padding: 50px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    border-radius: 8px;
}}
.cover {{
    border-bottom: 3px solid {risk_color};
    padding-bottom: 30px; margin-bottom: 30px;
}}
.cover h1 {{ margin: 0 0 10px 0; font-size: 32px; color: #0f172a; }}
.cover .subtitle {{ color: #64748b; font-size: 14px; }}
.meta-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 15px; margin: 20px 0;
}}
.meta-card {{
    background: #f8fafc; padding: 15px;
    border-radius: 6px; border-left: 3px solid #6366f1;
}}
.meta-card .label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
.meta-card .value {{ font-size: 18px; font-weight: 600; margin-top: 4px; color: #0f172a; }}
.risk-banner {{
    background: linear-gradient(135deg, {risk_color} 0%, {risk_color}dd 100%);
    color: white; padding: 20px 25px; border-radius: 8px;
    margin: 25px 0; display: flex; align-items: center; justify-content: space-between;
}}
.risk-banner .score {{ font-size: 48px; font-weight: 800; line-height: 1; }}
.risk-banner .label-text {{ font-size: 14px; opacity: 0.9; }}
.section {{ margin: 30px 0; }}
.section h2 {{
    font-size: 22px; color: #0f172a;
    border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;
    margin-bottom: 20px;
}}
.section h3 {{ font-size: 16px; color: #334155; margin: 20px 0 10px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
table th {{ background: #1e293b; color: white; padding: 12px 10px; text-align: left; font-size: 13px; }}
table td {{ padding: 10px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
.sub-table th {{ background: #475569; font-size: 11px; padding: 8px; }}
.sub-table td {{ padding: 6px 8px; font-size: 11px; }}
.service-badge {{ background: #dbeafe; color: #1e40af; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
.status-open {{ background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 6px; }}
.badge-success {{ background: #dcfce7; color: #166534; }}
.badge-warning {{ background: #fef3c7; color: #92400e; }}
.badge-danger {{ background: #fee2e2; color: #991b1b; }}
.badge-info {{ background: #dbeafe; color: #1e40af; }}
.service-card, .web-card {{
    background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 6px; padding: 15px; margin: 12px 0;
}}
.service-header, .web-header {{
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 10px; flex-wrap: wrap;
}}
.service-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6px 20px; font-size: 12px; color: #475569; margin: 10px 0; }}
.finding {{
    background: white; border-left: 4px solid #6366f1;
    padding: 12px; margin: 8px 0; border-radius: 0 6px 6px 0;
}}
.finding-critical {{ border-left-color: #dc2626; }}
.finding-high {{ border-left-color: #ea580c; }}
.finding-medium {{ border-left-color: #f59e0b; }}
.finding-low {{ border-left-color: #10b981; }}
.finding-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
.finding-body {{ font-size: 12px; color: #475569; }}
.finding-body code {{ background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 11px; }}
.recommendation {{
    background: #ecfdf5; border-left: 3px solid #10b981;
    padding: 8px 12px; margin-top: 8px; font-size: 12px; border-radius: 0 4px 4px 0;
}}
.recommendation-list {{ background: #fffbeb; padding: 15px 15px 15px 35px; border-radius: 6px; border-left: 4px solid #f59e0b; }}
.recommendation-list li {{ margin: 6px 0; }}
.summary-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 12px; margin: 20px 0;
}}
.summary-item {{
    text-align: center; padding: 15px;
    border-radius: 6px; color: white;
}}
.summary-item .num {{ font-size: 32px; font-weight: 800; }}
.summary-item .name {{ font-size: 12px; margin-top: 4px; }}
.footer {{
    margin-top: 50px; padding-top: 20px;
    border-top: 1px solid #e2e8f0;
    text-align: center; color: #94a3b8; font-size: 11px;
}}
@media print {{
    body {{ background: white; padding: 0; }}
    .report {{ box-shadow: none; padding: 20px; }}
    .section {{ page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="report">

<div class="cover">
    <h1>🛡️ 资产扫描报告</h1>
    <div class="subtitle">{self.brand} v{self.version} · 生成时间 {gen_time}</div>
    <div class="meta-grid">
        <div class="meta-card"><div class="label">目标主机</div><div class="value">{hostname}</div></div>
        <div class="meta-card"><div class="label">IP 地址</div><div class="value">{ip}</div></div>
        <div class="meta-card"><div class="label">资产重要性</div><div class="value">{criticality}</div></div>
        <div class="meta-card"><div class="label">负责人</div><div class="value">{owner}</div></div>
    </div>
</div>

<div class="risk-banner">
    <div>
        <div class="label-text">综合风险评级</div>
        <div style="font-size:24px; margin-top:4px;"><strong>{risk_text}</strong></div>
    </div>
    <div class="score">{risk}<span style="font-size:18px;">/100</span></div>
</div>

<div class="section">
    <h2>📊 漏洞摘要</h2>
    <div class="summary-grid">
        <div class="summary-item" style="background:#dc2626;"><div class="num">{sev_counts['critical']}</div><div class="name">严重漏洞</div></div>
        <div class="summary-item" style="background:#ea580c;"><div class="num">{sev_counts['high']}</div><div class="name">高危漏洞</div></div>
        <div class="summary-item" style="background:#f59e0b;"><div class="num">{sev_counts['medium']}</div><div class="name">中危漏洞</div></div>
        <div class="summary-item" style="background:#10b981;"><div class="num">{sev_counts['low']}</div><div class="name">低危漏洞</div></div>
    </div>
</div>

<div class="section">
    <h2>🔌 开放端口 ({len(ports)})</h2>
    {f'<table><thead><tr><th>端口</th><th>服务</th><th>状态</th><th>响应时间</th><th>Banner</th></tr></thead><tbody>{ports_rows}</tbody></table>' if ports else '<p style="color:#94a3b8;">未发现开放端口</p>'}
</div>

{f'''<div class="section">
    <h2>🌐 HTTP 服务识别 ({len(services)})</h2>
    {services_html}
</div>''' if services else ''}

{f'''<div class="section">
    <h2>🛡️ Web 漏洞扫描 ({len(web_findings)} 个服务, {sum(len(w.get("findings", [])) for w in web_findings)} 个发现)</h2>
    {web_html}
</div>''' if web_findings else ''}

<div class="section">
    <h2>💡 修复建议</h2>
    <div class="recommendation-list">
        <ul>{recs_html}</ul>
    </div>
</div>

<div class="section">
    <h2>ℹ️ 扫描元数据</h2>
    <table>
        <tbody>
            <tr><th style="width:200px;">任务 ID</th><td><code>{task_id}</code></td></tr>
            <tr><th>扫描后端</th><td>{scan_backend}</td></tr>
            <tr><th>扫描开始</th><td>{scan_start}</td></tr>
            <tr><th>扫描结束</th><td>{scan_end}</td></tr>
            <tr><th>扫描耗时</th><td>{duration} 秒</td></tr>
            <tr><th>生成报告</th><td>{gen_time}</td></tr>
        </tbody>
    </table>
</div>

<div class="footer">
    本报告由 {self.brand} v{self.version} 自动生成 · 仅供安全评估使用 · 请勿对外传播<br>
    浏览器按 Cmd+P (Mac) / Ctrl+P (Win) 可保存为 PDF
</div>

</div>
</body>
</html>"""

    def _render_finding_details(self, finding: Dict[str, Any]) -> str:
        """渲染单个漏洞详情"""
        parts = []
        skip_keys = {'type', 'severity', 'severity_score', 'recommendation'}
        for key, value in finding.items():
            if key in skip_keys or value is None or value == '':
                continue
            if isinstance(value, (dict, list)):
                continue
            display_key = {
                'path': '路径',
                'parameter': '参数',
                'payload': 'Payload',
                'evidence': '证据',
                'findings': '发现',
                'username': '用户名',
                'password': '密码',
                'label': '标签',
                'status': '状态',
                'missing': '缺失头',
            }.get(key, key)
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            parts.append(f"<div><strong>{display_key}:</strong> <code>{value}</code></div>")
        return ''.join(parts)

    def generate_zip(self, scan_result: Dict[str, Any]) -> bytes:
        """生成 ZIP 包（HTML 报告 + 原始 JSON + README）"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 1. HTML 报告
            html = self.generate_html(scan_result)
            html_name = f"scan_report_{scan_result.get('ip_address', 'unknown')}_{scan_result.get('task_id', 'unknown')[:20]}.html"
            zf.writestr(html_name, html)

            # 2. 原始 JSON
            json_name = f"scan_data_{scan_result.get('task_id', 'unknown')[:20]}.json"
            # 不能序列化 datetime / 不可序列化对象，先 dump str
            safe_result = json.loads(json.dumps(scan_result, default=str, ensure_ascii=False))
            zf.writestr(json_name, json.dumps(safe_result, ensure_ascii=False, indent=2))

            # 3. README
            readme = f"""扫描报告包
=============

文件名：
- {html_name} - HTML 报告（浏览器打开，按 Cmd+P 保存为 PDF）
- {json_name} - 原始扫描数据 JSON

目标: {scan_result.get('hostname')} ({scan_result.get('ip_address')})
任务: {scan_result.get('task_id')}
风险: {scan_result.get('risk_score')}/100
时间: {scan_result.get('scan_start')} - {scan_result.get('scan_end')}
"""
            zf.writestr('README.txt', readme)

        return buf.getvalue()

    def save_report(self, scan_result: Dict[str, Any], output_dir: str = None) -> Dict[str, str]:
        """保存 HTML + JSON 到磁盘，返回文件路径"""
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                       'reports')
        os.makedirs(output_dir, exist_ok=True)

        html = self.generate_html(scan_result)
        ip_safe = scan_result.get('ip_address', 'unknown').replace('.', '_').replace(':', '_')
        task_short = scan_result.get('task_id', 'unknown')[:20]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        html_path = os.path.join(output_dir, f'report_{ip_safe}_{task_short}_{timestamp}.html')
        json_path = os.path.join(output_dir, f'data_{ip_safe}_{task_short}_{timestamp}.json')

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(scan_result, f, ensure_ascii=False, indent=2, default=str)

        return {'html': html_path, 'json': json_path}


if __name__ == '__main__':
    # 测试用
    sample = {
        'task_id': 'SCAN-TEST-001',
        'hostname': 'test-server',
        'ip_address': '10.0.0.10',
        'criticality': 'high',
        'owner': 'security-team',
        'risk_score': 45,
        'scan_backend': 'python-builtin',
        'scan_start': '2026-07-16 10:00:00',
        'scan_end': '2026-07-16 10:00:35',
        'scan_duration': 35,
        'ports_open': [
            {'port': 22, 'service': 'SSH', 'state': 'open', 'banner': 'OpenSSH_8.2', 'response_time_ms': 12.3},
            {'port': 80, 'service': 'HTTP', 'state': 'open', 'banner': '', 'response_time_ms': 5.6},
        ],
        'services': [],
        'web_findings': [],
        'recommendations': ['✅ 测试通过']
    }
    gen = ReportGenerator()
    print('HTML length:', len(gen.generate_html(sample)))
    saved = gen.save_report(sample, '/tmp/test_reports')
    print('Saved:', saved)