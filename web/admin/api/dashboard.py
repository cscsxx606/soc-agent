#!/usr/bin/env python3
"""
仪表盘图表 API
提供 24h 告警趋势、优先级分布、攻击类型 Top 10、Agent 性能等图表数据
所有数据从 incidents 表实时统计，不再使用 random 模拟
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify, Response, stream_with_context
from auth import login_required
from db import get_db


def register(app):

    @app.route('/api/admin/dashboard/charts')
    @login_required
    def dashboard_charts():
        """返回所有图表数据（全部从 incidents 表实时统计）"""
        with get_db() as conn:
            return jsonify({
                'success': True,
                'hunts_done': _count_action(conn, 'hunt'),
                'resolved': _count_action(conn, 'dispose'),
                'charts': {
                    'alert_trend_24h': _alert_trend_24h(conn),
                    'priority_distribution': _priority_distribution(conn),
                    'attack_type_top10': _attack_type_top10(conn),
                    'severity_distribution': _severity_distribution(conn),
                    'agent_performance': _agent_performance(conn),
                    'source_ip_top': _source_ip_top(conn),
                    'response_actions': _response_actions_stats(conn),
                    'vuln_distribution': _vuln_distribution(conn)
                }
            })

    @app.route('/api/admin/dashboard/stream')
    @login_required
    def dashboard_stream():
        """SSE 实时事件流"""
        def generate():
            last_id = int(request.args.get('last_id', 0))
            yield f"event: connected\ndata: {json.dumps({'status': 'connected'})}\n\n"

            try:
                while True:
                    with get_db() as conn:
                        rows = conn.execute("""
                            SELECT id, timestamp, username, action, module, target, result
                            FROM audit_logs WHERE id > ? ORDER BY id DESC LIMIT 10
                        """, (last_id,)).fetchall()

                    for r in rows:
                        event_data = {
                            'id': r['id'],
                            'timestamp': r['timestamp'],
                            'username': r['username'],
                            'action': r['action'],
                            'module': r['module'],
                            'target': r['target'],
                            'result': r['result']
                        }
                        yield f"event: audit\ndata: {json.dumps(event_data, ensure_ascii=False)}\n\n"
                        last_id = max(last_id, r['id'])

                    time.sleep(3)
            except GeneratorExit:
                pass
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )


def _safe_table_query(conn, query, params=(), default=None):
    """安全查询：表不存在时返回默认值，不抛 500"""
    try:
        return conn.execute(query, params).fetchall()
    except Exception:
        return default or []


def _count_action(conn, keyword: str) -> int:
    """统计 audit_logs 中某个关键词的动作次数（30 天）"""
    cutoff = (datetime.now() - timedelta(days=30)).isoformat()
    row = _safe_table_query(conn,
        "SELECT COUNT(*) as c FROM audit_logs WHERE action LIKE ? AND timestamp >= ?",
        (f'%{keyword}%', cutoff))
    if row:
        return row[0]['c'] or 0
    return 0


def _alert_trend_24h(conn):
    """24 小时告警趋势 (按小时统计) - 从 incidents 表"""
    hours = {h: 0 for h in range(24)}
    severities = {h: {'critical': 0, 'high': 0, 'medium': 0, 'low': 0} for h in range(24)}

    # 取最近 24 小时（表不存在时安全返回空数据）
    cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
    rows = _safe_table_query(conn, """
        SELECT timestamp, severity FROM incidents
        WHERE timestamp >= ?
        ORDER BY timestamp
    """, (cutoff,))

    for r in rows:
        try:
            dt = datetime.fromisoformat(r['timestamp'].replace('Z', ''))
            hour = dt.hour
            hours[hour] += 1
            sev = r['severity'] or 'medium'
            if sev in severities[hour]:
                severities[hour][sev] += 1
        except (ValueError, AttributeError):
            pass

    return {
        'hours': list(range(24)),
        'total': [hours[h] for h in range(24)],
        'critical': [severities[h]['critical'] for h in range(24)],
        'high': [severities[h]['high'] for h in range(24)],
        'medium': [severities[h]['medium'] for h in range(24)],
        'low': [severities[h]['low'] for h in range(24)]
    }


def _priority_distribution(conn):
    """优先级分布饼图 - 从 incidents 表"""
    rows = _safe_table_query(conn, """
        SELECT priority, COUNT(*) as cnt FROM incidents
        GROUP BY priority
    """)
    counts = {'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0}
    for r in rows:
        if r['priority'] in counts:
            counts[r['priority']] = r['cnt']
    return [{'name': k, 'value': v} for k, v in counts.items()]


def _attack_type_top10(conn):
    """攻击类型 Top 10 - 从 incidents.alert_type 统计"""
    rows = _safe_table_query(conn, """
        SELECT alert_type, COUNT(*) as cnt FROM incidents
        WHERE alert_type IS NOT NULL AND alert_type != ''
        GROUP BY alert_type ORDER BY cnt DESC LIMIT 10
    """)
    return [{'name': r['alert_type'], 'value': r['cnt']} for r in rows]


def _severity_distribution(conn):
    """严重级别分布 - 从 incidents 表"""
    rows = _safe_table_query(conn, """
        SELECT severity, COUNT(*) as cnt FROM incidents
        WHERE severity IS NOT NULL
        GROUP BY severity
    """)
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for r in rows:
        if r['severity'] in counts:
            counts[r['severity']] = r['cnt']
    return [{'name': k.upper(), 'value': v} for k, v in counts.items()]


def _agent_performance(conn):
    """Agent 性能数据 - 从 audit_logs 表统计"""
    # 7 天内各 Agent 的执行次数和成功率
    cutoff = (datetime.now() - timedelta(days=7)).isoformat()
    rows = conn.execute("""
        SELECT
            target as agent_name,
            COUNT(*) as total,
            SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as success
        FROM audit_logs
        WHERE module LIKE 'agent%'
          AND timestamp >= ?
        GROUP BY target
    """, (cutoff,)).fetchall()

    agents = []
    executions = []
    success_rate = []
    for r in rows:
        if r['agent_name']:
            agents.append(r['agent_name'])
            total = r['total']
            success = r['success'] or 0
            executions.append(total)
            success_rate.append(round(success / total * 100, 1) if total > 0 else 0)

    # 默认四 Agent 兜底（如果表为空）
    if not agents:
        agents = ['TriageAgent', 'HuntingAgent', 'ResponseAgent', 'VulnAgent']
        executions = [0, 0, 0, 0]
        success_rate = [0, 0, 0, 0]

    return {
        'agents': agents,
        'executions': executions,
        'success_rate': success_rate,
        'avg_latency_ms': [0] * len(agents),
        'tokens_consumed': [0] * len(agents)
    }


# IP -> (国家, ASN) 映射表（从 seed 数据逆向）
_IP_GEO = {
    '203.0.113.45': ('CN', 'AS4134'),
    '198.51.100.20': ('US', 'AS15169'),
    '192.0.2.88': ('RU', 'AS12389'),
    '203.0.113.99': ('CN', 'AS9808'),
    '198.51.100.55': ('NL', 'AS60781'),
    '185.220.101.32': ('DE', 'AS208294'),
    '45.33.32.156': ('US', 'AS63949'),
    '91.219.236.222': ('RU', 'AS49505'),
    '103.25.61.110': ('KR', 'AS4766'),
    '194.5.249.180': ('IR', 'AS44244'),
    '5.188.10.156': ('BG', 'AS204957'),
    '162.247.74.7': ('US', 'AS19752'),
    '23.129.64.130': ('US', 'AS396507'),
    '171.25.193.20': ('SE', 'AS198093'),
}


def _source_ip_top(conn):
    """Top 攻击源 IP - 从 incidents 表"""
    rows = _safe_table_query(conn, """
        SELECT source_ip, COUNT(*) as cnt FROM incidents
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
    """)
    result = []
    for r in rows:
        ip = r['source_ip']
        country, asn = _IP_GEO.get(ip, ('-', '-'))
        result.append({'ip': ip, 'count': r['cnt'], 'country': country, 'asn': asn})
    return result


def _response_actions_stats(conn):
    """响应动作统计 - 从 audit_logs 统计近期响应事件"""
    cutoff = (datetime.now() - timedelta(days=30)).isoformat()
    row = conn.execute("""
        SELECT
            SUM(CASE WHEN action LIKE '%block%' THEN 1 ELSE 0 END) as auto_blocked_ips,
            SUM(CASE WHEN action LIKE '%isolate%' THEN 1 ELSE 0 END) as isolated_hosts,
            SUM(CASE WHEN action LIKE '%disable%' THEN 1 ELSE 0 END) as disabled_users,
            SUM(CASE WHEN action LIKE '%notify%' OR action LIKE '%alert%' THEN 1 ELSE 0 END) as notifications_sent,
            SUM(CASE WHEN action LIKE '%playbook%' THEN 1 ELSE 0 END) as playbooks_executed,
            SUM(CASE WHEN action LIKE '%manual%' THEN 1 ELSE 0 END) as manual_interventions
        FROM audit_logs WHERE timestamp >= ?
    """, (cutoff,)).fetchone()
    return {
        'auto_blocked_ips': row['auto_blocked_ips'] or 0,
        'isolated_hosts': row['isolated_hosts'] or 0,
        'disabled_users': row['disabled_users'] or 0,
        'notifications_sent': row['notifications_sent'] or 0,
        'playbooks_executed': row['playbooks_executed'] or 0,
        'manual_interventions': row['manual_interventions'] or 0
    }


def _vuln_distribution(conn):
    """漏洞风险分布 - 从 scans 或 vulns 表"""
    # 尝试 vulns 表
    try:
        rows = conn.execute("""
            SELECT
                CASE
                    WHEN cvss_score >= 9.0 THEN 'Critical (9.0-10.0)'
                    WHEN cvss_score >= 7.0 THEN 'High (7.0-8.9)'
                    WHEN cvss_score >= 4.0 THEN 'Medium (4.0-6.9)'
                    ELSE 'Low (0.1-3.9)'
                END as level,
                COUNT(*) as cnt
            FROM vulns GROUP BY level
        """).fetchall()
        if rows:
            color_map = {
                'Critical (9.0-10.0)': '#ff4757',
                'High (7.0-8.9)': '#ffa502',
                'Medium (4.0-6.9)': '#00d4ff',
                'Low (0.1-3.9)': '#8a93a8'
            }
            return [{'name': r['level'], 'value': r['cnt'], 'color': color_map.get(r['level'], '#8a93a8')} for r in rows]
    except Exception:
        pass

    # 兜底：返回 0 数据
    return [
        {'name': 'Critical (9.0-10.0)', 'value': 0, 'color': '#ff4757'},
        {'name': 'High (7.0-8.9)', 'value': 0, 'color': '#ffa502'},
        {'name': 'Medium (4.0-6.9)', 'value': 0, 'color': '#00d4ff'},
        {'name': 'Low (0.1-3.9)', 'value': 0, 'color': '#8a93a8'}
    ]