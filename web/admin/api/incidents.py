#!/usr/bin/env python3
"""告警事件 API - 统一从 incidents 表读取"""
import os, sys, json, csv, io
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required
from db import get_db


def register(app):

    @app.route('/api/admin/incidents/list')
    @login_required
    def list_incidents():
        """从 incidents 表读取告警事件"""
        # 查询参数
        priority = request.args.get('priority', '')
        severity = request.args.get('severity', '')
        status = request.args.get('status', '')
        limit = int(request.args.get('limit', 200))
        offset = int(request.args.get('offset', 0))

        # 构建 WHERE
        conditions = []
        params = []
        if priority:
            conditions.append("priority = ?")
            params.append(priority)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if status:
            conditions.append("status = ?")
            params.append(status)
        search = request.args.get('search', '')
        if search:
            conditions.append("(alert_type LIKE ? OR source_ip LIKE ? OR hostname LIKE ? OR description LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with get_db() as conn:
            # 总数
            total = conn.execute(f"SELECT COUNT(*) as c FROM incidents WHERE {where_clause}", params).fetchone()['c']

            # 分页查询
            rows = conn.execute(f"""
                SELECT * FROM incidents WHERE {where_clause}
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """, params + [limit, offset]).fetchall()

            # 优先级统计
            stats_rows = conn.execute("""
                SELECT priority, COUNT(*) as cnt FROM incidents GROUP BY priority
            """).fetchall()

        stats = {'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0, 'total': total}
        for r in stats_rows:
            if r['priority'] in stats:
                stats[r['priority']] = r['cnt']

        incidents = []
        for r in rows:
            d = dict(r)
            incidents.append({
                'id': d['id'],
                'alert_id': d['alert_id'],
                'timestamp': d['timestamp'],
                'source_ip': d['source_ip'],
                'dest_ip': d['dest_ip'],
                'alert_type': d['alert_type'],
                'severity': d['severity'],
                'priority': d['priority'],
                'risk_score': d['risk_score'],
                'hostname': d['hostname'],
                'owner': d['owner'],
                'mitre_technique': d['mitre_technique'],
                'confidence': d['confidence'],
                'description': d['description'],
                'status': d['status']
            })

        return jsonify({'success': True, 'total': total, 'stats': stats, 'incidents': incidents})

    @app.route('/api/admin/incidents/export', methods=['POST'])
    @login_required
    def incident_export():
        """导出事件到 CSV"""
        data = request.get_json() or {}

        conditions = []
        params = []
        if data.get('start_date'):
            conditions.append("timestamp >= ?")
            params.append(data['start_date'])
        if data.get('end_date'):
            conditions.append("timestamp <= ?")
            params.append(data['end_date'])
        if data.get('priority'):
            conditions.append("priority = ?")
            params.append(data['priority'])

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with get_db() as conn:
            rows = conn.execute(f"""
                SELECT alert_id, timestamp, alert_type, source_ip, hostname, risk_score, priority, severity, status
                FROM incidents WHERE {where_clause} ORDER BY timestamp DESC
            """, params).fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['事件ID', '时间', '攻击类型', '源IP', '目标资产', '风险评分', '优先级', '严重级别', '状态'])
        for r in rows:
            writer.writerow([r['alert_id'], r['timestamp'], r['alert_type'], r['source_ip'],
                           r['hostname'], r['risk_score'], r['priority'], r['severity'], r['status']])

        csv_data = output.getvalue(); output.close()
        return jsonify({'success': True, 'csv': csv_data, 'count': len(rows)})

    @app.route('/api/admin/incidents/<alert_id>/respond', methods=['POST'])
    @login_required
    def incident_respond(alert_id):
        """响应事件"""
        with get_db() as conn:
            # 更新事件状态
            conn.execute("""
                UPDATE incidents SET status='investigating' WHERE alert_id=?
            """, (alert_id,))
            conn.execute(
                "INSERT INTO audit_logs (username, action, module, target, result, timestamp) VALUES (?,?,?,?,?,?)",
                (getattr(request, 'username', 'system'), 'respond_incident', 'incidents', alert_id, 'success', datetime.now().isoformat())
            )
            conn.commit()

        return jsonify({
            'success': True, 'alert_id': alert_id,
            'response_plan': {
                'containment_immediate': ['阻断攻击源 IP', '关闭受影响服务端口'],
                'containment_short': ['隔离受感染主机', '保存相关日志证据', '通知安全团队'],
                'eradication': ['确认是否已被攻陷', '清除恶意进程/文件', '修复对应漏洞'],
                'recovery': ['从备份恢复业务', '监控恢复后异常行为', '验证安全状态'],
                'playbook_actions': [
                    {'action': 'block_ip', 'target': 'source_ip', 'auto': True, 'rollback': '从防火墙黑名单移除'},
                    {'action': 'isolate_host', 'target': 'affected_host', 'auto': False, 'need_approval': True},
                    {'action': 'collect_evidence', 'target': 'affected_host', 'auto': True}
                ]
            },
            'message': f'{alert_id} 处置方案已生成，请审批'
        })

    @app.route('/api/admin/incidents/<alert_id>')
    @login_required
    def get_incident(alert_id):
        """获取单个事件的完整详情"""
        with get_db() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE alert_id=?", (alert_id,)).fetchone()

        if not row:
            return jsonify({'success': False, 'error': '未找到该事件'}), 404

        return jsonify({'success': True, 'incident': dict(row)})

    @app.route('/api/admin/incidents/<alert_id>/status', methods=['POST'])
    @login_required
    def update_incident_status(alert_id):
        """更新事件状态"""
        data = request.get_json()
        new_status = data.get('status', '')
        if new_status not in ('open', 'investigating', 'contained', 'closed'):
            return jsonify({'success': False, 'error': '无效状态'}), 400

        with get_db() as conn:
            conn.execute("UPDATE incidents SET status=? WHERE alert_id=?", (new_status, alert_id))
            conn.execute(
                "INSERT INTO audit_logs (username, action, module, target, details, result, timestamp) VALUES (?,?,?,?,?,?,?)",
                (getattr(request, 'username', 'system'), 'update_status', 'incidents', alert_id,
                 f'状态更新为 {new_status}', 'success', datetime.now().isoformat())
            )
            conn.commit()

        return jsonify({'success': True, 'alert_id': alert_id, 'status': new_status})
