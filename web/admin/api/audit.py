#!/usr/bin/env python3
"""审计日志 API - 使用上下文管理器防止连接泄漏"""

import os
import sys
import csv
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify, Response
from auth import login_required, role_required
from db import get_db


def register(app):

    @app.route('/api/admin/audit/list')
    @role_required('admin', 'auditor')
    def list_logs():
        # 查询参数
        username = request.args.get('username', '')
        module = request.args.get('module', '')
        action = request.args.get('action', '')
        result_filter = request.args.get('result', '')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        # 构建 WHERE
        conditions = []
        params = []
        if username:
            conditions.append("username LIKE ?")
            params.append(f"%{username}%")
        if module:
            conditions.append("module = ?")
            params.append(module)
        if action:
            conditions.append("action LIKE ?")
            params.append(f"%{action}%")
        if result_filter:
            conditions.append("result = ?")
            params.append(result_filter)
        search = request.args.get('search', '')
        if search:
            conditions.append("(username LIKE ? OR action LIKE ? OR module LIKE ? OR target LIKE ? OR details LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # 使用上下文管理器自动关闭连接
        with get_db() as conn:
            # 总数
            total = conn.execute(f"SELECT COUNT(*) as c FROM audit_logs WHERE {where_clause}", params).fetchone()['c']

            # 分页
            rows = conn.execute(f"""
                SELECT * FROM audit_logs WHERE {where_clause}
                ORDER BY id DESC LIMIT ? OFFSET ?
            """, params + [limit, offset]).fetchall()

        return jsonify({
            'success': True,
            'total': total,
            'limit': limit,
            'offset': offset,
            'logs': [dict(r) for r in rows]
        })

    @app.route('/api/admin/audit/export', methods=['POST'])
    @role_required('admin', 'auditor')
    def export_logs():
        """导出审计日志"""
        data = request.get_json() or {}

        conditions = []
        params = []
        if data.get('start_date'):
            conditions.append("timestamp >= ?")
            params.append(data['start_date'])
        if data.get('end_date'):
            conditions.append("timestamp <= ?")
            params.append(data['end_date'])

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with get_db() as conn:
            rows = conn.execute(f"""
                SELECT timestamp, username, action, module, target, details, ip_address, result
                FROM audit_logs WHERE {where_clause} ORDER BY id
            """, params).fetchall()

        # 生成 CSV（连接已关闭，可安全做 IO）
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['时间', '用户', '动作', '模块', '对象', '详情', 'IP', '结果'])
        for r in rows:
            writer.writerow([r['timestamp'], r['username'], r['action'], r['module'],
                           r['target'], r['details'], r['ip_address'], r['result']])

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'}
        )