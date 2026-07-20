#!/usr/bin/env python3
"""
AegisGuard · Copilot API

提供 SOC Copilot 的 REST API 端点
"""

import json
from flask import Blueprint, jsonify, request
from core.soc_copilot import SOCCopilot

bp = Blueprint('copilot', __name__)
copilot = SOCCopilot()


def register(app):
    app.register_blueprint(bp, url_prefix='/api/copilot')

    @app.route('/api/copilot/suggest')
    def copilot_suggest():
        """根据 incident_id 推荐下一步"""
        incident_id = request.args.get('incident_id', '')
        if not incident_id:
            # 从数据库中读 incident 数据
            from web.admin.db import get_db
            with get_db() as conn:
                row = conn.execute(
                    'SELECT * FROM incidents ORDER BY id DESC LIMIT 1'
                ).fetchone()
                if row:
                    incident = dict(row)
                else:
                    return jsonify({'success': False, 'error': '无 incident 可分析'}), 404
        else:
            from web.admin.db import get_db
            with get_db() as conn:
                row = conn.execute(
                    'SELECT * FROM incidents WHERE id = ?', (incident_id,)
                ).fetchone()
                if not row:
                    return jsonify({'success': False, 'error': 'incident 不存在'}), 404
                incident = dict(row)

        # 解析 ai_analysis
        if isinstance(incident.get('ai_analysis'), str):
            incident['ai_analysis'] = json.loads(incident['ai_analysis'])
        if isinstance(incident.get('enrichment'), str):
            incident['enrichment'] = json.loads(incident['enrichment'])
        if isinstance(incident.get('asset_info'), str):
            incident['asset_info'] = json.loads(incident['asset_info'])

        suggestions = copilot.suggest_next_action(incident)
        return jsonify({
            'success': True,
            'suggestions': [s.__dict__ for s in suggestions],
            'count': len(suggestions),
        })

    @app.route('/api/copilot/explain/<int:incident_id>')
    def copilot_explain(incident_id):
        """解释某条 incident 的 AI 决策"""
        from web.admin.db import get_db
        with get_db() as conn:
            row = conn.execute(
                'SELECT * FROM incidents WHERE id = ?', (incident_id,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'incident 不存在'}), 404
            incident = dict(row)

        for field in ['ai_analysis', 'enrichment', 'asset_info']:
            if isinstance(incident.get(field), str):
                try:
                    incident[field] = json.loads(incident[field])
                except (json.JSONDecodeError, TypeError):
                    incident[field] = {}

        explanation = copilot.explain_decision(incident)
        return jsonify({
            'success': True,
            'explanation': explanation,
            'incident_id': incident_id,
        })

    @app.route('/api/copilot/report/<int:incident_id>')
    def copilot_report(incident_id):
        """生成 incident 报告初稿"""
        from web.admin.db import get_db
        with get_db() as conn:
            row = conn.execute(
                'SELECT * FROM incidents WHERE id = ?', (incident_id,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'incident 不存在'}), 404
            incident = dict(row)

        for field in ['ai_analysis', 'enrichment', 'asset_info']:
            if isinstance(incident.get(field), str):
                try:
                    incident[field] = json.loads(incident[field])
                except (json.JSONDecodeError, TypeError):
                    incident[field] = {}

        report = copilot.auto_draft_report(incident)
        return jsonify({
            'success': True,
            'report': report,
            'incident_id': incident_id,
        })

    @app.route('/api/copilot/trend')
    def copilot_trend():
        """告警趋势分析"""
        from web.admin.db import get_db
        with get_db() as conn:
            rows = conn.execute(
                'SELECT * FROM incidents ORDER BY id DESC LIMIT 100'
            ).fetchall()
            incidents = []
            for row in rows:
                inc = dict(row)
                for field in ['ai_analysis', 'enrichment', 'asset_info']:
                    if isinstance(inc.get(field), str):
                        try:
                            inc[field] = json.loads(inc[field])
                        except (json.JSONDecodeError, TypeError):
                            inc[field] = {}
                incidents.append(inc)

        trend = copilot.analyze_trend(incidents)
        return jsonify({
            'success': True,
            'trend': trend,
        })
