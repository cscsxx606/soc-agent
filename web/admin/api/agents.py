#!/usr/bin/env python3
"""Agent 配置管理 API"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/agents/list')
    @login_required
    def list_agents():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM agent_configs ORDER BY agent_name").fetchall()

        # 解析 config_json
        agents = []
        for r in rows:
            d = dict(r)
            try:
                d['config'] = json.loads(d['config_json'])
            except Exception:
                d['config'] = {}
            d.pop('config_json', None)
            agents.append(d)

        return jsonify({'success': True, 'agents': agents})

    @app.route('/api/admin/agents/update/<agent_name>', methods=['POST'])
    @role_required('admin')
    def update_agent(agent_name):
        data = request.get_json()
        config = data.get('config', {})

        with get_db() as conn:
            existing = conn.execute("SELECT id FROM agent_configs WHERE agent_name=?", (agent_name,)).fetchone()

            if existing:
                conn.execute("""
                    UPDATE agent_configs
                    SET config_json=?, updated_at=CURRENT_TIMESTAMP, updated_by=?
                    WHERE agent_name=?
                """, (json.dumps(config, ensure_ascii=False),
                      getattr(request, 'username', 'system'),
                      agent_name))
            else:
                conn.execute("""
                    INSERT INTO agent_configs (agent_name, config_json, updated_by)
                    VALUES (?, ?, ?)
                """, (agent_name, json.dumps(config, ensure_ascii=False),
                      getattr(request, 'username', 'system')))

            conn.commit()

        log_action('update', 'agents', agent_name, f'更新 Agent 配置')
        return jsonify({'success': True, 'message': f'{agent_name} 配置已保存，热加载中...'})

    @app.route('/api/admin/agents/reset/<agent_name>', methods=['POST'])
    @role_required('admin')
    def reset_agent(agent_name):
        """重置为默认配置"""
        defaults = {
            'triage': {
                'risk_thresholds': {'P1': 80, 'P2': 60, 'P3': 40, 'P4': 0},
                'ai_model': 'deepseek-v3',
                'temperature': 0.2,
                'timeout_seconds': 30,
                'rule_engine_weight': 0.3,
                'auto_close_threshold': 20,
                'enable_ai_analysis': True
            },
            'hunting': {
                'min_risk_score': 50,
                'max_queries_per_hunt': 10,
                'time_window_hours': 24,
                'enable_chain_analysis': True,
                'enable_ioc_correlation': True
            },
            'response': {
                'enable_auto_response': False,
                'auto_response_priority': ['P1'],
                'require_approval_for': ['isolate_host', 'disable_user'],
                'notification_channels': ['feishu', 'email']
            },
            'vuln': {
                'cvss_critical_threshold': 9.0,
                'auto_calculate_priority': True,
                'include_mitigations': True
            }
        }

        if agent_name not in defaults:
            return jsonify({'success': False, 'error': '未知 Agent'}), 400

        with get_db() as conn:
            conn.execute("""
                UPDATE agent_configs SET config_json=?, updated_at=CURRENT_TIMESTAMP, updated_by=?
                WHERE agent_name=?
            """, (json.dumps(defaults[agent_name], ensure_ascii=False),
                  getattr(request, 'username', 'system'),
                  agent_name))
            conn.commit()

        log_action('reset', 'agents', agent_name, '重置为默认配置')
        return jsonify({'success': True})

    @app.route('/api/admin/agents/test/<agent_name>', methods=['POST'])
    @login_required
    def test_agent(agent_name):
        """用样例数据测试 Agent"""
        data = request.get_json() or {}
        sample_alert = data.get('alert', {
            "id": "TEST-001",
            "timestamp": "2026-07-16T13:30:00Z",
            "source_ip": "203.0.113.99",
            "dest_ip": "10.0.0.99",
            "alert_type": "brute_force_ssh",
            "severity": "high",
            "description": "测试告警",
            "asset_info": {"hostname": "test", "role": "server", "criticality": "high", "owner": "ops"}
        })

        try:
            if agent_name == 'triage':
                from agents.triage_agent import AlertTriageAgent
                agent = AlertTriageAgent()
                result = agent.execute([sample_alert])
                return jsonify({
                    'success': True,
                    'result': result[0] if result else None,
                    'stats': agent.get_stats()
                })
            elif agent_name == 'hunting':
                from agents.hunting_agent import ThreatHuntingAgent
                agent = ThreatHuntingAgent()
                result = agent.execute(sample_alert)
                return jsonify({'success': True, 'result': result})
            elif agent_name == 'vuln':
                from agents.vuln_agent import VulnAssessmentAgent
                agent = VulnAssessmentAgent()
                vulns = agent.generate_sample_vulns()[:2]
                result = agent.execute(vulns)
                return jsonify({'success': True, 'result': result})
            else:
                return jsonify({'success': False, 'error': f'暂不支持测试 {agent_name}'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/admin/agents/stats/<agent_name>')
    @login_required
    def agent_stats(agent_name):
        """获取 Agent 运行统计 - 从 audit_logs 表真实统计"""
        with get_db() as conn:
            # 统计该 Agent 的执行次数和成功率
            row = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as success,
                    AVG(CASE WHEN details LIKE '%耗时%' THEN
                        CAST(REPLACE(REPLACE(details, '耗时 ', ''), 's', '') AS REAL)
                        ELSE NULL END) as avg_duration
                FROM audit_logs
                WHERE module = ? AND timestamp >= datetime('now', '-7 days')
            """, (f'agent_{agent_name}',)).fetchone()

        total = row['total'] or 0
        success = row['success'] or 0
        avg_duration = row['avg_duration'] or 0

        return jsonify({
            'success': True,
            'agent_name': agent_name,
            'stats': {
                'executions': total,
                'success_rate': round(success / total * 100, 1) if total > 0 else 0,
                'avg_latency_ms': round(avg_duration * 1000, 0),
                'total_tokens': 0  # 需要 LLM 客户端上报
            }
        })