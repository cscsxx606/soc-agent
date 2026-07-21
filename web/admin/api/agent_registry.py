#!/usr/bin/env python3
"""Agent 注册表 API - 动态 Agent 模板商店"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify

from auth import login_required, role_required, log_action
from db import get_db


def register(app):
    """注册路由"""

    @app.route('/api/admin/agents/registry/list')
    @login_required
    def registry_list():
        """列出所有 Agent（模板+用户）"""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_registry ORDER BY is_builtin DESC, usage_count DESC, name"
            ).fetchall()
        agents = []
        for r in rows:
            d = dict(r)
            for k in ('input_schema', 'output_schema', 'tools', 'config_json'):
                v = d.get(k)
                if isinstance(v, str):
                    try: d[k] = json.loads(v)
                    except (json.JSONDecodeError, TypeError): d[k] = {} if k == 'config_json' else []
            agents.append(d)
        return jsonify({'success': True, 'agents': agents, 'total': len(agents)})

    @app.route('/api/admin/agents/registry/<agent_key>')
    @login_required
    def registry_get(agent_key):
        """获取单个 Agent 详情"""
        with get_db() as conn:
            r = conn.execute(
                "SELECT * FROM agent_registry WHERE agent_key=?", (agent_key,)
            ).fetchone()
        if not r:
            return jsonify({'success': False, 'error': 'Agent 不存在'}), 404
        d = dict(r)
        for k in ('input_schema', 'output_schema', 'tools', 'config_json'):
            v = d.get(k)
            if isinstance(v, str):
                try: d[k] = json.loads(v)
                except (json.JSONDecodeError, TypeError): d[k] = {} if k == 'config_json' else []
        return jsonify({'success': True, 'agent': d})

    @app.route('/api/admin/agents/registry/create', methods=['POST'])
    @role_required('admin')
    def registry_create():
        """创建自定义 Agent"""
        data = request.get_json()
        key = (data.get('agent_key') or '').strip()
        if not key:
            return jsonify({'success': False, 'error': 'agent_key 必填'}), 400
        if not data.get('name') or not data.get('system_prompt'):
            return jsonify({'success': False, 'error': 'name 和 system_prompt 必填'}), 400

        with get_db() as conn:
            if conn.execute("SELECT id FROM agent_registry WHERE agent_key=?", (key,)).fetchone():
                return jsonify({'success': False, 'error': 'agent_key 已存在'}), 400

            conn.execute("""
                INSERT INTO agent_registry
                (agent_key, name, category, description, icon, system_prompt,
                 input_schema, output_schema, tools, config_json, enabled, is_builtin, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """, (
                key,
                data['name'],
                data.get('category', 'custom'),
                data.get('description', ''),
                data.get('icon', '🤖'),
                data['system_prompt'],
                json.dumps(data.get('input_schema', {}), ensure_ascii=False),
                json.dumps(data.get('output_schema', {}), ensure_ascii=False),
                json.dumps(data.get('tools', []), ensure_ascii=False),
                json.dumps(data.get('config_json', {}), ensure_ascii=False),
                1 if data.get('enabled', True) else 0,
                getattr(request, 'username', 'admin')
            ))
            conn.commit()

        log_action(request, 'create', 'agent_registry', key, f'创建 Agent: {data["name"]}')
        return jsonify({'success': True, 'agent_key': key, 'message': 'Agent 已创建'})

    @app.route('/api/admin/agents/registry/update/<agent_key>', methods=['POST'])
    @role_required('admin')
    def registry_update(agent_key):
        """更新 Agent（内置只能改配置，自定义可改全部）"""
        data = request.get_json()

        with get_db() as conn:
            row = conn.execute(
                "SELECT is_builtin FROM agent_registry WHERE agent_key=?", (agent_key,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Agent 不存在'}), 404

            is_builtin = row['is_builtin']

            # 字段映射
            fields = []
            values = []
            allowed = ['name', 'category', 'description', 'icon', 'system_prompt',
                       'input_schema', 'output_schema', 'tools', 'config_json', 'enabled']
            for f in allowed:
                if f in data:
                    # 内置 Agent 禁止修改 prompt/schema 等核心字段
                    if is_builtin and f in ('system_prompt', 'input_schema', 'output_schema', 'tools', 'category', 'name', 'icon'):
                        continue
                    v = data[f]
                    if f in ('input_schema', 'output_schema', 'tools', 'config_json') and not isinstance(v, str):
                        v = json.dumps(v, ensure_ascii=False)
                    fields.append(f'{f}=?')
                    values.append(v)

            if fields:
                fields.append('updated_at=CURRENT_TIMESTAMP')
                fields.append('updated_by=?')
                values.append(getattr(request, 'username', 'admin'))
                values.append(agent_key)
                conn.execute(f"UPDATE agent_registry SET {', '.join(fields)} WHERE agent_key=?", values)
                conn.commit()

    @app.route('/api/admin/agents/registry/delete/<agent_key>', methods=['POST'])
    @role_required('admin')
    def registry_delete(agent_key):
        """删除 Agent（不能删内置）"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT is_builtin FROM agent_registry WHERE agent_key=?", (agent_key,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Agent 不存在'}), 404
            if row['is_builtin']:
                return jsonify({'success': False, 'error': '内置模板不可删除（可禁用）'}), 400
            conn.execute("DELETE FROM agent_registry WHERE agent_key=?", (agent_key,))
            conn.commit()
        log_action(request, 'delete', 'agent_registry', agent_key, '删除 Agent')
        return jsonify({'success': True, 'message': 'Agent 已删除'})

    @app.route('/api/admin/agents/registry/toggle/<agent_key>', methods=['POST'])
    @role_required('admin')
    def registry_toggle(agent_key):
        """启用/禁用"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT enabled FROM agent_registry WHERE agent_key=?", (agent_key,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Agent 不存在'}), 404
            new_state = 0 if row['enabled'] else 1
            conn.execute(
                "UPDATE agent_registry SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE agent_key=?",
                (new_state, agent_key)
            )
            conn.commit()
        return jsonify({'success': True, 'enabled': bool(new_state)})

    @app.route('/api/admin/agents/registry/clone/<agent_key>', methods=['POST'])
    @role_required('admin')
    def registry_clone(agent_key):
        """克隆内置 Agent 作为自定义版本（可改 prompt）"""
        data = request.get_json() or {}
        new_key = data.get('new_key', f'{agent_key}_custom')

        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM agent_registry WHERE agent_key=?", (agent_key,)
            ).fetchone()
            if not row:
                return jsonify({'success': False, 'error': '源 Agent 不存在'}), 404
            if conn.execute("SELECT id FROM agent_registry WHERE agent_key=?", (new_key,)).fetchone():
                return jsonify({'success': False, 'error': '新 agent_key 已存在'}), 400

            # 复制所有字段，去掉 is_builtin
            conn.execute(f"""
                INSERT INTO agent_registry
                (agent_key, name, category, description, icon, system_prompt,
                 input_schema, output_schema, tools, config_json, enabled, is_builtin, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
            """, (
                new_key,
                data.get('name', row['name'] + ' (自定义)'),
                data.get('category', row['category']),
                row['description'], row['icon'], row['system_prompt'],
                row['input_schema'], row['output_schema'], row['tools'],
                row['config_json'] or '{}',
                getattr(request, 'username', 'admin')
            ))
            conn.commit()
        log_action(request, 'clone', 'agent_registry', new_key, f'从 {agent_key} 克隆')
        return jsonify({'success': True, 'agent_key': new_key, 'message': '已克隆为自定义 Agent'})

    @app.route('/api/admin/agents/registry/test/<agent_key>', methods=['POST'])
    @login_required
    def registry_test(agent_key):
        """测试运行 Agent"""
        data = request.get_json() or {}
        input_data = data.get('input', {})

        # 动态导入（确保 core 包可被发现）
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            # 也加 cwd
            cwd = os.getcwd()
            if cwd not in sys.path:
                sys.path.insert(0, cwd)
            from core.dynamic_agent import AgentRegistry
            reg = AgentRegistry()
            result = reg.run(agent_key, input_data)
            log_action(request, 'test', 'agent_registry', agent_key, f'测试运行（success={result.get("success")}）')
            return jsonify(result)
        except Exception as e:
            import traceback
            return jsonify({'success': False, 'error': str(e), 'trace': traceback.format_exc()}), 500

    @app.route('/api/admin/agents/registry/stats')
    @login_required
    def registry_stats():
        """统计信息"""
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM agent_registry").fetchone()[0]
            enabled = conn.execute("SELECT COUNT(*) FROM agent_registry WHERE enabled=1").fetchone()[0]
            builtin = conn.execute("SELECT COUNT(*) FROM agent_registry WHERE is_builtin=1").fetchone()[0]
            custom = conn.execute("SELECT COUNT(*) FROM agent_registry WHERE is_builtin=0").fetchone()[0]
            total_usage = conn.execute("SELECT COALESCE(SUM(usage_count),0) FROM agent_registry").fetchone()[0]
            by_cat = conn.execute(
                "SELECT category, COUNT(*) as c FROM agent_registry GROUP BY category"
            ).fetchall()
            top_used = conn.execute(
                "SELECT agent_key, name, usage_count FROM agent_registry WHERE usage_count > 0 ORDER BY usage_count DESC LIMIT 5"
            ).fetchall()
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'enabled': enabled,
                'builtin': builtin,
                'custom': custom,
                'total_usage': total_usage,
                'by_category': {r['category']: r['c'] for r in by_cat},
                'top_used': [dict(r) for r in top_used]
            }
        })

    @app.route('/api/admin/agents/registry/categories')
    @login_required
    def registry_categories():
        """支持的分类"""
        return jsonify({
            'success': True,
            'categories': [
                {'key': 'phishing', 'name': '🎣 钓鱼检测', 'description': '邮件/链接钓鱼分析'},
                {'key': 'detection', 'name': '📊 威胁检测', 'description': '日志/行为异常检测'},
                {'key': 'intel', 'name': '🔍 威胁情报', 'description': 'IOC 富化与情报摘要'},
                {'key': 'vulnerability', 'name': '🛡️ 漏洞管理', 'description': '漏洞优先级与修复建议'},
                {'key': 'malware', 'name': '🦠 恶意软件', 'description': '样本分类与家族识别'},
                {'key': 'response', 'name': '⚡ 应急响应', 'description': '事件响应与决策支持'},
                {'key': 'compliance', 'name': '📋 合规审计', 'description': '合规检查与报告'},
                {'key': 'custom', 'name': '🛠️ 自定义', 'description': '用户自定义 Agent'},
            ]
        })